import argparse
import datetime
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from config import DATASET_DIR, RESULT_DIR, TEMP_DIR
from dataset import DatasetLoader
from enhanced_meta_agent import EnhancedMetaAgent
from huggingface_dataset_mirror import System4DatasetAdapter
from vulnscan.project_scanner import ProjectScanner
from vulnscan.testdata_generator import generate_big_c_file


def _ensure_utf8_stdio() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def save_json(data: Dict[str, Any], filepath: str) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def analyze_file(meta_agent: Any, sample, temp_dir: str) -> Dict[str, Any]:
    file_path = getattr(sample, "file_path", getattr(sample, "file_name", "unknown.c"))
    file_name = getattr(sample, "file_name", os.path.basename(file_path))
    project = getattr(sample, "project", "default")
    code = getattr(sample, "code", "")

    file_id = hashlib.md5(str(file_path).encode("utf-8", errors="ignore")).hexdigest()[:10]
    temp_file = os.path.join(temp_dir, f"{file_id}_{file_name}")
    os.makedirs(os.path.dirname(temp_file), exist_ok=True)
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(code)

    try:
        start = time.time()
        result = meta_agent.analyze(temp_file, code, {"file_name": file_name, "project": project})
        return {
            "success": True,
            "elapsed": time.time() - start,
            "file_name": file_name,
            "project": project,
            "result": result,
        }
    except Exception as e:
        return {"success": False, "file_name": file_name, "project": project, "error": str(e)}


def load_samples(args) -> List[Any]:
    if args.source in ("primevul", "secvul"):
        adapter = System4DatasetAdapter(use_huggingface=True, use_mirror=not args.no_mirror)
        if args.source == "primevul":
            return adapter.load_primevul_balanced(
                total_samples=max(1, int(args.samples)),
                vuln_ratio=max(0.0, min(1.0, float(args.vuln_ratio))),
                split=args.split,
                seed=int(args.seed),
            )
        return adapter.load_secvul_balanced(
            total_samples=max(1, int(args.samples)),
            vuln_ratio=max(0.0, min(1.0, float(args.vuln_ratio))),
            split=args.split,
            seed=int(args.seed),
        )

    target_dir = args.dir if args.dir else DATASET_DIR
    loader = DatasetLoader(target_dir)
    if args.file:
        one = loader.load_single_file(args.file)
        return [one] if one else []
    return loader.load_files(
        extensions=[".c", ".cpp", ".cc", ".h", ".hpp", ".cxx", ".c++"]
    )[: max(1, int(args.max_samples))]


def run_detect_mode(args) -> None:
    samples = load_samples(args)
    if not samples:
        raise FileNotFoundError("未加载到可检测样本")

    meta_agent = EnhancedMetaAgent(
        use_cache=not args.no_cache,
        enable_hypothesis_extraction=True,
        enable_llm_trigger_path=True,
    )
    print("\n检测语言: C/C++（独立项目专精链路）")
    print(f"\n共加载 {len(samples)} 个样本，开始检测（并行度={args.parallel}）")

    reports: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    start = time.time()

    def _consume(i: int, n: int, r: Dict[str, Any]) -> None:
        if not r.get("success"):
            print(f"[{i}/{n}] {r['file_name']} - 失败: {r['error']}")
            results.append(r)
            return
        report = r["result"]["report"]
        save_json(report, os.path.join(RESULT_DIR, f"{r['file_name']}.report.json"))
        reports.append(report)
        results.append(r)
        print(f"[{i}/{n}] {r['file_name']} - {r['elapsed']:.2f}s, 漏洞: {report.get('total_vulnerabilities', 0)}")

    if args.parallel > 1 and len(samples) > 1:
        with ThreadPoolExecutor(max_workers=args.parallel) as ex:
            futs = {ex.submit(analyze_file, meta_agent, s, TEMP_DIR): s for s in samples}
            done = 0
            for fut in as_completed(futs):
                done += 1
                _consume(done, len(samples), fut.result())
    else:
        for i, s in enumerate(samples, 1):
            _consume(i, len(samples), analyze_file(meta_agent, s, TEMP_DIR))

    elapsed = time.time() - start
    summary = {
        "scan_time": datetime.datetime.now().isoformat(),
        "mode": "detect",
        "language": "c",
        "source": args.source,
        "total_files": len(reports),
        "total_vulnerabilities": sum(r.get("total_vulnerabilities", 0) for r in reports),
        "severity_summary": {
            "critical": sum(r.get("severity_summary", {}).get("critical", 0) for r in reports),
            "high": sum(r.get("severity_summary", {}).get("high", 0) for r in reports),
            "medium": sum(r.get("severity_summary", {}).get("medium", 0) for r in reports),
            "low": sum(r.get("severity_summary", {}).get("low", 0) for r in reports),
        },
        "cwe_summary": {},
        "results": reports,
        "performance_stats": {
            "total_time": elapsed,
            "avg_time_per_file": elapsed / max(1, len(reports)),
            "files_processed": len(reports),
        },
    }
    for report in reports:
        for cwe, count in report.get("vulnerabilities_by_cwe", {}).items():
            summary["cwe_summary"][cwe] = summary["cwe_summary"].get(cwe, 0) + count

    summary_file = os.path.join(RESULT_DIR, "scan_summary.json")
    save_json(summary, summary_file)
    print("\n" + "=" * 60)
    print("检测完成")
    print(f"总耗时: {elapsed:.2f}s")
    print(f"结果目录: {RESULT_DIR}")
    print(f"汇总报告: {summary_file}")
    print("=" * 60)


def run_scan_mode(args) -> None:
    scanner = ProjectScanner(
        root_dir=args.root,
        result_dir=args.result_dir,
        temp_dir=args.temp_dir,
        extensions=args.extensions,
        parallel=args.parallel,
        max_files=args.max_files,
        checkpoint_path=os.path.abspath(args.checkpoint) if args.checkpoint else None,
        resume=not args.no_resume,
        save_full_analysis=args.save_full_analysis,
        use_cache=not args.no_cache,
        c_workspace_cpg=getattr(args, "c_workspace_cpg", False),
    )
    scanner.scan()


def run_generate_mode(args) -> None:
    out_path = os.path.abspath(args.out)
    generate_big_c_file(out_path, blocks=args.blocks)
    print(f"已生成大文件: {out_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="独立运行的 C/C++ 漏洞检测项目入口")
    parser.add_argument("--mode", choices=["detect", "scan", "generate-big-file"], default="detect")

    parser.add_argument("--source", choices=["local", "secvul", "primevul"], default="local")
    parser.add_argument("--file", "-f", help="单文件检测")
    parser.add_argument("--dir", "-d", help="目录检测")
    parser.add_argument("--max-samples", type=int, default=10, help="本地模式最大处理数")
    parser.add_argument("--parallel", type=int, default=2, help="并行度")
    parser.add_argument("--no-cache", action="store_true", help="禁用缓存")

    parser.add_argument("--samples", type=int, default=20, help="数据集样本数（secvul/primevul）")
    parser.add_argument("--vuln-ratio", type=float, default=0.5, help="漏洞/安全比例")
    parser.add_argument("--split", default="train", help="HuggingFace split")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    parser.add_argument("--no-mirror", action="store_true", help="禁用HF镜像")

    parser.add_argument("--root", default=DATASET_DIR, help="scan模式：代码根目录")
    parser.add_argument("--result-dir", default=RESULT_DIR, help="scan模式：输出目录")
    parser.add_argument("--temp-dir", default=TEMP_DIR, help="scan模式：Joern临时目录")
    parser.add_argument("--max-files", type=int, default=None, help="scan模式：最多扫描文件数")
    parser.add_argument(
        "--extensions",
        nargs="*",
        default=[".c", ".cpp", ".cc", ".h", ".hpp", ".cxx", ".c++"],
        help="scan模式：扫描扩展名",
    )
    parser.add_argument("--checkpoint", default=None, help="scan模式：断点续扫文件")
    parser.add_argument("--no-resume", action="store_true", help="scan模式：禁用续扫")
    parser.add_argument("--save-full-analysis", action="store_true", help="scan模式：保存完整中间结果")
    parser.add_argument("--c-workspace-cpg", action="store_true", help="整目录先 joern-parse/export 一次，多文件共享静态结果")

    parser.add_argument("--out", default=os.path.join(DATASET_DIR, "big_test.c"), help="生成大文件输出路径")
    parser.add_argument("--blocks", type=int, default=200, help="生成大文件时的漏洞片段块数")
    return parser


def main() -> None:
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")
    _ensure_utf8_stdio()
    os.makedirs(DATASET_DIR, exist_ok=True)
    os.makedirs(RESULT_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    args = build_parser().parse_args()
    if args.mode == "scan":
        run_scan_mode(args)
    elif args.mode == "generate-big-file":
        run_generate_mode(args)
    else:
        run_detect_mode(args)


if __name__ == "__main__":
    main()

