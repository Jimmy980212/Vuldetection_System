import argparse
import datetime
import hashlib
import json
import math
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

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
    sample_meta = {
        "ground_truth": bool(getattr(sample, "is_vulnerable", False)),
        "true_cwes": list(getattr(sample, "cwe_list", None) or []),
        "idx": getattr(sample, "idx", None),
    }

    file_id = hashlib.md5(str(file_path).encode("utf-8", errors="ignore")).hexdigest()[:10]
    temp_file = os.path.join(temp_dir, f"{file_id}_{file_name}")
    os.makedirs(os.path.dirname(temp_file), exist_ok=True)

    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(code)

    try:
        start_time = time.time()
        result = meta_agent.analyze(
            temp_file,
            code,
            {"file_name": file_name, "project": project},
        )
        elapsed = time.time() - start_time
        return {
            "success": True,
            "result": result,
            "file_name": file_name,
            "project": project,
            "elapsed": elapsed,
            **sample_meta,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "file_name": file_name,
            "project": project,
            **sample_meta,
        }


def _pred_cwes_from_report(report: Dict[str, Any]) -> List[str]:
    by_cwe = report.get("vulnerabilities_by_cwe") or {}
    if by_cwe:
        return sorted(by_cwe.keys())
    out = []
    for v in report.get("vulnerabilities") or []:
        c = v.get("cwe_id") or v.get("cwe") or v.get("type")
        if c:
            out.append(str(c).strip())
    return sorted(set(out))


def _normalize_cwe_set(cwes: List[str]) -> set:
    s = set()
    for c in cwes or []:
        t = str(c).strip().upper()
        if t:
            s.add(t)
    return s


def _build_eval_rows_for_source(source: str, analyze_results: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    if source not in ("primevul", "secvul"):
        return [], 0
    rows: List[Dict[str, Any]] = []
    failed = 0
    for r in analyze_results:
        if not r.get("success"):
            failed += 1
            continue
        report = r["result"]["report"]
        n = int(report.get("total_vulnerabilities") or 0)
        pred_positive = n > 0
        pred_cwes = _pred_cwes_from_report(report)
        rows.append(
            {
                "success": True,
                "file_name": r["file_name"],
                "project": r.get("project"),
                "idx": r.get("idx"),
                "ground_truth": bool(r.get("ground_truth", False)),
                "true_cwes": list(r.get("true_cwes") or []),
                "pred_positive": pred_positive,
                "pred_vuln_count": n,
                "pred_cwes": pred_cwes,
                "elapsed": r.get("elapsed", 0.0),
            }
        )
    return rows, failed


def _binary_metrics_from_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    for r in rows:
        gt = r["ground_truth"]
        pr = r["pred_positive"]
        if gt and pr:
            tp += 1
        elif not gt and pr:
            fp += 1
        elif not gt and not pr:
            tn += 1
        else:
            fn += 1
    total = tp + fp + tn + fn
    acc = 100.0 * (tp + tn) / total if total else 0.0
    prec = 100.0 * tp / (tp + fp) if (tp + fp) else 0.0
    rec = 100.0 * tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    denom_mcc = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc = ((tp * tn - fp * fn) / math.sqrt(denom_mcc)) if denom_mcc > 0 else 0.0
    cwe_hits = 0
    cwe_rel = 0
    for r in rows:
        if not (r["ground_truth"] and r["pred_positive"]):
            continue
        cwe_rel += 1
        tset = _normalize_cwe_set(r.get("true_cwes") or [])
        pset = _normalize_cwe_set(r.get("pred_cwes") or [])
        if tset and pset and (tset & pset):
            cwe_hits += 1
    cwe_match_rate = round(100.0 * cwe_hits / cwe_rel, 2) if cwe_rel else 0.0
    return {
        "total_samples": total,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "accuracy": round(acc, 2),
        "precision": round(prec, 2),
        "recall": round(rec, 2),
        "f1_score": round(f1, 2),
        "mcc": round(mcc, 4),
        "cwe_match_rate": cwe_match_rate,
    }


def _load_samples(args) -> List[Any]:
    source = args.source
    if args.huggingface and source == "local":
        source = "secvul"

    if source == "primevul":
        adapter = System4DatasetAdapter(use_huggingface=True, use_mirror=not args.no_mirror)
        print(
            f"从 PrimeVul 加载样本: samples={args.samples}, "
            f"vuln_ratio={args.vuln_ratio}, split={args.split}"
        )
        return adapter.load_primevul_balanced(
            total_samples=max(1, int(args.samples)),
            vuln_ratio=max(0.0, min(1.0, float(args.vuln_ratio))),
            split=args.split,
            seed=int(args.seed),
        )

    if source == "secvul":
        adapter = System4DatasetAdapter(use_huggingface=True, use_mirror=not args.no_mirror)
        print(
            f"从 SecVulEval(HuggingFace) 按比例加载样本: "
            f"samples={args.samples}, vuln_ratio={args.vuln_ratio}, split={args.split}"
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
    return loader.load_files()[: max(1, int(args.max_samples))]


def run_detect_mode(args) -> None:
    samples = _load_samples(args)
    if not samples:
        raise FileNotFoundError("未加载到可检测样本")

    meta_agent = EnhancedMetaAgent(
        use_cache=not args.no_cache,
        enable_hypothesis_extraction=True,
        enable_llm_trigger_path=True,
    )
    print("\n检测语言: C/C++")
    print(f"\n共加载 {len(samples)} 个样本，开始检测（并行度={args.parallel}）")

    all_reports: List[Dict[str, Any]] = []
    analyze_results: List[Dict[str, Any]] = []
    total_start_time = time.time()

    def _handle_done(i: int, n: int, result: Dict[str, Any]) -> None:
        if not result["success"]:
            print(f"[{i}/{n}] {result['file_name']} - 失败: {result['error']}")
            analyze_results.append(result)
            return
        report = result["result"]["report"]
        save_json(report, os.path.join(RESULT_DIR, f"{result['file_name']}.report.json"))
        all_reports.append(report)
        analyze_results.append(result)
        print(
            f"[{i}/{n}] {result['file_name']} - "
            f"{result['elapsed']:.2f}s, 漏洞: {report.get('total_vulnerabilities', 0)}"
        )

    if args.parallel > 1 and len(samples) > 1:
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            future_to_sample = {
                executor.submit(analyze_file, meta_agent, sample, TEMP_DIR): sample for sample in samples
            }
            done = 0
            for fut in as_completed(future_to_sample):
                done += 1
                _handle_done(done, len(samples), fut.result())
    else:
        for i, sample in enumerate(samples, 1):
            result = analyze_file(meta_agent, sample, TEMP_DIR)
            _handle_done(i, len(samples), result)

    total_elapsed = time.time() - total_start_time
    cache_stats = meta_agent.get_cache_stats() if hasattr(meta_agent, "get_cache_stats") else {}

    summary = {
        "scan_time": datetime.datetime.now().isoformat(),
        "mode": "detect",
        "language": "c",
        "source": args.source,
        "total_files": len(all_reports),
        "total_vulnerabilities": sum(r.get("total_vulnerabilities", 0) for r in all_reports),
        "severity_summary": {
            "critical": sum(r.get("severity_summary", {}).get("critical", 0) for r in all_reports),
            "high": sum(r.get("severity_summary", {}).get("high", 0) for r in all_reports),
            "medium": sum(r.get("severity_summary", {}).get("medium", 0) for r in all_reports),
            "low": sum(r.get("severity_summary", {}).get("low", 0) for r in all_reports),
        },
        "cwe_summary": {},
        "results": all_reports,
        "performance_stats": {
            "total_time": total_elapsed,
            "avg_time_per_file": total_elapsed / max(1, len(all_reports)),
            "files_processed": len(all_reports),
            "api_calls": cache_stats.get("llm_cache_stats", {}).get("api_calls", 0),
            "cache_hits": cache_stats.get("llm_cache_stats", {}).get("cache_hits", 0),
            "cache_misses": cache_stats.get("llm_cache_stats", {}).get("cache_misses", 0),
        },
    }

    for report in all_reports:
        for cwe, count in report.get("vulnerabilities_by_cwe", {}).items():
            summary["cwe_summary"][cwe] = summary["cwe_summary"].get(cwe, 0) + count

    eval_rows, eval_failed = _build_eval_rows_for_source(args.source, analyze_results)
    if eval_rows:
        metrics = _binary_metrics_from_rows(eval_rows)
        metrics["failed_samples"] = eval_failed
        metrics["avg_detection_time_sec"] = round(
            sum(r["elapsed"] for r in eval_rows) / max(1, len(eval_rows)), 3
        )
        metrics["total_detection_time_sec"] = round(sum(r["elapsed"] for r in eval_rows), 3)
        fps = len(eval_rows) / metrics["total_detection_time_sec"] if metrics["total_detection_time_sec"] else 0
        metrics["files_per_second"] = round(fps, 3)
        summary["evaluation"] = {
            "rule": "pred_positive iff total_vulnerabilities > 0 (任意检出即阳性)",
            "metrics": metrics,
        }
        eval_cfg = {
            "samples": args.samples,
            "vuln_ratio": args.vuln_ratio,
            "parallel": args.parallel,
            "split": args.split,
            "seed": args.seed,
            "use_mirror": not args.no_mirror,
            "use_cache": not args.no_cache,
        }
        eval_out = {
            "timestamp": datetime.datetime.now().isoformat(),
            "dataset": args.source,
            "config": eval_cfg,
            "sample_loaded": len(samples),
            "metrics": metrics,
            "results": eval_rows,
        }
        eval_dir = os.path.join(RESULT_DIR, "evaluation_reports")
        eval_name = f"{args.source}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        eval_path = os.path.join(eval_dir, eval_name)
        save_json(eval_out, eval_path)
        summary["evaluation"]["report_path"] = eval_path

    summary_file = os.path.join(RESULT_DIR, "scan_summary.json")
    save_json(summary, summary_file)
    print("\n" + "=" * 60)
    print("检测完成")
    print(f"总耗时: {total_elapsed:.2f}s")
    print(f"结果目录: {RESULT_DIR}")
    print(f"汇总报告: {summary_file}")
    if eval_rows:
        m = summary["evaluation"]["metrics"]
        print("\n数据集评估（预测阳性 = total_vulnerabilities > 0）")
        print(f"  TP={m['true_positive']} FP={m['false_positive']} TN={m['true_negative']} FN={m['false_negative']}")
        if eval_failed:
            print(f"  解析/检测失败未计入矩阵: {eval_failed}")
        print(f"  混淆矩阵 [[TN, FP],[FN, TP]] = {m['confusion_matrix']}")
        print(
            f"  Accuracy={m['accuracy']}% Precision={m['precision']}% "
            f"Recall={m['recall']}% F1={m['f1_score']}% MCC={m['mcc']} CWE命中率={m['cwe_match_rate']}%"
        )
        print(f"  评估明细: {summary['evaluation']['report_path']}")
    print("=" * 60)


def run_scan_mode(args) -> None:
    checkpoint_path = os.path.abspath(args.checkpoint) if args.checkpoint else None
    print("vulnscan 语言: C/C++（ProjectScanner）")
    scanner = ProjectScanner(
        root_dir=args.root,
        result_dir=args.result_dir,
        temp_dir=args.temp_dir,
        extensions=args.extensions,
        parallel=args.parallel,
        max_files=args.max_files,
        checkpoint_path=checkpoint_path,
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
    parser = argparse.ArgumentParser(description="C/C++ 漏洞检测 CLI：本地/数据集检测 + vulnscan 扫描")
    parser.add_argument(
        "--mode",
        choices=["detect", "scan", "generate-big-file"],
        default="detect",
        help="运行模式：detect(默认) / scan(vulnscan) / generate-big-file",
    )
    parser.add_argument("--lang", choices=["c"], default="c", help="检测/扫描语言，仅支持 c")
    parser.add_argument(
        "--c-workspace-cpg",
        action="store_true",
        help="C/C++ vulnscan：整目录先 joern-parse/export 一次，多文件共享静态结果",
    )
    parser.add_argument(
        "--source",
        choices=["local", "secvul", "primevul"],
        default="local",
        help="检测输入源：local / secvul / primevul",
    )
    parser.add_argument("--file", "-f", help="单文件检测")
    parser.add_argument("--dir", "-d", help="目录检测")
    parser.add_argument("--max-samples", type=int, default=10, help="本地模式最大处理数")
    parser.add_argument("--parallel", type=int, default=2, help="并行度")
    parser.add_argument("--no-cache", action="store_true", help="禁用缓存")
    parser.add_argument("--stats", action="store_true", help="兼容参数：保留但不影响执行")
    parser.add_argument("--huggingface", "-hf", action="store_true", help="兼容参数：等价于 --source secvul")
    parser.add_argument("--samples", type=int, default=20, help="数据集样本数（secvul/primevul）")
    parser.add_argument("--vuln-ratio", type=float, default=0.5, help="漏洞/安全比例（primevul 等）")
    parser.add_argument("--split", default="train", help="HuggingFace split（primevul/secvul，默认 train）")
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
    print("=" * 60)
    print("统一漏洞检测入口（C/C++ CLI）")
    print("=" * 60)

    if args.mode == "scan":
        run_scan_mode(args)
    elif args.mode == "generate-big-file":
        run_generate_mode(args)
    else:
        run_detect_mode(args)


if __name__ == "__main__":
    main()
