import os
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from typing import Any, Dict, Iterable, List, Optional, Tuple

# 确保能从项目根目录导入 `agent.py`
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from enhanced_meta_agent import EnhancedMetaAgent
from joern_utils import JoernHandler, parse_c_workspace

from .checkpoint import CheckpointStore
from .target_discovery import iter_code_files
from .utils import file_signature, now_iso, safe_relpath_id, save_json, md5_text


def _read_text_robust(path: str) -> str:
    # UTF-8 优先；非法字节用替换符保留流结构，避免中文旁边静默截断
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _project_name_from_rel(rel_path: str) -> str:
    # 尽量保持与现有 dataset.CodeSample.project 一致：取相对路径第一段目录
    parts = rel_path.replace("\\", "/").split("/")
    return parts[0] if len(parts) >= 2 else "default"


def _analyze_one(
    meta_agent: EnhancedMetaAgent,
    root_dir: str,
    file_path: str,
    temp_dir: str,
    static_result_override: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    在 worker 内执行“单文件完整检测链路”：
      Joern -> Slice -> LLM -> Validator -> Report
    """
    try:
        code = _read_text_robust(file_path)
        rel_path = os.path.relpath(file_path, root_dir)
        project = _project_name_from_rel(rel_path)
        file_name = os.path.basename(file_path)

        # 每个源文件的 Joern 输入都必须独立，避免并发时临时文件互相覆盖
        file_id = md5_text(os.path.abspath(file_path))[:10]
        os.makedirs(temp_dir, exist_ok=True)
        # 保留扩展名，便于 Joern 区分 Java（javasrc2cpg）与 C/C++（joern-parse）
        temp_file = os.path.join(temp_dir, f"{file_id}_{file_name}")

        # 与 main.analyze_file 一致：Joern 输入使用原始源码，不前置行号
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(code)

        start = time.time()
        result = meta_agent.analyze(
            temp_file,
            code,
            {"file_name": file_name, "project": project},
            static_result_override=static_result_override,
        )
        elapsed = time.time() - start

        return {
            "success": True,
            "elapsed": elapsed,
            "rel_path": rel_path,
            "file_name": file_name,
            "project": project,
            "analysis": result,
            "report": result.get("report", {}),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "rel_path": os.path.relpath(file_path, root_dir),
        }


class ProjectScanner:
    """
    面向大规模程序检测的“扫描编排器”，只做调度与结果落盘：
      - 流式发现目标文件（避免一次性加载全量到内存）
      - 断点续扫（按 mtime + size）
      - 并发调度（控制吞吐）
    """

    def __init__(
        self,
        root_dir: str,
        result_dir: str,
        temp_dir: str,
        extensions: Iterable[str],
        parallel: int = 2,
        max_files: Optional[int] = None,
        checkpoint_path: Optional[str] = None,
        resume: bool = True,
        save_full_analysis: bool = False,
        use_cache: bool = True,
        c_workspace_cpg: bool = False,
    ):
        self.root_dir = os.path.abspath(root_dir)
        self.result_dir = result_dir
        self.temp_dir = temp_dir
        self.extensions = list(extensions)
        self.parallel = max(1, int(parallel))
        self.max_files = max_files
        self.checkpoint_path = checkpoint_path
        self.resume = resume
        self.save_full_analysis = save_full_analysis
        self.use_cache = use_cache
        self.c_workspace_cpg = bool(c_workspace_cpg)

        os.makedirs(self.result_dir, exist_ok=True)
        os.makedirs(self.temp_dir, exist_ok=True)

    def scan(self) -> Dict[str, Any]:
        meta_agent = EnhancedMetaAgent(
            use_cache=self.use_cache,
            enable_hypothesis_extraction=True,
            enable_llm_trigger_path=True,
        )

        # C 工程级 CPG：对 root_dir 只跑一次 joern-parse/export，多文件共享静态结果
        workspace_static: Optional[Dict[str, Any]] = None
        if self.c_workspace_cpg:
            print("vulnscan: 启用 C 工作区级 CPG（单次 joern-parse/export，多文件共享）")
            pe = parse_c_workspace(self.root_dir)
            dot = pe.get("dot_file", "")
            handler = JoernHandler()
            reachable_flows_by_cwe: Dict[str, List[Dict[str, Any]]] = {}
            cpg_bin = pe.get("cpg_bin", "")
            script_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "cscan", "c_flow_extract.sc")
            )
            if cpg_bin and os.path.exists(script_path):
                for cwe in ("CWE-78", "CWE-22", "CWE-119", "CWE-190"):
                    try:
                        reachable_flows_by_cwe[cwe] = handler.extract_c_reachable_flows(
                            cpg_bin=cpg_bin,
                            cwe=cwe,
                            script_path=script_path,
                            max_flows=50,
                            timeout_s=300,
                        )
                    except Exception:
                        reachable_flows_by_cwe[cwe] = []
            workspace_static = {
                "status": "success",
                "slices": handler.extract_slices(dot),
                "data_flows": handler.extract_data_flow(dot),
                "call_graph": handler.extract_call_graph(dot),
                "reachable_flows_by_cwe": reachable_flows_by_cwe,
                "parse_dir": pe.get("parse_dir"),
                "export_dir": pe.get("export_dir"),
                "dot_file": dot,
                "cpg_bin": pe.get("cpg_bin"),
            }

        checkpoint = None
        if self.checkpoint_path:
            checkpoint = CheckpointStore(self.checkpoint_path)
            if self.resume:
                checkpoint.load()

        total_start = time.time()
        files_processed = 0
        total_vulnerabilities = 0

        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cwe_summary: Dict[str, int] = {}
        results_index: List[Dict[str, Any]] = []

        # 流式提交任务：避免一次性把所有 futures 绑在内存里
        max_inflight = max(2, self.parallel * 2)

        def _make_output_paths(rel_id: str) -> Tuple[str, str]:
            report_path = os.path.join(self.result_dir, f"{rel_id}.report.json")
            full_path = os.path.join(self.result_dir, f"{rel_id}.full.json")
            return report_path, full_path

        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            futures: List[Any] = []
            for file_path in iter_code_files(
                self.root_dir,
                self.extensions,
                max_files=self.max_files,
            ):
                rel_path = os.path.relpath(file_path, self.root_dir)
                rel_id = safe_relpath_id(self.root_dir, file_path)
                sig = file_signature(file_path)

                if checkpoint and self.resume and checkpoint.should_skip(rel_id, sig):
                    continue

                futures.append(
                    executor.submit(
                        _analyze_one,
                        meta_agent,
                        self.root_dir,
                        file_path,
                        self.temp_dir,
                        workspace_static,
                    )
                )

                # 控制 inflight 数，避免 futures 过多占用内存
                if len(futures) >= max_inflight:
                    done, not_done = wait(futures, return_when=FIRST_COMPLETED)
                    for fut in done:
                        self._consume_future(fut, checkpoint, _make_output_paths, results_index, severity_summary, cwe_summary)
                        if fut.result().get("success"):
                            files_processed += 1
                    futures = list(not_done)

            for fut in as_completed(futures):
                self._consume_future(fut, checkpoint, _make_output_paths, results_index, severity_summary, cwe_summary)
                if fut.result().get("success"):
                    files_processed += 1

        elapsed = time.time() - total_start

        # 聚合统计（从每个报告的统计字段推导）
        for idx in results_index:
            total_vulnerabilities += int(idx.get("total_vulnerabilities", 0))

        summary = {
            "scan_time": now_iso(),
            "root_dir": self.root_dir,
            "total_files": files_processed,
            "total_vulnerabilities": total_vulnerabilities,
            "severity_summary": severity_summary,
            "cwe_summary": cwe_summary,
            "results_index": results_index,
            "performance_stats": {
                "total_time": elapsed,
                "avg_time_per_file": elapsed / max(1, files_processed),
            },
        }

        # 全局写入汇总文件
        save_json(summary, os.path.join(self.result_dir, "scan_summary.json"))
        return summary

    def _consume_future(
        self,
        fut,
        checkpoint: Optional[CheckpointStore],
        make_output_paths,
        results_index: List[Dict[str, Any]],
        severity_summary: Dict[str, int],
        cwe_summary: Dict[str, int],
    ) -> None:
        data = fut.result()
        if not data.get("success"):
            # 失败不抛出中断整批，便于大规模跑批
            print(f"失败: {data.get('rel_path')} - {data.get('error')}")
            return

        rel_path = data["rel_path"]
        rel_id = safe_relpath_id(self.root_dir, os.path.join(self.root_dir, rel_path))
        report_path, full_path = make_output_paths(rel_id)

        report = data.get("report", {})
        total_vulns = int(report.get("total_vulnerabilities", 0))

        # 落盘：报告总览 + （可选）完整中间结果
        if self.save_full_analysis:
            save_json(data["analysis"], full_path)
        save_json(report, report_path)

        # 更新索引
        results_index.append(
            {
                "file": report.get("file", data.get("file_name")),
                "project": report.get("project", data.get("project")),
                "rel_path": rel_path,
                "report_path": report_path,
                "total_vulnerabilities": total_vulns,
            }
        )

        # 聚合 severity / CWE 统计
        for sev in ["critical", "high", "medium", "low"]:
            severity_summary[sev] += int(report.get("severity_summary", {}).get(sev, 0))

        for cwe, count in report.get("vulnerabilities_by_cwe", {}).items():
            cwe_summary[cwe] = cwe_summary.get(cwe, 0) + int(count)

        # 更新断点续扫
        if checkpoint:
            abs_path = os.path.join(self.root_dir, rel_path)
            checkpoint.mark_done(
                rel_id=rel_id,
                signature=file_signature(abs_path),
                report_path=report_path,
                total_vulnerabilities=total_vulns,
            )

        print(f"完成: {rel_path} - 漏洞 {total_vulns}")

