import os
import uuid
from datetime import datetime
from typing import Dict

from agents.FeatureAgent import FeatureAgent
from agents.InferenceAgent import InferenceAgent
from agents.PreprocessAgent import PreprocessAgent
from agents.ValidationAgent import ValidationAgent
from agents.report_agent import ReportAgent
from core.contracts import ScanRequest
from core.orchestrator import AgentCoordinator
from core.pipeline import CandidateEngine, DeepAnalyzer
from utils.structured_logging import get_logger, log_event


LOGGER = get_logger("vuldetection.main")


def run_vulnerability_detection(
    target_path: str,
    cppcheck_path: str = None,
    max_alerts: int = 30,
    analysis_workers: int = 4,
    wsl_distro: str = None,
    enable_joern: bool = True,
    save_cpg: bool = True,
) -> Dict[str, object]:
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
    started_at = datetime.now().isoformat(timespec="seconds")

    print(f"=== Starting Vulnerability Detection for: {target_path} ===")
    print(f"Scan ID: {scan_id}")
    print(f"Tools: Cppcheck + {'Joern' if enable_joern else 'N/A'}")
    log_event(
        LOGGER,
        "scan_start",
        scan_id=scan_id,
        target_path=os.path.abspath(target_path),
        enable_joern=enable_joern,
        max_alerts=max_alerts,
        analysis_workers=analysis_workers,
    )

    coordinator = AgentCoordinator()
    cpg_output_dir = None
    if enable_joern and save_cpg:
        cpg_output_dir = os.path.join(os.path.dirname(__file__), "outputs", "cpg", scan_id)
        os.makedirs(cpg_output_dir, exist_ok=True)

    cve_db_path = os.path.join(os.path.dirname(__file__), "data", "CVE_collection.xlsx")
    preprocess_agent = PreprocessAgent(
        cppcheck_path=cppcheck_path,
        wsl_distro=wsl_distro,
        enable_joern=enable_joern,
    )
    feature_agent = FeatureAgent(window_size=35)
    inference_agent = InferenceAgent(
        base_url="https://api.deepseek.com/v1",
        model_name="deepseek-coder",
        cve_db_path=cve_db_path,
    )
    validation_agent = ValidationAgent(cve_db_path=cve_db_path)
    report_agent = ReportAgent()

    coordinator.register_agent(preprocess_agent)
    coordinator.register_agent(feature_agent)
    coordinator.register_agent(inference_agent)
    coordinator.register_agent(validation_agent)
    coordinator.register_agent(report_agent)

    scan_request = ScanRequest(
        target_path=target_path,
        max_alerts=max_alerts,
        analysis_workers=analysis_workers,
        enable_joern=enable_joern,
        save_cpg=save_cpg,
        enable_all=True,
        cpg_output_dir=cpg_output_dir,
        schema_failure_policy=os.getenv("VULDET_SCHEMA_POLICY", "fail_close"),
    )
    candidate_engine = CandidateEngine(
        coordinator=coordinator,
        preprocess_agent=preprocess_agent,
        inference_agent=inference_agent,
    )
    deep_analyzer = DeepAnalyzer(
        coordinator=coordinator,
        preprocess_agent=preprocess_agent,
        feature_agent=feature_agent,
        inference_agent=inference_agent,
        validation_agent=validation_agent,
        report_agent=report_agent,
    )

    print("\n=== Stage 1/2: Candidate Engine ===")
    try:
        candidate_result = candidate_engine.run(scan_request)
    except Exception as exc:
        print(f"Error in CandidateEngine: {exc}")
        log_event(LOGGER, "candidate_stage_failed", scan_id=scan_id, error=str(exc), status="error")
        return {"scan_id": scan_id, "error": str(exc), "reports": []}

    project_info = candidate_result.project_info
    dedup_stats = candidate_result.dedup_stats
    print(
        f"Found {dedup_stats['input']} raw alerts, "
        f"removed {dedup_stats['duplicates_removed']} duplicates, "
        f"remaining {dedup_stats['deduped']}."
    )
    print(f"  - Cppcheck alerts: {project_info.get('cppcheck_raw_count', 0)}")
    print(f"  - Joern alerts: {project_info.get('joern_raw_count', 0)}")
    print(f"  - Joern status: {project_info.get('joern_status', 'unknown')}")
    if project_info.get("cpg_path"):
        print(f"  - CPG file: {project_info.get('cpg_path')}")

    print("\n=== Stage 2/2: Deep Analyzer ===")
    deep_result = deep_analyzer.run(scan_request, candidate_result)

    finished_at = datetime.now().isoformat(timespec="seconds")
    scan_metadata = {
        "scan_id": scan_id,
        "target_path": os.path.abspath(target_path),
        "started_at": started_at,
        "finished_at": finished_at,
        "max_alerts": max_alerts,
        "tools": {
            "cppcheck": {
                "enabled": True,
                "alerts": project_info.get("cppcheck_raw_count", 0),
            },
            "joern": {
                "requested": enable_joern,
                "available": project_info.get("joern_available", False),
                "executed": project_info.get("joern_executed", False),
                "status": project_info.get("joern_status", "unknown"),
                "error": project_info.get("joern_error", ""),
                "alerts": project_info.get("joern_raw_count", 0),
            },
        },
        "cppcheck_alerts": project_info.get("cppcheck_raw_count", 0),
        "joern_alerts": project_info.get("joern_raw_count", 0),
        "raw_alerts": dedup_stats["input"],
        "duplicates_removed": dedup_stats["duplicates_removed"],
        "alerts_considered": dedup_stats["deduped"],
        "alerts_processed": deep_result.processed_alerts,
        "alerts_skipped": deep_result.skipped_alerts,
        "unresolved_path_skips": deep_result.unresolved_path_skips,
        "degraded_alerts": deep_result.degraded_alerts,
        "schema_warning_count": len(deep_result.schema_warnings),
        "cpg_path": project_info.get("cpg_path"),
        "pipeline_stages": ["candidate_engine", "deep_analyzer"],
        "stage_metrics": {
            "candidate_engine": candidate_result.metrics,
            "deep_analyzer": deep_result.metrics,
        },
    }

    ordered_reports = report_agent._sort_reports(deep_result.reports)

    print("\n=== Final Analysis Report ===")
    report_file = report_agent.save_reports(ordered_reports, run_metadata=scan_metadata)
    report_dir = os.path.dirname(report_file)
    markdown_report_file = os.path.join(report_dir, "vulnerability_report.md")
    csv_report_file = os.path.join(report_dir, "vulnerability_report.csv")
    if ordered_reports:
        risk_counts = {"high": 0, "medium": 0, "low": 0, "none": 0, "needs_review": 0, "degraded": 0}
        for report in ordered_reports:
            level = str(report.get("risk_level", "None")).lower()
            if level in risk_counts:
                risk_counts[level] += 1
            else:
                risk_counts["none"] += 1
            if report.get("needs_review"):
                risk_counts["needs_review"] += 1
            if str(report.get("decision_status", "")).lower() == "degraded":
                risk_counts["degraded"] += 1

        print(
            "Findings summary: "
            f"total={len(ordered_reports)}, "
            f"high={risk_counts['high']}, "
            f"medium={risk_counts['medium']}, "
            f"low={risk_counts['low']}, "
            f"none={risk_counts['none']}, "
            f"needs_review={risk_counts['needs_review']}, "
            f"degraded={risk_counts['degraded']}"
        )
        print("Top findings (up to 5):")
        for report in ordered_reports[:5]:
            file_path = report.get("file", "unknown")
            line_no = int(report.get("line", 0) or 0)
            print(
                "  - "
                f"[{report.get('risk_level', 'None')}] "
                f"{report.get('vulnerability_type', 'Unknown')} "
                f"at {file_path}:{line_no} "
                f"(confidence={float(report.get('confidence', 0.0) or 0.0):.2f})"
            )
        if len(ordered_reports) > 5:
            print(f"  - ... and {len(ordered_reports) - 5} more findings in the full report.")
    else:
        print("No vulnerabilities found.")

    print("\nReport files:")
    print(f"  - JSON: {report_file}")
    print(f"  - Markdown: {markdown_report_file}")
    print(f"  - CSV: {csv_report_file}")
    if deep_result.schema_warnings:
        print(f"Schema warnings ({len(deep_result.schema_warnings)}):")
        for warning in deep_result.schema_warnings[:10]:
            print(f"  - {warning}")

    log_event(
        LOGGER,
        "scan_complete",
        scan_id=scan_id,
        elapsed_sec=round((datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)).total_seconds(), 2),
        alerts_processed=deep_result.processed_alerts,
        reports_count=len(ordered_reports),
        schema_warning_count=len(deep_result.schema_warnings),
        status="ok",
    )

    return {
        "scan_id": scan_id,
        "report_file": report_file,
        "reports": ordered_reports,
        "metadata": scan_metadata,
        "schema_warnings": deep_result.schema_warnings,
    }


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "data", "test_codes", "test_10_vulnerabilities.c")
    custom_cppcheck_path = "D:/CS/cppcheck/cppcheck.exe"
    run_vulnerability_detection(target, cppcheck_path=custom_cppcheck_path)
