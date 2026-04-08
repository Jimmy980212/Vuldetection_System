# agents/report_agent.py
import csv
import io
import json
import os
import tempfile
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.base import BaseAgent
from core.models import ReportContract


class ReportAgent(BaseAgent):
    """Generate and persist standardized vulnerability reports."""
    _scan_index_lock = threading.Lock()

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        alert = input_data.get("alert")
        analysis = input_data.get("analysis")
        validation = input_data.get("validation")

        if not alert or not analysis:
            return {"error": "Missing alert or analysis data", "report": None}

        report = self.generate_standardized_report(alert, analysis, validation)
        return {"report": report}

    def save_reports(
        self,
        reports: List[Dict[str, Any]],
        run_metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        output_dir = self._get_output_dir()
        history_root = os.path.join(output_dir, "history")
        latest_dir = os.path.join(output_dir, "latest")
        os.makedirs(history_root, exist_ok=True)
        os.makedirs(latest_dir, exist_ok=True)

        if run_metadata is None:
            run_metadata = {}
        scan_id = run_metadata.get("scan_id") or datetime.now().strftime("%Y%m%d_%H%M%S")
        ordered_reports = self._sort_reports(reports)

        payload = {
            "scan_metadata": run_metadata,
            "summary": self._build_summary(ordered_reports),
            "reports": ordered_reports,
        }
        markdown_report = self._build_markdown(payload)
        csv_report = self._build_csv_rows(ordered_reports)

        scan_dir = os.path.join(history_root, str(scan_id))
        os.makedirs(scan_dir, exist_ok=True)
        scan_report_file = os.path.join(scan_dir, "vulnerability_report.json")
        with open(scan_report_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        with open(os.path.join(scan_dir, "vulnerability_report.md"), "w", encoding="utf-8") as f:
            f.write(markdown_report)
        with open(os.path.join(scan_dir, "vulnerability_report.csv"), "w", encoding="utf-8", newline="") as f:
            f.write(csv_report)

        latest_report_file = os.path.join(latest_dir, "vulnerability_report.json")
        with open(latest_report_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        with open(os.path.join(latest_dir, "vulnerability_report.md"), "w", encoding="utf-8") as f:
            f.write(markdown_report)
        with open(os.path.join(latest_dir, "vulnerability_report.csv"), "w", encoding="utf-8", newline="") as f:
            f.write(csv_report)

        self._update_scan_index(output_dir, payload)
        return latest_report_file

    def _get_output_dir(self) -> str:
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs", "reports")

    def generate_standardized_report(
        self,
        alert: Dict[str, Any],
        analysis: Dict[str, Any],
        validation: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        risk_level = self._determine_risk_level(analysis)

        report = {
            "alert_id": alert.get("alert_id", ""),
            "file": alert.get("file", "unknown"),
            "line": int(alert.get("line", 0) or 0),
            "function": alert.get("func", "unknown"),
            "severity": alert.get("severity", "unknown"),
            "vulnerability_type": analysis.get("vulnerability_type", "Unknown"),
            "cwe_id": analysis.get("cwe_id", "CWE-000"),
            "risk_level": risk_level,
            "trigger_condition": analysis.get("trigger_condition", "Not provided"),
            "description": analysis.get("analysis", "No analysis provided"),
            "recommendation": analysis.get("recommendation", "No recommendation provided"),
            "confidence": float(analysis.get("confidence", 0.0) or 0.0),
            "analysis": analysis.get("analysis", "No analysis provided"),
            "exploitability": analysis.get("exploitability", "Unknown"),
            "decision_status": analysis.get("decision_status", "confirmed"),
            "needs_review": bool(analysis.get("needs_review", False)),
        }

        if validation:
            report["validation"] = {
                "is_valid": validation.get("is_valid", False),
                "validation_reason": validation.get("validation_reason", "No validation performed"),
                "validation_issues": validation.get("validation_issues", []),
                "confidence_adjustment": validation.get("confidence_adjustment", 0.0),
                "suggestions": validation.get("suggestions", []),
                "evidence_score": validation.get("evidence_score", 0.0),
                "requires_manual_review": validation.get("requires_manual_review", False),
            }

        return ReportContract.from_dict(report).to_dict()

    @staticmethod
    def _determine_risk_level(analysis: Dict[str, Any]) -> str:
        cwe_id = analysis.get("cwe_id", "")
        confidence = float(analysis.get("confidence", 0.0) or 0.0)
        is_vuln = bool(analysis.get("is_vulnerable", False))
        needs_review = bool(analysis.get("needs_review", False))

        if not is_vuln:
            return "None"

        high_risk_cwes = {"CWE-119", "CWE-120", "CWE-121", "CWE-787", "CWE-416", "CWE-78"}
        if cwe_id in high_risk_cwes and confidence >= 0.72 and not needs_review:
            return "High"
        if confidence >= 0.5:
            return "Medium"
        return "Low"

    @staticmethod
    def _build_summary(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        summary = {
            "total_reports": len(reports),
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0,
            "needs_review": 0,
            "degraded": 0,
        }
        for report in reports:
            level = str(report.get("risk_level", "None")).lower()
            if level in summary:
                summary[level] += 1
            else:
                summary["none"] += 1

            if report.get("needs_review"):
                summary["needs_review"] += 1
            if str(report.get("decision_status", "")).lower() == "degraded":
                summary["degraded"] += 1
        return summary

    @staticmethod
    def _risk_rank(risk_level: str) -> int:
        order = {"high": 3, "medium": 2, "low": 1, "none": 0}
        return order.get(str(risk_level).lower(), -1)

    @classmethod
    def _sort_reports(cls, reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def sort_key(report: Dict[str, Any]) -> Any:
            file_path = str(report.get("file", "")).lower()
            line = int(report.get("line", 0) or 0)
            confidence = float(report.get("confidence", 0.0) or 0.0)
            risk_rank = cls._risk_rank(str(report.get("risk_level", "None")))
            return (-risk_rank, -confidence, file_path, line)

        return sorted(reports, key=sort_key)

    @staticmethod
    def _to_yes_no(value: Any) -> str:
        return "Yes" if bool(value) else "No"

    @staticmethod
    def _sanitize_text(value: Any) -> str:
        return str(value or "").replace("\r\n", " ").replace("\n", " ").strip()

    @classmethod
    def _build_markdown(cls, payload: Dict[str, Any]) -> str:
        metadata = payload.get("scan_metadata", {})
        summary = payload.get("summary", {})
        reports = payload.get("reports", [])
        tools = metadata.get("tools", {}) or {}
        if not isinstance(tools, dict):
            tools = {}

        cppcheck_raw = tools.get("cppcheck", {})
        joern_raw = tools.get("joern", {})

        cppcheck_info = cppcheck_raw if isinstance(cppcheck_raw, dict) else {"enabled": bool(cppcheck_raw)}
        joern_info = (
            joern_raw
            if isinstance(joern_raw, dict)
            else {"enabled": bool(joern_raw), "status": "enabled" if joern_raw else "disabled"}
        )

        lines: List[str] = [
            "# Vulnerability Scan Report",
            "",
            "## Scan Overview",
            f"- Scan ID: `{metadata.get('scan_id', 'N/A')}`",
            f"- Target: `{metadata.get('target_path', 'N/A')}`",
            f"- Started At: `{metadata.get('started_at', 'N/A')}`",
            f"- Finished At: `{metadata.get('finished_at', 'N/A')}`",
            f"- Cppcheck Alerts: `{cppcheck_info.get('alerts', metadata.get('cppcheck_alerts', 0))}`",
            f"- Joern Status: `{joern_info.get('status', metadata.get('joern_status', 'unknown'))}`",
            f"- Joern Alerts: `{joern_info.get('alerts', metadata.get('joern_alerts', 0))}`",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "| --- | --- |",
            f"| Total Findings | {summary.get('total_reports', 0)} |",
            f"| High | {summary.get('high', 0)} |",
            f"| Medium | {summary.get('medium', 0)} |",
            f"| Low | {summary.get('low', 0)} |",
            f"| None | {summary.get('none', 0)} |",
            f"| Needs Review | {summary.get('needs_review', 0)} |",
            f"| Degraded | {summary.get('degraded', 0)} |",
            "",
            "## Findings",
            "",
        ]

        if not reports:
            lines.append("No vulnerabilities found.")
            lines.append("")
            return "\n".join(lines)

        lines.extend(
            [
                "| # | Risk | Confidence | Type | Location | Review |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for idx, report in enumerate(reports, start=1):
            vuln_type = cls._sanitize_text(report.get("vulnerability_type", "Unknown")).replace("|", "\\|")
            file_path = cls._sanitize_text(report.get("file", "unknown")).replace("|", "\\|")
            line_no = int(report.get("line", 0) or 0)
            location = f"{file_path}:{line_no}"
            risk = cls._sanitize_text(report.get("risk_level", "None"))
            confidence = float(report.get("confidence", 0.0) or 0.0)
            review = cls._to_yes_no(report.get("needs_review"))
            lines.append(f"| {idx} | {risk} | {confidence:.2f} | {vuln_type} | `{location}` | {review} |")

        lines.extend(["", "## Detailed Findings", ""])
        for idx, report in enumerate(reports, start=1):
            validation = report.get("validation", {}) or {}
            lines.extend(
                [
                    f"### {idx}. {cls._sanitize_text(report.get('vulnerability_type', 'Unknown'))}",
                    f"- Alert ID: `{cls._sanitize_text(report.get('alert_id', 'N/A'))}`",
                    f"- Location: `{cls._sanitize_text(report.get('file', 'unknown'))}:{int(report.get('line', 0) or 0)}`",
                    f"- Function: `{cls._sanitize_text(report.get('function', 'unknown'))}`",
                    f"- CWE: `{cls._sanitize_text(report.get('cwe_id', 'CWE-000'))}`",
                    f"- Risk Level: `{cls._sanitize_text(report.get('risk_level', 'None'))}`",
                    f"- Confidence: `{float(report.get('confidence', 0.0) or 0.0):.2f}`",
                    f"- Decision Status: `{cls._sanitize_text(report.get('decision_status', 'unknown'))}`",
                    f"- Needs Review: `{cls._to_yes_no(report.get('needs_review'))}`",
                    f"- Validation Passed: `{cls._to_yes_no(validation.get('is_valid'))}`",
                    f"- Validation Reason: {cls._sanitize_text(validation.get('validation_reason', 'N/A'))}",
                    "",
                    "**Trigger Condition**",
                    cls._sanitize_text(report.get("trigger_condition", "Not provided")) or "Not provided",
                    "",
                    "**Description**",
                    cls._sanitize_text(report.get("description", "No description")) or "No description",
                    "",
                    "**Recommendation**",
                    cls._sanitize_text(report.get("recommendation", "No recommendation")) or "No recommendation",
                    "",
                ]
            )

        return "\n".join(lines)

    @classmethod
    def _build_csv_rows(cls, reports: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = [
            "alert_id",
            "file",
            "line",
            "function",
            "severity",
            "vulnerability_type",
            "cwe_id",
            "risk_level",
            "confidence",
            "decision_status",
            "needs_review",
            "requires_manual_review",
            "is_valid",
            "validation_reason",
            "trigger_condition",
            "recommendation",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for report in reports:
            validation = report.get("validation", {}) or {}
            writer.writerow(
                {
                    "alert_id": cls._sanitize_text(report.get("alert_id", "")),
                    "file": cls._sanitize_text(report.get("file", "")),
                    "line": int(report.get("line", 0) or 0),
                    "function": cls._sanitize_text(report.get("function", "")),
                    "severity": cls._sanitize_text(report.get("severity", "")),
                    "vulnerability_type": cls._sanitize_text(report.get("vulnerability_type", "")),
                    "cwe_id": cls._sanitize_text(report.get("cwe_id", "")),
                    "risk_level": cls._sanitize_text(report.get("risk_level", "")),
                    "confidence": f"{float(report.get('confidence', 0.0) or 0.0):.2f}",
                    "decision_status": cls._sanitize_text(report.get("decision_status", "")),
                    "needs_review": cls._to_yes_no(report.get("needs_review")),
                    "requires_manual_review": cls._to_yes_no(validation.get("requires_manual_review")),
                    "is_valid": cls._to_yes_no(validation.get("is_valid")),
                    "validation_reason": cls._sanitize_text(validation.get("validation_reason", "")),
                    "trigger_condition": cls._sanitize_text(report.get("trigger_condition", "")),
                    "recommendation": cls._sanitize_text(report.get("recommendation", "")),
                }
            )

        return output.getvalue()

    @classmethod
    def _update_scan_index(cls, output_dir: str, payload: Dict[str, Any]) -> None:
        index_file = os.path.join(output_dir, "scan_index.json")
        os.makedirs(output_dir, exist_ok=True)

        with cls._scan_index_lock:
            index = []
            if os.path.exists(index_file):
                try:
                    with open(index_file, "r", encoding="utf-8") as f:
                        index = json.load(f) or []
                except Exception:
                    index = []

            meta = payload.get("scan_metadata", {})
            summary = payload.get("summary", {})
            entry = {
                "scan_id": meta.get("scan_id"),
                "target_path": meta.get("target_path"),
                "started_at": meta.get("started_at"),
                "finished_at": meta.get("finished_at"),
                "report_count": summary.get("total_reports", 0),
                "high": summary.get("high", 0),
                "medium": summary.get("medium", 0),
                "low": summary.get("low", 0),
                "needs_review": summary.get("needs_review", 0),
                "degraded": summary.get("degraded", 0),
            }
            index.append(entry)
            index = index[-200:]

            tmp_file = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    delete=False,
                    dir=output_dir,
                    prefix="scan_index_",
                    suffix=".tmp",
                ) as f:
                    json.dump(index, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                    tmp_file = f.name

                os.replace(tmp_file, index_file)
            finally:
                if tmp_file and os.path.exists(tmp_file):
                    try:
                        os.remove(tmp_file)
                    except Exception:
                        pass
