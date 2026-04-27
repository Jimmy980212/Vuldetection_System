import json
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: str | Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _normalize_path(value: str) -> str:
    return str(value or "").replace("\\", "/").strip().lower()


def _same_file(left: str, right: str) -> bool:
    left_norm = _normalize_path(left)
    right_norm = _normalize_path(right)
    if not left_norm or not right_norm:
        return False
    return left_norm == right_norm or left_norm.endswith("/" + right_norm) or right_norm.endswith("/" + left_norm)


def _is_positive_report(report: Dict[str, Any], min_confidence: float) -> bool:
    risk_level = str(report.get("risk_level", "None")).strip().lower()
    if risk_level in {"", "none"}:
        return False
    confidence = float(report.get("confidence", 0.0) or 0.0)
    return confidence >= min_confidence


def _iter_reports(payload: Dict[str, Any] | List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    reports = payload.get("reports", [])
    return reports if isinstance(reports, list) else []


def _iter_labels(payload: Dict[str, Any] | List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    labels = payload.get("labels", [])
    return labels if isinstance(labels, list) else []


def _match_report(
    report: Dict[str, Any],
    label: Dict[str, Any],
    line_tolerance: int,
    require_cwe: bool,
) -> bool:
    if not _same_file(str(report.get("file", "")), str(label.get("file", ""))):
        return False

    report_line = int(report.get("line", 0) or 0)
    label_line = int(label.get("line", 0) or 0)
    if label_line > 0 and report_line > 0 and abs(report_line - label_line) > line_tolerance:
        return False

    if require_cwe:
        report_cwe = str(report.get("cwe_id", "")).strip().upper()
        label_cwe = str(label.get("cwe_id", "")).strip().upper()
        if label_cwe and report_cwe != label_cwe:
            return False

    return True


def evaluate_reports(
    report_payload: Dict[str, Any] | List[Dict[str, Any]],
    label_payload: Dict[str, Any] | List[Dict[str, Any]],
    line_tolerance: int = 2,
    require_cwe: bool = False,
    min_confidence: float = 0.0,
) -> Dict[str, Any]:
    reports = [r for r in _iter_reports(report_payload) if _is_positive_report(r, min_confidence)]
    labels = [l for l in _iter_labels(label_payload) if bool(l.get("is_vulnerable", True))]

    matched_reports = set()
    matches: List[Dict[str, Any]] = []

    for label in labels:
        matched_idx = None
        for idx, report in enumerate(reports):
            if idx in matched_reports:
                continue
            if _match_report(report, label, line_tolerance=line_tolerance, require_cwe=require_cwe):
                matched_idx = idx
                break

        if matched_idx is not None:
            matched_reports.add(matched_idx)
            report = reports[matched_idx]
            matches.append(
                {
                    "label_id": label.get("id", ""),
                    "file": label.get("file", ""),
                    "expected_line": label.get("line", 0),
                    "reported_line": report.get("line", 0),
                    "expected_cwe": label.get("cwe_id", ""),
                    "reported_cwe": report.get("cwe_id", ""),
                    "risk_level": report.get("risk_level", ""),
                    "confidence": report.get("confidence", 0.0),
                }
            )

    tp = len(matches)
    fp = len(reports) - tp
    fn = len(labels) - tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "line_tolerance": int(line_tolerance),
        "require_cwe": bool(require_cwe),
        "min_confidence": float(min_confidence),
        "positive_reports": len(reports),
        "positive_labels": len(labels),
        "matches": matches,
    }


def save_metrics(metrics: Dict[str, Any], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
