from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "y", "on"}:
            return True
        if text in {"0", "false", "no", "n", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


@dataclass
class ProgramSliceContract:
    source_lines: List[int] = field(default_factory=list)
    sink_lines: List[int] = field(default_factory=list)
    slice_lines: List[int] = field(default_factory=list)
    sliced_code: str = ""
    control_flow: Dict[str, List[int]] = field(default_factory=dict)
    slice_quality: str = "low"

    required_fields = ("sliced_code", "source_lines", "sink_lines", "slice_lines", "control_flow")

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "ProgramSliceContract":
        payload = data or {}
        control_flow_raw = payload.get("control_flow", {}) or {}
        control_flow: Dict[str, List[int]] = {}
        if isinstance(control_flow_raw, dict):
            for key, values in control_flow_raw.items():
                items = values if isinstance(values, list) else []
                control_flow[str(key)] = [_to_int(item, 0) for item in items]

        return cls(
            source_lines=[_to_int(item, 0) for item in (payload.get("source_lines", []) or [])],
            sink_lines=[_to_int(item, 0) for item in (payload.get("sink_lines", []) or [])],
            slice_lines=[_to_int(item, 0) for item in (payload.get("slice_lines", []) or [])],
            sliced_code=str(payload.get("sliced_code", "") or ""),
            control_flow=control_flow,
            slice_quality=str(payload.get("slice_quality", "low") or "low"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_lines": list(self.source_lines),
            "sink_lines": list(self.sink_lines),
            "slice_lines": list(self.slice_lines),
            "sliced_code": str(self.sliced_code),
            "control_flow": dict(self.control_flow),
            "slice_quality": str(self.slice_quality),
        }


@dataclass
class AlertContract:
    alert_id: str = ""
    file: str = ""
    line: int = 0
    func: str = "unknown"
    msg: str = ""
    severity: str = "unknown"
    tool: str = "unknown"
    program_slice: ProgramSliceContract = field(default_factory=ProgramSliceContract)

    required_fields = ("file", "line", "msg", "severity")

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "AlertContract":
        payload = data or {}
        return cls(
            alert_id=str(payload.get("alert_id", "") or ""),
            file=str(payload.get("file", "") or ""),
            line=_to_int(payload.get("line", 0), 0),
            func=str(payload.get("func", "unknown") or "unknown"),
            msg=str(payload.get("msg", "") or ""),
            severity=str(payload.get("severity", "unknown") or "unknown"),
            tool=str(payload.get("tool", "unknown") or "unknown"),
            program_slice=ProgramSliceContract.from_dict(payload.get("program_slice", {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": str(self.alert_id),
            "file": str(self.file),
            "line": int(self.line),
            "func": str(self.func),
            "msg": str(self.msg),
            "severity": str(self.severity),
            "tool": str(self.tool),
            "program_slice": self.program_slice.to_dict(),
        }


@dataclass
class InferenceResultContract:
    is_vulnerable: bool = False
    confidence: float = 0.0
    analysis: str = ""
    cwe_id: str = "CWE-000"
    recommendation: str = ""
    vulnerability_type: str = "Unknown"
    exploitability: str = "Medium"
    context_info: str = ""
    trigger_condition: str = ""
    decision_status: str = "confirmed"
    needs_review: bool = False
    degraded_reason: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    required_fields = (
        "is_vulnerable",
        "confidence",
        "analysis",
        "cwe_id",
        "recommendation",
        "vulnerability_type",
        "exploitability",
        "context_info",
        "trigger_condition",
    )

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "InferenceResultContract":
        payload = data or {}
        evidence = payload.get("evidence", {}) or {}
        if not isinstance(evidence, dict):
            evidence = {}
        return cls(
            is_vulnerable=_to_bool(payload.get("is_vulnerable", False), False),
            confidence=max(0.0, min(1.0, _to_float(payload.get("confidence", 0.0), 0.0))),
            analysis=str(payload.get("analysis", "") or ""),
            cwe_id=str(payload.get("cwe_id", "CWE-000") or "CWE-000"),
            recommendation=str(payload.get("recommendation", "") or ""),
            vulnerability_type=str(payload.get("vulnerability_type", "Unknown") or "Unknown"),
            exploitability=str(payload.get("exploitability", "Medium") or "Medium"),
            context_info=str(payload.get("context_info", "") or ""),
            trigger_condition=str(payload.get("trigger_condition", "") or ""),
            decision_status=str(payload.get("decision_status", "confirmed") or "confirmed"),
            needs_review=_to_bool(payload.get("needs_review", False), False),
            degraded_reason=str(payload.get("degraded_reason", "") or ""),
            evidence=evidence,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_vulnerable": bool(self.is_vulnerable),
            "confidence": float(self.confidence),
            "analysis": str(self.analysis),
            "cwe_id": str(self.cwe_id),
            "recommendation": str(self.recommendation),
            "vulnerability_type": str(self.vulnerability_type),
            "exploitability": str(self.exploitability),
            "context_info": str(self.context_info),
            "trigger_condition": str(self.trigger_condition),
            "decision_status": str(self.decision_status),
            "needs_review": bool(self.needs_review),
            "degraded_reason": str(self.degraded_reason),
            "evidence": dict(self.evidence),
        }


@dataclass
class ValidationResultContract:
    is_valid: bool = True
    validation_reason: str = ""
    validation_issues: List[str] = field(default_factory=list)
    confidence_adjustment: float = 0.0
    suggestions: List[str] = field(default_factory=list)
    validation_details: Dict[str, Any] = field(default_factory=dict)
    evidence_score: float = 0.0
    requires_manual_review: bool = False

    required_fields = (
        "is_valid",
        "validation_reason",
        "validation_issues",
        "confidence_adjustment",
        "suggestions",
        "validation_details",
    )

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "ValidationResultContract":
        payload = data or {}
        issues = payload.get("validation_issues", []) or []
        suggestions = payload.get("suggestions", []) or []
        details = payload.get("validation_details", {}) or {}
        if not isinstance(issues, list):
            issues = [str(issues)]
        if not isinstance(suggestions, list):
            suggestions = [str(suggestions)]
        if not isinstance(details, dict):
            details = {}
        return cls(
            is_valid=_to_bool(payload.get("is_valid", True), True),
            validation_reason=str(payload.get("validation_reason", "") or ""),
            validation_issues=[str(item) for item in issues],
            confidence_adjustment=_to_float(payload.get("confidence_adjustment", 0.0), 0.0),
            suggestions=[str(item) for item in suggestions],
            validation_details=details,
            evidence_score=max(0.0, min(1.0, _to_float(payload.get("evidence_score", 0.0), 0.0))),
            requires_manual_review=_to_bool(payload.get("requires_manual_review", False), False),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": bool(self.is_valid),
            "validation_reason": str(self.validation_reason),
            "validation_issues": list(self.validation_issues),
            "confidence_adjustment": float(self.confidence_adjustment),
            "suggestions": list(self.suggestions),
            "validation_details": dict(self.validation_details),
            "evidence_score": float(self.evidence_score),
            "requires_manual_review": bool(self.requires_manual_review),
        }


@dataclass
class ReportContract:
    alert_id: str = ""
    file: str = "unknown"
    line: int = 0
    function: str = "unknown"
    severity: str = "unknown"
    vulnerability_type: str = "Unknown"
    cwe_id: str = "CWE-000"
    risk_level: str = "None"
    trigger_condition: str = ""
    description: str = ""
    recommendation: str = ""
    confidence: float = 0.0
    analysis: str = ""
    exploitability: str = "Unknown"
    decision_status: str = "confirmed"
    needs_review: bool = False
    validation: Dict[str, Any] = field(default_factory=dict)

    required_fields = (
        "file",
        "line",
        "function",
        "vulnerability_type",
        "cwe_id",
        "risk_level",
        "trigger_condition",
        "description",
        "recommendation",
        "confidence",
        "analysis",
    )

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "ReportContract":
        payload = data or {}
        validation = payload.get("validation", {}) or {}
        if not isinstance(validation, dict):
            validation = {}
        return cls(
            alert_id=str(payload.get("alert_id", "") or ""),
            file=str(payload.get("file", "unknown") or "unknown"),
            line=_to_int(payload.get("line", 0), 0),
            function=str(payload.get("function", "unknown") or "unknown"),
            severity=str(payload.get("severity", "unknown") or "unknown"),
            vulnerability_type=str(payload.get("vulnerability_type", "Unknown") or "Unknown"),
            cwe_id=str(payload.get("cwe_id", "CWE-000") or "CWE-000"),
            risk_level=str(payload.get("risk_level", "None") or "None"),
            trigger_condition=str(payload.get("trigger_condition", "") or ""),
            description=str(payload.get("description", "") or ""),
            recommendation=str(payload.get("recommendation", "") or ""),
            confidence=max(0.0, min(1.0, _to_float(payload.get("confidence", 0.0), 0.0))),
            analysis=str(payload.get("analysis", "") or ""),
            exploitability=str(payload.get("exploitability", "Unknown") or "Unknown"),
            decision_status=str(payload.get("decision_status", "confirmed") or "confirmed"),
            needs_review=_to_bool(payload.get("needs_review", False), False),
            validation=validation,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": str(self.alert_id),
            "file": str(self.file),
            "line": int(self.line),
            "function": str(self.function),
            "severity": str(self.severity),
            "vulnerability_type": str(self.vulnerability_type),
            "cwe_id": str(self.cwe_id),
            "risk_level": str(self.risk_level),
            "trigger_condition": str(self.trigger_condition),
            "description": str(self.description),
            "recommendation": str(self.recommendation),
            "confidence": float(self.confidence),
            "analysis": str(self.analysis),
            "exploitability": str(self.exploitability),
            "decision_status": str(self.decision_status),
            "needs_review": bool(self.needs_review),
            "validation": dict(self.validation),
        }
