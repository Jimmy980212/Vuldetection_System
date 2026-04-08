from typing import Any, Dict, Iterable, List, Tuple, Type


class SchemaValidator:
    """Lightweight runtime schema validator used across agents."""

    @staticmethod
    def validate(
        data: Dict[str, Any],
        schema: Dict[str, Type[Any]],
        required: Iterable[str],
    ) -> Tuple[bool, List[str]]:
        if not isinstance(data, dict):
            return False, ["Payload must be a dict."]

        errors: List[str] = []
        for field in required:
            if field not in data:
                errors.append(f"Missing required field: {field}")

        for key, expected_type in schema.items():
            if key not in data:
                continue
            value = data.get(key)
            if value is None:
                continue

            if expected_type is float and isinstance(value, int):
                continue
            if expected_type is int and isinstance(value, bool):
                errors.append(f"Field '{key}' should be int, got bool.")
                continue
            if not isinstance(value, expected_type):
                errors.append(
                    f"Field '{key}' should be {expected_type.__name__}, got {type(value).__name__}."
                )

        return len(errors) == 0, errors


class AlertSchema:
    def __init__(self):
        self.schema = {
            "alert_id": str,
            "file": str,
            "line": int,
            "func": str,
            "msg": str,
            "severity": str,
            "tool": str,
            "program_slice": dict,
        }
        self.required = ("file", "line", "msg", "severity")

    def validate(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        return SchemaValidator.validate(data, self.schema, self.required)


class ProgramSliceSchema:
    def __init__(self):
        self.schema = {
            "sliced_code": str,
            "source_lines": list,
            "sink_lines": list,
            "slice_lines": list,
            "control_flow": dict,
            "slice_quality": str,
        }
        self.required = ("sliced_code", "source_lines", "sink_lines", "slice_lines", "control_flow")

    def validate(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        return SchemaValidator.validate(data, self.schema, self.required)


class InferenceResultSchema:
    def __init__(self):
        self.schema = {
            "is_vulnerable": bool,
            "confidence": float,
            "analysis": str,
            "cwe_id": str,
            "recommendation": str,
            "vulnerability_type": str,
            "exploitability": str,
            "context_info": str,
            "trigger_condition": str,
            "decision_status": str,
            "needs_review": bool,
            "degraded_reason": str,
        }
        self.required = (
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

    def validate(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        return SchemaValidator.validate(data, self.schema, self.required)


class ValidationResultSchema:
    def __init__(self):
        self.schema = {
            "is_valid": bool,
            "validation_reason": str,
            "validation_issues": list,
            "confidence_adjustment": float,
            "suggestions": list,
            "validation_details": dict,
            "evidence_score": float,
            "requires_manual_review": bool,
        }
        self.required = (
            "is_valid",
            "validation_reason",
            "validation_issues",
            "confidence_adjustment",
            "suggestions",
            "validation_details",
        )

    def validate(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        return SchemaValidator.validate(data, self.schema, self.required)


class ReportSchema:
    def __init__(self):
        self.schema = {
            "file": str,
            "line": int,
            "function": str,
            "vulnerability_type": str,
            "cwe_id": str,
            "risk_level": str,
            "trigger_condition": str,
            "description": str,
            "recommendation": str,
            "confidence": float,
            "analysis": str,
            "validation": dict,
            "decision_status": str,
            "needs_review": bool,
        }
        self.required = (
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

    def validate(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        return SchemaValidator.validate(data, self.schema, self.required)
