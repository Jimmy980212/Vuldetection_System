import os
import re
from typing import Any, Dict, List

from core.base import BaseAgent
from core.models import ValidationResultContract
from utils.cve_knowledge import CVEKnowledgeBase


class ValidationAgent(BaseAgent):
    """Validate model output by evidence scoring and CWE/CVE consistency checks."""

    def __init__(self, cve_db_path: str = None):
        super().__init__()

        self.vulnerability_patterns = {
            "buffer_overflow": [
                r"\bstrcpy\(",
                r"\bstrcat\(",
                r"\bgets\(",
                r"\bsprintf\(",
                r"\bmemcpy\(",
                r"\bmemmove\(",
            ],
            "use_after_free": [r"\bfree\([^)]+\)", r"\bdelete\s+", r"\bdelete\["],
            "double_free": [r"\bfree\([^)]+\)[\s\S]{0,200}\bfree\("],
            "out_of_bounds": [r"\[[^\]]+\]", r"\bmemcpy\(", r"\bstrncpy\("],
            "null_pointer": [r"\bNULL\b", r"\bnullptr\b", r"\->"],
            "memory_leak": [r"\bmalloc\(", r"\bcalloc\(", r"\brealloc\(", r"\bnew\s+"],
            "command_injection": [r"\bsystem\(", r"\bexec\w*\(", r"\bpopen\("],
            "format_string": [r"\bprintf\([^,\)]*\)", r"\bfprintf\([^,]+,[^,\)]*\)"],
            "integer_overflow": [r"\boverflow\b", r"\bINT_MAX\b", r"\bUINT_MAX\b"],
        }

        self.cwe_to_family = {
            "CWE-120": "buffer_overflow",
            "CWE-121": "buffer_overflow",
            "CWE-122": "buffer_overflow",
            "CWE-415": "double_free",
            "CWE-416": "use_after_free",
            "CWE-787": "out_of_bounds",
            "CWE-125": "out_of_bounds",
            "CWE-126": "out_of_bounds",
            "CWE-476": "null_pointer",
            "CWE-401": "memory_leak",
            "CWE-78": "command_injection",
            "CWE-134": "format_string",
            "CWE-190": "integer_overflow",
        }

        if cve_db_path is None:
            cve_db_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "data", "CVE_collection.xlsx"
            )
        self.cve_knowledge = CVEKnowledgeBase(cve_db_path)

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        analysis = input_data.get("analysis", {}) or {}
        sliced_code = input_data.get("sliced_code", "") or ""

        validation_result = {
            "is_valid": True,
            "validation_issues": [],
            "confidence_adjustment": 0.0,
            "validation_details": {},
            "suggestions": [],
            "validation_reason": "",
            "evidence_score": 0.0,
            "requires_manual_review": False,
        }

        required_fields = [
            "is_vulnerable",
            "confidence",
            "analysis",
            "cwe_id",
            "recommendation",
            "vulnerability_type",
            "exploitability",
            "context_info",
            "trigger_condition",
        ]
        for field in required_fields:
            if field not in analysis:
                validation_result["is_valid"] = False
                validation_result["validation_issues"].append(f"Missing required field: {field}")

        evidence_validation = self._validate_code_patterns(sliced_code, analysis)
        validation_result["validation_details"]["code_patterns"] = evidence_validation
        validation_result["evidence_score"] = evidence_validation["overall_score"]

        cwe_validation = self._validate_cwe_id(analysis.get("cwe_id", ""), sliced_code)
        validation_result["validation_details"]["cwe_validation"] = cwe_validation

        cve_coverage = self._validate_cve_coverage(analysis.get("cwe_id", ""))
        validation_result["validation_details"]["cve_coverage"] = cve_coverage

        if not cwe_validation["is_valid"]:
            validation_result["is_valid"] = False
            validation_result["validation_issues"].append(cwe_validation["message"])

        if not evidence_validation["consistency"]:
            validation_result["validation_issues"].append(
                "Pattern consistency mismatch between code evidence and model verdict."
            )

        decision_status = str(analysis.get("decision_status", "confirmed")).lower()
        needs_review = bool(analysis.get("needs_review", False))
        if decision_status == "degraded" or needs_review:
            validation_result["requires_manual_review"] = True
            validation_result["suggestions"].append(
                "Model inference is degraded/uncertain. Please perform manual triage."
            )

        adjustment = self._compute_confidence_adjustment(
            evidence_score=evidence_validation["overall_score"],
            consistency=evidence_validation["consistency"],
            cwe_valid=cwe_validation["is_valid"],
            known_cwe=cve_coverage["is_known_cwe"],
            degraded=decision_status == "degraded",
        )
        validation_result["confidence_adjustment"] = adjustment

        if not cve_coverage["is_known_cwe"]:
            validation_result["suggestions"].append(
                "Predicted CWE not found in CVE sheet; review CWE classification."
            )

        if evidence_validation["overall_score"] < 0.22 and analysis.get("is_vulnerable", False):
            validation_result["requires_manual_review"] = True
            validation_result["suggestions"].append(
                "Low local evidence for a positive verdict. Add reproducer or PoC-based confirmation."
            )

        validation_result["validation_reason"] = (
            "Validation passed."
            if not validation_result["validation_issues"]
            else "; ".join(validation_result["validation_issues"])
        )
        return ValidationResultContract.from_dict(validation_result).to_dict()

    def _validate_code_patterns(self, code: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        matched_patterns: List[Dict[str, str]] = []
        lowered_code = code or ""

        family_scores: Dict[str, float] = {}
        for vuln_family, patterns in self.vulnerability_patterns.items():
            hits = 0
            for pattern in patterns:
                if re.search(pattern, lowered_code, flags=re.IGNORECASE):
                    hits += 1
                    matched_patterns.append({"vulnerability_family": vuln_family, "pattern": pattern})
            if patterns:
                family_scores[vuln_family] = hits / len(patterns)
            else:
                family_scores[vuln_family] = 0.0

        predicted_family = self._infer_predicted_family(analysis)
        predicted_score = family_scores.get(predicted_family, 0.0) if predicted_family else 0.0
        max_score = max(family_scores.values()) if family_scores else 0.0
        overall_score = max(predicted_score, max_score)

        verdict = bool(analysis.get("is_vulnerable", False))
        consistency = True
        if verdict and overall_score < 0.22:
            consistency = False
        if not verdict and overall_score > 0.45:
            consistency = False

        return {
            "matched_patterns": matched_patterns,
            "consistency": consistency,
            "predicted_family": predicted_family,
            "family_scores": family_scores,
            "overall_score": round(float(overall_score), 3),
        }

    def _infer_predicted_family(self, analysis: Dict[str, Any]) -> str:
        cwe_id = str(analysis.get("cwe_id", "")).upper()
        if cwe_id in self.cwe_to_family:
            return self.cwe_to_family[cwe_id]

        text = f"{analysis.get('vulnerability_type', '')} {analysis.get('analysis', '')}".lower()
        alias_map = {
            "buffer_overflow": ["buffer overflow", "stack overflow", "heap overflow"],
            "use_after_free": ["use after free", "uaf"],
            "double_free": ["double free"],
            "out_of_bounds": ["out of bounds", "out-of-bounds", "oob"],
            "null_pointer": ["null pointer", "nullptr"],
            "memory_leak": ["memory leak"],
            "command_injection": ["command injection"],
            "format_string": ["format string"],
            "integer_overflow": ["integer overflow"],
        }
        for family, aliases in alias_map.items():
            if any(alias in text for alias in aliases):
                return family
        return ""

    def _validate_cwe_id(self, cwe_id: str, code: str) -> Dict[str, Any]:
        if not cwe_id:
            return {"is_valid": False, "message": "Missing CWE ID"}

        if cwe_id == "N/A":
            return {"is_valid": True, "message": "Non-vulnerability/tooling classification"}

        if not cwe_id.startswith("CWE-"):
            return {"is_valid": False, "message": "Invalid CWE format"}

        family = self.cwe_to_family.get(cwe_id)
        if not family:
            return {"is_valid": True, "message": "CWE format valid (no strict family mapping)"}

        patterns = self.vulnerability_patterns.get(family, [])
        for pattern in patterns:
            if re.search(pattern, code or "", flags=re.IGNORECASE):
                return {"is_valid": True, "message": f"CWE aligns with code pattern family '{family}'"}

        return {"is_valid": False, "message": f"CWE '{cwe_id}' is weakly supported by current code slice"}

    def _validate_cve_coverage(self, cwe_id: str) -> Dict[str, Any]:
        if not cwe_id or cwe_id == "N/A":
            return {"is_known_cwe": True, "message": "Not applicable"}

        if not self.cve_knowledge.loaded:
            return {"is_known_cwe": True, "message": "CVE knowledge base unavailable"}

        is_known = self.cve_knowledge.is_known_cwe(cwe_id)
        return {
            "is_known_cwe": is_known,
            "message": "CWE present in CVE collection" if is_known else "CWE not present in CVE collection",
        }

    @staticmethod
    def _compute_confidence_adjustment(
        evidence_score: float,
        consistency: bool,
        cwe_valid: bool,
        known_cwe: bool,
        degraded: bool,
    ) -> float:
        adjustment = 0.0

        # Evidence score centered around 0.5, scaled into [-0.12, +0.12]
        adjustment += (evidence_score - 0.5) * 0.24

        adjustment += 0.05 if consistency else -0.09
        adjustment += 0.04 if cwe_valid else -0.06
        adjustment += 0.02 if known_cwe else -0.01
        if degraded:
            adjustment -= 0.07

        adjustment = max(-0.3, min(0.22, adjustment))
        return round(adjustment, 3)
