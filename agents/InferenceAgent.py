import json
import os
import re
import hashlib
from typing import Any, Dict, Optional

from core.base import BaseAgent
from core.models import InferenceResultContract
from utils.cve_knowledge import CVEKnowledgeBase
from utils.structured_logging import get_logger, log_event
from utils.llm_manager import get_multi_llm_manager


LOGGER = get_logger("vuldetection.inference")


class InferenceAgent(BaseAgent):
    def __init__(
        self,
        model_name: str = "deepseek-coder",
        base_url: Optional[str] = "https://api.deepseek.com/v1",
        api_key: Optional[str] = None,
        cve_db_path: Optional[str] = None,
        llm_rpm_limit: int = 60,
        llm_breaker_failure_threshold: int = 2,
        llm_breaker_reset_sec: float = 30.0,
        llm_client_max_retries: int = 1,
        llm_client_retry_backoff_sec: float = 0.2,
        llm_timeout_sec: int = 120,
        provider_name: Optional[str] = None,
    ):
        super().__init__()
        self.model_name = model_name
        self.base_url = base_url
        self.api_key = api_key
        self.llm_timeout_sec = max(5, int(llm_timeout_sec or 120))
        self.provider_name = provider_name

        self.multi_llm = get_multi_llm_manager()

        if provider_name:
            self.multi_llm.set_active_provider(provider_name)

        if cve_db_path is None:
            cve_db_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "data", "CVE_collection.xlsx"
            )
        self.cve_knowledge = CVEKnowledgeBase(cve_db_path)
        self.prompt_template = self._get_prompt_template()

    def preflight_health_check(self) -> Dict[str, Any]:
        return self.multi_llm.preflight_health_check()

    @staticmethod
    def _get_prompt_template() -> str:
        return """
You are a senior C/C++ security reviewer.
Analyze the following alert and source-sink evidence package, then output strict JSON only.
Prefer concrete evidence over dangerous API names. Treat missing guards as a hypothesis to verify.

file: {file}
line: {line}
function: {func}
alert: {sink}
source_lines: {source_lines}
sink_lines: {sink_lines}
slice_lines: {slice_lines}
prompt_token_budget: {prompt_token_budget}

source_sink_evidence:
```json
{evidence_context}
```

code:
```c
{sliced_code}
```

CVE context:
{cve_intel}

JSON schema:
{{
  "is_vulnerable": bool,
  "confidence": float,
  "analysis": "reasoning",
  "cwe_id": "CWE-xxx",
  "recommendation": "fix",
  "vulnerability_type": "type",
  "exploitability": "High|Medium|Low",
  "context_info": "context",
  "trigger_condition": "trigger"
}}
"""

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        alert_info = input_data.get("alert") or {}
        sliced_code = input_data.get("sliced_code")

        program_slice = alert_info.get("program_slice", {}) or {}
        if not sliced_code:
            sliced_code = program_slice.get("sliced_code", "")

        if not alert_info or not sliced_code:
            return self._fallback_result(
                alert_info=alert_info,
                sliced_code=sliced_code or "",
                error_msg="Missing alert info or sliced code",
                degraded=True,
                degraded_reason="invalid_input",
            )

        source_lines = program_slice.get("source_lines", [])
        sink_lines = program_slice.get("sink_lines", [])
        slice_lines = program_slice.get("slice_lines", [])

        alert_msg = alert_info.get("msg", "")
        cve_intel = self.cve_knowledge.build_prompt_context(alert_msg=alert_msg, cwe_hint=alert_msg)
        prompt_inputs = self._build_budgeted_prompt_inputs(
            program_slice=program_slice,
            sliced_code=sliced_code,
            cve_intel=cve_intel,
        )

        def render_prompt() -> str:
            return self.prompt_template.format(
                file=alert_info.get("file", "unknown"),
                line=alert_info.get("line", 0),
                func=alert_info.get("func", "unknown"),
                sink=alert_msg,
                sliced_code=prompt_inputs["sliced_code"],
                source_lines=source_lines,
                sink_lines=sink_lines,
                slice_lines=slice_lines,
                evidence_context=prompt_inputs["evidence_context"],
                cve_intel=prompt_inputs["cve_intel"],
                prompt_token_budget=prompt_inputs["max_prompt_tokens"],
            )

        prompt = render_prompt()
        for _ in range(3):
            estimated = self._estimate_tokens(prompt)
            if estimated <= prompt_inputs["max_prompt_tokens"]:
                break
            overflow = estimated - prompt_inputs["max_prompt_tokens"]
            code_tokens = self._estimate_tokens(prompt_inputs["sliced_code"])
            if code_tokens > 220:
                prompt_inputs["sliced_code"] = self._trim_text_to_tokens(
                    prompt_inputs["sliced_code"],
                    max(220, code_tokens - overflow - 100),
                )
            else:
                evidence_tokens = self._estimate_tokens(prompt_inputs["evidence_context"])
                prompt_inputs["evidence_context"] = self._trim_text_to_tokens(
                    prompt_inputs["evidence_context"],
                    max(260, evidence_tokens - overflow - 60),
                )
            prompt = render_prompt()
        estimated_prompt_tokens = self._estimate_tokens(prompt)

        local_evidence = self._collect_local_evidence(alert_msg=alert_msg, sliced_code=sliced_code)
        try:
            system_prompt = "You are a strict C/C++ vulnerability auditor. Output valid JSON only."
            log_event(
                LOGGER,
                "inference_start",
                alert_id=alert_info.get("alert_id", ""),
                file=alert_info.get("file", ""),
                line=alert_info.get("line", 0),
                provider=self.multi_llm.active_provider.provider_name if self.multi_llm.active_provider else "unknown",
                estimated_prompt_tokens=estimated_prompt_tokens,
                prompt_token_budget=prompt_inputs["max_prompt_tokens"],
            )

            result_str, error = self.multi_llm.call_with_fallback(
                prompt=prompt,
                system_prompt=system_prompt,
                timeout_sec=self.llm_timeout_sec,
            )
            if not result_str.strip():
                log_event(
                    LOGGER,
                    "inference_empty_response",
                    alert_id=alert_info.get("alert_id", ""),
                    error=error or "Empty model response",
                    status="degraded",
                )
                return self._fallback_result(
                    alert_info=alert_info,
                    sliced_code=sliced_code,
                    error_msg=error or "Empty model response",
                    degraded=True,
                    local_evidence=local_evidence,
                    degraded_reason=self._classify_degraded_reason(
                        error or "Empty model response"
                    ),
                )

            parsed = self._extract_json_payload(result_str)
            if parsed is None:
                log_event(
                    LOGGER,
                    "inference_parse_error",
                    alert_id=alert_info.get("alert_id", ""),
                    status="degraded",
                )
                return self._fallback_result(
                    alert_info=alert_info,
                    sliced_code=sliced_code,
                    error_msg="No JSON found in model response",
                    degraded=True,
                    raw_response=result_str,
                    local_evidence=local_evidence,
                    degraded_reason="response_parse_error",
                )

            result = self._normalize_result(
                parsed,
                alert_info=alert_info,
                raw_response=result_str,
                local_evidence=local_evidence,
                degraded=False,
            )
            log_event(
                LOGGER,
                "inference_complete",
                alert_id=alert_info.get("alert_id", ""),
                confidence=result.get("confidence", 0.0),
                decision_status=result.get("decision_status", "confirmed"),
                status="ok",
            )
            return result
        except Exception as exc:  # pragma: no cover - defensive path
            log_event(
                LOGGER,
                "inference_exception",
                alert_id=alert_info.get("alert_id", ""),
                error=str(exc),
                status="degraded",
            )
            return self._fallback_result(
                alert_info=alert_info,
                sliced_code=sliced_code,
                error_msg=f"Inference exception: {exc}",
                degraded=True,
                local_evidence=local_evidence,
                degraded_reason="inference_exception",
            )

    @staticmethod
    def _extract_json_payload(result_str: str) -> Optional[Dict[str, Any]]:
        if not result_str:
            return None

        fenced = re.search(r"```json\s*([\s\S]*?)\s*```", result_str, flags=re.IGNORECASE)
        if fenced:
            try:
                return json.loads(fenced.group(1))
            except json.JSONDecodeError:
                pass

        start = result_str.find("{")
        end = result_str.rfind("}")
        if start != -1 and end != -1 and end > start:
            raw = result_str[start : end + 1]
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return None
        return None

    @staticmethod
    def _classify_degraded_reason(error_msg: str, raw_response: str = "") -> str:
        text = f"{error_msg or ''} {raw_response or ''}".lower()
        if "timeout" in text:
            return "llm_timeout"
        if "winerror 10013" in text or "e_accessdenied" in text or "access denied" in text:
            return "llm_network_blocked"
        if "429" in text or "rate limit" in text:
            return "llm_rate_limited"
        if "503" in text or "502" in text or "500" in text or "504" in text:
            return "llm_upstream_error"
        if "connection_error" in text or "connection" in text or "dns" in text:
            return "llm_network_error"
        if "empty model response" in text or "did not contain text" in text:
            return "empty_response"
        if "json" in text and "no json found" in text:
            return "response_parse_error"
        return "unknown_degraded"

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, (len(str(text or "")) + 3) // 4)

    @staticmethod
    def _trim_text_to_tokens(text: str, max_tokens: int) -> str:
        value = str(text or "")
        if InferenceAgent._estimate_tokens(value) <= max_tokens:
            return value
        max_chars = max(80, int(max_tokens) * 4)
        return value[:max_chars].rstrip() + "\n... [truncated to fit prompt token budget]"

    @staticmethod
    def _resolve_prompt_token_budget(program_slice: Dict[str, Any]) -> int:
        token_budget = program_slice.get("token_budget", {}) if isinstance(program_slice, dict) else {}
        raw = token_budget.get("max_prompt_tokens", os.getenv("VULDET_MAX_PROMPT_TOKENS", 3600))
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 3600
        return max(2000, min(4000, value))

    def _compact_evidence_context(self, program_slice: Dict[str, Any], max_tokens: int) -> str:
        prompt_context = str(program_slice.get("prompt_context", "") or "")
        if prompt_context:
            try:
                parsed = json.loads(prompt_context)
                parsed.pop("code_excerpt", None)
                prompt_context = json.dumps(parsed, ensure_ascii=False, indent=2)
            except Exception:
                pass
            if self._estimate_tokens(prompt_context) <= max_tokens:
                return prompt_context

        evidence = program_slice.get("evidence_package", {}) or {}
        if not isinstance(evidence, dict):
            evidence = {}
        compact = {
            "source_sink_evidence": {
                "version": evidence.get("version", "source_sink_evidence.v1"),
                "function": evidence.get("function", {}),
                "alert_line": evidence.get("alert_line", 0),
                "key_variables": (evidence.get("key_variables", []) or [])[:8],
                "source_sink_paths": (evidence.get("source_sink_paths", []) or [])[:3],
                "control_conditions": (evidence.get("control_conditions", []) or [])[:6],
                "sanitizers": (evidence.get("sanitizers", []) or [])[:6],
                "memory_events": (evidence.get("memory_events", []) or [])[:6],
                "dangerous_calls": (evidence.get("dangerous_calls", []) or [])[:8],
                "notes": (evidence.get("notes", []) or [])[:2],
            }
        }
        text = json.dumps(compact, ensure_ascii=False, indent=2)
        return self._trim_text_to_tokens(text, max_tokens)

    def _build_budgeted_prompt_inputs(
        self,
        program_slice: Dict[str, Any],
        sliced_code: str,
        cve_intel: str,
    ) -> Dict[str, Any]:
        max_prompt_tokens = self._resolve_prompt_token_budget(program_slice)
        evidence_budget = min(760, max(420, max_prompt_tokens // 4))
        cve_budget = min(320, max(180, max_prompt_tokens // 10))
        template_overhead = 760
        code_budget = max(260, max_prompt_tokens - evidence_budget - cve_budget - template_overhead)

        evidence_context = self._compact_evidence_context(program_slice, evidence_budget)
        budgeted_code = self._trim_text_to_tokens(sliced_code, code_budget)
        budgeted_cve = self._trim_text_to_tokens(cve_intel, cve_budget)

        return {
            "max_prompt_tokens": max_prompt_tokens,
            "evidence_context": evidence_context,
            "sliced_code": budgeted_code,
            "cve_intel": budgeted_cve,
        }

    def _normalize_result(
        self,
        result: Dict[str, Any],
        alert_info: Dict[str, Any],
        raw_response: str,
        local_evidence: Dict[str, Any],
        degraded: bool,
    ) -> Dict[str, Any]:
        family = self.cve_knowledge.infer_family_from_text(
            f"{alert_info.get('msg', '')} {result.get('vulnerability_type', '')}",
            cwe_hint=result.get("cwe_id", ""),
        )
        default_cwe, default_type = self.cve_knowledge.get_family_default(family or "unknown")

        confidence = result.get("confidence", 0.0)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        cwe_id = str(result.get("cwe_id", "")).strip()
        if not cwe_id.startswith("CWE-") and cwe_id != "N/A":
            cwe_id = default_cwe

        normalized = {
            "is_vulnerable": bool(result.get("is_vulnerable", False)),
            "confidence": confidence,
            "analysis": str(result.get("analysis", "")).strip() or "No analysis returned.",
            "cwe_id": cwe_id or default_cwe,
            "recommendation": str(result.get("recommendation", "")).strip()
            or "Add strict boundary/lifetime checks and harden error paths.",
            "vulnerability_type": str(result.get("vulnerability_type", "")).strip() or default_type,
            "exploitability": str(result.get("exploitability", "")).strip() or "Medium",
            "context_info": str(result.get("context_info", "")).strip() or "No context info returned.",
            "trigger_condition": str(result.get("trigger_condition", "")).strip()
            or "Potentially reachable by crafted input along source->sink path.",
            "decision_status": "degraded" if degraded else "confirmed",
            "needs_review": degraded or confidence < 0.45,
            "degraded_reason": "unknown_degraded" if degraded else "",
            "evidence": local_evidence,
        }

        if not degraded and raw_response:
            normalized["raw_excerpt"] = raw_response[:400]
        return InferenceResultContract.from_dict(normalized).to_dict()

    def _fallback_result(
        self,
        alert_info: Dict[str, Any],
        sliced_code: str,
        error_msg: str,
        degraded: bool,
        raw_response: str = "",
        local_evidence: Optional[Dict[str, Any]] = None,
        degraded_reason: str = "unknown_degraded",
    ) -> Dict[str, Any]:
        msg = (alert_info.get("msg", "") or "").lower()
        family = self.cve_knowledge.infer_family_from_text(f"{msg}\n{sliced_code}", cwe_hint=msg)
        cwe_id, vuln_type = self.cve_knowledge.get_family_default(family or "unknown")

        if "include file" in msg:
            return InferenceResultContract.from_dict(
                {
                    "is_vulnerable": False,
                    "confidence": 0.85,
                    "analysis": "Static analysis environment warning, not a real vulnerability.",
                    "cwe_id": "N/A",
                    "recommendation": "Fix tool include path configuration; ignore this finding for security scoring.",
                    "vulnerability_type": "Tooling Warning",
                    "exploitability": "Low",
                    "context_info": f"Fallback reason: {error_msg}",
                    "trigger_condition": "Build/include path misconfiguration.",
                    "decision_status": "degraded" if degraded else "confirmed",
                    "needs_review": False,
                    "degraded_reason": degraded_reason if degraded else "",
                    "error": error_msg,
                    "evidence": local_evidence or {},
                }
            ).to_dict()

        evidence_strength = 0.0
        if local_evidence:
            evidence_strength = float(local_evidence.get("score", 0.0))

        if family is not None and evidence_strength >= 0.3:
            return InferenceResultContract.from_dict(
                {
                    "is_vulnerable": True,
                    "confidence": min(0.7, 0.45 + evidence_strength * 0.35),
                    "analysis": (
                        "Degraded inference: classified by CVE-family similarity and local code evidence. "
                        "Manual review recommended."
                    ),
                    "cwe_id": cwe_id,
                    "recommendation": "Apply strict bounds/lifetime checks and verify all error/cleanup paths.",
                    "vulnerability_type": vuln_type,
                    "exploitability": "Medium",
                    "context_info": f"Fallback reason: {error_msg}",
                    "trigger_condition": "Potentially reachable attacker-controlled path to sensitive operation.",
                    "decision_status": "degraded" if degraded else "confirmed",
                    "needs_review": True,
                    "degraded_reason": degraded_reason if degraded else "",
                    "error": error_msg,
                    "evidence": local_evidence or {},
                }
            ).to_dict()

        return InferenceResultContract.from_dict(
            {
                "is_vulnerable": False,
                "confidence": 0.42,
                "analysis": "Degraded inference: no strong vulnerability evidence. Manual review recommended.",
                "cwe_id": cwe_id,
                "recommendation": "Keep the code under review; add targeted tests for boundary and lifetime cases.",
                "vulnerability_type": vuln_type,
                "exploitability": "Low",
                "context_info": f"Fallback reason: {error_msg}. Raw: {raw_response[:300]}",
                "trigger_condition": "Not established in fallback mode.",
                "decision_status": "degraded" if degraded else "confirmed",
                "needs_review": True,
                "degraded_reason": degraded_reason if degraded else "",
                "error": error_msg,
                "evidence": local_evidence or {},
            }
        ).to_dict()

    def _collect_local_evidence(self, alert_msg: str, sliced_code: str) -> Dict[str, Any]:
        families = {
            "buffer_overflow": [
                r"\bstrcpy\s*\(",
                r"\bstrcat\s*\(",
                r"\bsprintf\s*\(",
                r"\bmemcpy\s*\(",
                r"\bgets\s*\(",
            ],
            "use_after_free": [r"\bfree\s*\(", r"\bdelete\s+"],
            "double_free": [r"\bfree\s*\([^)]+\)[\s\S]{0,240}\bfree\s*\(", r"\bdelete\s+"],
            "out_of_bounds": [r"\[[^\]]+\]", r"\bmemcpy\s*\(", r"\bmemmove\s*\(", r"\bmemcmp\s*\("],
            "null_pointer": [r"\bNULL\b", r"\bnullptr\b", r"->", r"\*\s*\w+"],
            "format_string": [r"\bprintf\s*\([^,\)]*\)", r"\bfprintf\s*\([^,]+,[^,\)]*\)"],
            "command_injection": [r"\bsystem\s*\(", r"\bexec\w*\s*\("],
            "integer_overflow": [r"\+\s*\w+", r"-\s*\w+", r"\bINT_MAX\b", r"overflow"],
        }

        text = f"{alert_msg}\n{sliced_code}"
        family_hits: Dict[str, int] = {}
        total_hits = 0
        for family, patterns in families.items():
            hits = 0
            for pattern in patterns:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    hits += 1
            if hits:
                family_hits[family] = hits
                total_hits += hits

        score = min(1.0, total_hits / 6.0)
        return {"family_hits": family_hits, "score": round(score, 3)}


if __name__ == "__main__":
    agent = InferenceAgent()
    test_alert = {"file": "test.c", "line": 10, "func": "main", "msg": "strcpy(dest, src)"}
    test_code = """
void main() {
    char src[100] = "long string...";
    char dest[10];
    strcpy(dest, src);
}
"""
    print(json.dumps(agent.run({"alert": test_alert, "sliced_code": test_code}), indent=2, ensure_ascii=False))
