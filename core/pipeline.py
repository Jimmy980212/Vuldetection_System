import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from agents.FeatureAgent import FeatureAgent
from agents.InferenceAgent import InferenceAgent
from agents.PreprocessAgent import PreprocessAgent
from agents.ValidationAgent import ValidationAgent
from agents.report_agent import ReportAgent
from core.contracts import CandidateStageResult, DeepAnalysisResult, ScanRequest
from core.models import (
    AlertContract,
    InferenceResultContract,
    ProgramSliceContract,
    ReportContract,
    ValidationResultContract,
)
from core.orchestrator import AgentCoordinator
from core.schema import AlertSchema, InferenceResultSchema, ProgramSliceSchema, ReportSchema, ValidationResultSchema
from utils.structured_logging import get_logger, log_event


LOGGER = get_logger("vuldetection.pipeline")


def clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, value))


def build_dedup_stats(raw_alerts: List[Dict], project_info: Dict[str, object]) -> Dict[str, int]:
    """
    Build dedup stats from PreprocessAgent output only.
    CandidateEngine must not perform a second dedup pass.
    """
    total_raw = int(project_info.get("total_raw_count", len(raw_alerts)) or 0)
    deduped = int(project_info.get("deduped_alert_count", len(raw_alerts)) or 0)

    if total_raw < 0:
        total_raw = 0
    if deduped < 0:
        deduped = 0
    if deduped > total_raw:
        deduped = total_raw

    return {
        "input": total_raw,
        "deduped": deduped,
        "duplicates_removed": total_raw - deduped,
    }


def _normalize_schema_policy(policy: str) -> str:
    text = str(policy or "fail_close").strip().lower()
    return text if text in {"fail_open", "fail_close"} else "fail_close"


def rank_alerts(raw_alerts: List[Dict], inference_agent: InferenceAgent) -> List[Dict]:
    quality_bonus = {"high": 2, "medium": 1, "low": 0}

    def score(alert: Dict) -> int:
        msg = alert.get("msg", "")
        severity = alert.get("severity", "")
        base = inference_agent.cve_knowledge.security_relevance_score(msg, severity)

        line_bonus = 1 if int(alert.get("line", 0) or 0) > 0 else 0
        program_slice = alert.get("program_slice", {}) or {}
        slice_lines = program_slice.get("slice_lines", []) or []
        slice_bonus = min(3, len(slice_lines) // 10)
        sq_bonus = quality_bonus.get(str(program_slice.get("slice_quality", "low")).lower(), 0)
        tool = str(alert.get("tool", "")).lower()
        tool_bonus = 0
        if "joern" in tool and "cppcheck" in tool:
            tool_bonus = 3
        elif "joern" in tool:
            tool_bonus = 2
        elif "cppcheck" in tool:
            tool_bonus = 1
        return base + line_bonus + slice_bonus + sq_bonus + tool_bonus

    return sorted(raw_alerts, key=score, reverse=True)


def _is_tooling_noise(alert: Dict) -> bool:
    msg = str(alert.get("msg", "")).lower()
    if "include file" in msg:
        return True
    if "configuration" in msg and "cppcheck" in str(alert.get("tool", "")).lower():
        return True
    return False


def should_skip_alert(alert: Dict, inference_agent: InferenceAgent) -> bool:
    msg = str(alert.get("msg", "")).lower()
    severity = str(alert.get("severity", "")).lower()
    tool = str(alert.get("tool", "")).lower()

    if _is_tooling_noise(alert):
        return True

    if severity == "information" and "limiting analysis" in msg:
        return True

    explicit_skip_phrases = [
        "should have static linkage",
    ]
    if any(phrase in msg for phrase in explicit_skip_phrases):
        return True

    if severity == "style":
        if "unused" in msg and ("function" in msg or "variable" in msg or "parameter" in msg):
            return True
        if "scope can be reduced" in msg:
            return True
        if "inconclusive" in msg:
            return True
        if tool == "joern":
            return False
        security_terms = [
            "overflow",
            "out of bounds",
            "use after free",
            "double free",
            "null pointer",
            "format string",
            "command injection",
            "memory leak",
        ]
        if not any(term in msg for term in security_terms):
            return True
        if inference_agent.cve_knowledge.infer_family_from_text(msg) is None:
            return True

    return False


def is_unresolved_path(file_path: str) -> bool:
    text = str(file_path or "").strip()
    if not text:
        return True
    return "<" in text and ">" in text


class CandidateEngine:
    def __init__(
        self,
        coordinator: AgentCoordinator,
        preprocess_agent: PreprocessAgent,
        inference_agent: InferenceAgent,
    ):
        self.coordinator = coordinator
        self.preprocess_agent = preprocess_agent
        self.inference_agent = inference_agent

    def run(self, scan_request: ScanRequest) -> CandidateStageResult:
        stage_start = time.perf_counter()
        before_metrics = self.coordinator.snapshot_metrics()
        log_event(
            LOGGER,
            "candidate_stage_start",
            stage="candidate_engine",
            target_path=scan_request.target_path,
        )
        preprocess_results = self.coordinator.run_agent(
            "PreprocessAgent",
            {
                "project_path": scan_request.target_path,
                "enable_all": scan_request.enable_all,
                "enable_joern": scan_request.enable_joern,
                "save_cpg": scan_request.save_cpg,
                "cpg_output_dir": scan_request.cpg_output_dir,
                "compute_slices": False,
            },
        )

        project_info = preprocess_results.get("project_info", {})
        raw_alerts = preprocess_results.get("raw_alerts", [])
        normalized_alerts = [AlertContract.from_dict(item).to_dict() for item in raw_alerts]
        dedup_stats = build_dedup_stats(raw_alerts, project_info)
        deduped_alerts = list(normalized_alerts)
        ranked_alerts = rank_alerts(deduped_alerts, self.inference_agent)
        stage_elapsed_ms = round((time.perf_counter() - stage_start) * 1000.0, 2)
        after_metrics = self.coordinator.snapshot_metrics()
        agent_metrics = AgentCoordinator.diff_metrics(before_metrics, after_metrics)
        preprocess_runtime = preprocess_results.get("_runtime", {}) or {}
        metrics = {
            "stage": "candidate_engine",
            "elapsed_ms": stage_elapsed_ms,
            "preprocess_elapsed_ms": float(preprocess_runtime.get("elapsed_ms", 0.0) or 0.0),
            "alerts_raw": dedup_stats.get("input", 0),
            "alerts_ranked": len(ranked_alerts),
            "alerts_deduped": dedup_stats.get("deduped", 0),
            "duplicates_removed": dedup_stats.get("duplicates_removed", 0),
            **agent_metrics,
        }
        log_event(
            LOGGER,
            "candidate_stage_complete",
            stage="candidate_engine",
            elapsed_ms=stage_elapsed_ms,
            alerts_raw=metrics["alerts_raw"],
            alerts_ranked=metrics["alerts_ranked"],
            status="ok",
        )

        return CandidateStageResult(
            project_info=project_info,
            raw_alerts=raw_alerts,
            deduped_alerts=deduped_alerts,
            dedup_stats=dedup_stats,
            ranked_alerts=ranked_alerts,
            metrics=metrics,
        )


class DeepAnalyzer:
    def __init__(
        self,
        coordinator: AgentCoordinator,
        preprocess_agent: PreprocessAgent,
        feature_agent: FeatureAgent,
        inference_agent: InferenceAgent,
        validation_agent: ValidationAgent,
        report_agent: ReportAgent,
    ):
        self.coordinator = coordinator
        self.preprocess_agent = preprocess_agent
        self.feature_agent = feature_agent
        self.inference_agent = inference_agent
        self.validation_agent = validation_agent
        self.report_agent = report_agent
        self.alert_schema = AlertSchema()
        self.slice_schema = ProgramSliceSchema()
        self.inference_schema = InferenceResultSchema()
        self.validation_schema = ValidationResultSchema()
        self.report_schema = ReportSchema()
        self.default_schema_policy = _normalize_schema_policy(os.getenv("VULDET_SCHEMA_POLICY", "fail_close"))

    def _resolve_schema_policy(self, scan_request: ScanRequest) -> str:
        req_policy = getattr(scan_request, "schema_failure_policy", None)
        if req_policy:
            return _normalize_schema_policy(req_policy)
        return self.default_schema_policy

    @staticmethod
    def _apply_contract_policy(
        payload: Dict,
        warnings: List[str],
        errors: List[str],
        policy: str,
        contract_name: str,
        contract_model,
    ) -> Tuple[bool, Dict]:
        if not errors:
            return True, payload

        warnings.extend([f"{contract_name}: {err}" for err in errors])
        if policy == "fail_open":
            warnings.append(f"{contract_name}: fail_open normalization applied.")
            return True, contract_model.from_dict(payload).to_dict()
        return False, payload

    def _prepare_alerts(
        self,
        scan_request: ScanRequest,
        candidate: CandidateStageResult,
    ) -> Tuple[List[Dict], int, int, List[str]]:
        prepared: List[Dict] = []
        skipped_alerts = 0
        unresolved_path_skips = 0
        schema_warnings: List[str] = []
        schema_policy = self._resolve_schema_policy(scan_request)
        project_files = candidate.project_info.get("files", []) or []

        for alert in candidate.ranked_alerts:
            if len(prepared) >= scan_request.max_alerts:
                print(f"Reached max_alerts={scan_request.max_alerts}; remaining alerts skipped.")
                break

            msg = str(alert.get("msg", ""))
            if should_skip_alert(alert, self.inference_agent):
                skipped_alerts += 1
                continue

            alert_ok, alert_errors = self.alert_schema.validate(alert)
            ok_after_policy, normalized_alert = self._apply_contract_policy(
                payload=alert,
                warnings=schema_warnings,
                errors=alert_errors,
                policy=schema_policy,
                contract_name="AlertContract",
                contract_model=AlertContract,
            )
            if not ok_after_policy:
                skipped_alerts += 1
                continue
            alert = normalized_alert

            if is_unresolved_path(alert.get("file", "")):
                unresolved_path_skips += 1
                skipped_alerts += 1
                continue

            alert_line = int(alert.get("line", 0) or 0)
            if alert_line <= 0:
                skipped_alerts += 1
                continue

            log_event(
                LOGGER,
                "deep_prepare_alert",
                stage="deep_analyzer",
                alert_id=alert.get("alert_id", ""),
                file=alert.get("file", ""),
                line=alert.get("line", 0),
                status="preparing",
            )
            program_slice = alert.get("program_slice", {}) or {}
            sliced_code = program_slice.get("sliced_code", "")

            if not sliced_code:
                self.preprocess_agent.build_program_slice_for_alert(
                    alert=alert,
                    project_path=scan_request.target_path,
                    project_files=project_files,
                )
                program_slice = alert.get("program_slice", {}) or {}
                sliced_code = program_slice.get("sliced_code", "")

            if not sliced_code:
                feature_result = self.coordinator.run_agent("FeatureAgent", {"alert": alert})
                sliced_code = feature_result.get("sliced_code", "")
                program_slice["sliced_code"] = sliced_code
                program_slice.setdefault("source_lines", [])
                program_slice.setdefault("sink_lines", [int(alert.get("line", 0) or 0)])
                program_slice.setdefault("slice_lines", [int(alert.get("line", 0) or 0)])
                program_slice.setdefault("control_flow", {})
                program_slice.setdefault("slice_quality", "low")
                alert["program_slice"] = program_slice

            slice_ok, slice_errors = self.slice_schema.validate(program_slice)
            ok_after_slice_policy, normalized_slice = self._apply_contract_policy(
                payload=program_slice,
                warnings=schema_warnings,
                errors=slice_errors,
                policy=schema_policy,
                contract_name="ProgramSliceContract",
                contract_model=ProgramSliceContract,
            )
            if ok_after_slice_policy:
                alert["program_slice"] = normalized_slice

            prepared.append(alert)

        return prepared, skipped_alerts, unresolved_path_skips, schema_warnings

    def _analyze_prepared_alert(self, alert: Dict, schema_policy: str = "fail_close") -> Dict[str, object]:
        sliced_code = (alert.get("program_slice", {}) or {}).get("sliced_code", "")
        local_schema_warnings: List[str] = []

        inference_result = self.coordinator.run_agent(
            "InferenceAgent",
            {"alert": alert, "sliced_code": sliced_code},
            retries=1,
            retry_backoff_sec=0.2,
        )
        infer_ok, infer_errors = self.inference_schema.validate(inference_result)
        infer_ok, inference_result = self._apply_contract_policy(
            payload=inference_result,
            warnings=local_schema_warnings,
            errors=infer_errors,
            policy=schema_policy,
            contract_name="InferenceResultContract",
            contract_model=InferenceResultContract,
        )
        if not infer_ok:
            return {
                "report": None,
                "degraded": True,
                "schema_warnings": local_schema_warnings,
            }

        validation_result = self.coordinator.run_agent(
            "ValidationAgent",
            {"alert": alert, "analysis": inference_result, "sliced_code": sliced_code},
            retries=0,
        )
        valid_ok, valid_errors = self.validation_schema.validate(validation_result)
        valid_ok, validation_result = self._apply_contract_policy(
            payload=validation_result,
            warnings=local_schema_warnings,
            errors=valid_errors,
            policy=schema_policy,
            contract_name="ValidationResultContract",
            contract_model=ValidationResultContract,
        )
        if not valid_ok:
            return {
                "report": None,
                "degraded": True,
                "schema_warnings": local_schema_warnings,
            }

        base_conf = float(inference_result.get("confidence", 0.0) or 0.0)
        conf_adjust = float(validation_result.get("confidence_adjustment", 0.0) or 0.0)
        inference_result["confidence"] = clamp_confidence(base_conf + conf_adjust)

        if validation_result.get("requires_manual_review"):
            inference_result["needs_review"] = True

        degraded = str(inference_result.get("decision_status", "")).lower() == "degraded"

        report_result = self.coordinator.run_agent(
            "ReportAgent",
            {"alert": alert, "analysis": inference_result, "validation": validation_result},
        )
        report_payload = report_result.get("report")
        report_ok, report_errors = self.report_schema.validate(report_payload or {})
        report_ok, report_payload = self._apply_contract_policy(
            payload=report_payload or {},
            warnings=local_schema_warnings,
            errors=report_errors,
            policy=schema_policy,
            contract_name="ReportContract",
            contract_model=ReportContract,
        )
        if not report_ok:
            report_payload = None

        return {
            "report": report_payload,
            "degraded": degraded,
            "schema_warnings": local_schema_warnings,
        }

    def run(self, scan_request: ScanRequest, candidate: CandidateStageResult) -> DeepAnalysisResult:
        stage_start = time.perf_counter()
        before_metrics = self.coordinator.snapshot_metrics()
        schema_policy = self._resolve_schema_policy(scan_request)
        log_event(
            LOGGER,
            "deep_stage_start",
            stage="deep_analyzer",
            target_path=scan_request.target_path,
            schema_policy=schema_policy,
        )
        prepare_start = time.perf_counter()
        prepared_alerts, skipped_alerts, unresolved_path_skips, schema_warnings = self._prepare_alerts(
            scan_request=scan_request,
            candidate=candidate,
        )
        prepare_elapsed_ms = round((time.perf_counter() - prepare_start) * 1000.0, 2)

        final_reports: List[Dict] = []
        processed_alerts = 0
        degraded_alerts = 0
        analysis_start = time.perf_counter()
        workers = max(1, int(scan_request.analysis_workers or 1))

        if workers <= 1 or len(prepared_alerts) <= 1:
            for alert in prepared_alerts:
                item = self._analyze_prepared_alert(alert, schema_policy=schema_policy)
                if item.get("report"):
                    final_reports.append(item["report"])
                schema_warnings.extend(item.get("schema_warnings", []))
                if item.get("degraded"):
                    degraded_alerts += 1
                processed_alerts += 1
        else:
            futures_map = {}
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for idx, alert in enumerate(prepared_alerts):
                    future = executor.submit(self._analyze_prepared_alert, alert, schema_policy)
                    futures_map[future] = idx

                ordered_results: List[Tuple[int, Dict[str, object]]] = []
                for future in as_completed(futures_map):
                    idx = futures_map[future]
                    try:
                        ordered_results.append((idx, future.result()))
                    except Exception as exc:  # pragma: no cover - defensive path
                        ordered_results.append(
                            (
                                idx,
                                {
                                    "report": None,
                                    "degraded": True,
                                    "schema_warnings": [f"DeepAnalyzer worker exception: {exc}"],
                                },
                            )
                        )

                for _, item in sorted(ordered_results, key=lambda pair: pair[0]):
                    if item.get("report"):
                        final_reports.append(item["report"])
                    schema_warnings.extend(item.get("schema_warnings", []))
                    if item.get("degraded"):
                        degraded_alerts += 1
                    processed_alerts += 1

        analysis_elapsed_ms = round((time.perf_counter() - analysis_start) * 1000.0, 2)
        stage_elapsed_ms = round((time.perf_counter() - stage_start) * 1000.0, 2)
        after_metrics = self.coordinator.snapshot_metrics()
        agent_metrics = AgentCoordinator.diff_metrics(before_metrics, after_metrics)
        metrics = {
            "stage": "deep_analyzer",
            "elapsed_ms": stage_elapsed_ms,
            "prepare_elapsed_ms": prepare_elapsed_ms,
            "analysis_elapsed_ms": analysis_elapsed_ms,
            "workers": workers,
            "prepared_alerts": len(prepared_alerts),
            "processed_alerts": processed_alerts,
            "skipped_alerts": skipped_alerts,
            "degraded_alerts": degraded_alerts,
            "schema_policy": schema_policy,
            **agent_metrics,
        }
        log_event(
            LOGGER,
            "deep_stage_complete",
            stage="deep_analyzer",
            elapsed_ms=stage_elapsed_ms,
            processed_alerts=processed_alerts,
            degraded_alerts=degraded_alerts,
            status="ok",
        )

        return DeepAnalysisResult(
            reports=final_reports,
            processed_alerts=processed_alerts,
            skipped_alerts=skipped_alerts,
            unresolved_path_skips=unresolved_path_skips,
            degraded_alerts=degraded_alerts,
            schema_warnings=schema_warnings,
            metrics=metrics,
        )
