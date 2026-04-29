"""
Enhanced Meta Agent integrating the new slice construction and hypothesis validation mechanisms
集成假设提取和 LLM 驱动的触发路径构造
"""

import os
import re
import json
import threading
import time
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from agent import (
    StaticAnalyzerAgent,
    EvidenceScorer,
    ReportAgent,
    SpecializedLLMAgent,
    DeepSeekClient,
    HypothesisValidatorAgent,
)
from enhanced_slice_constructor import EnhancedSliceConstructor
from hypothesis_extractor import HypothesisExtractor
from llm_trigger_path_constructor import LLMDrivenTriggerPathConstructor


class EnhancedMetaAgent:
    """Enhanced Meta Agent with new slice construction and hypothesis validation"""
    
    def __init__(self, use_cache=True, enable_hypothesis_extraction=True, enable_llm_trigger_path=True):
        self.static_agent = StaticAnalyzerAgent()
        self.enhanced_slice_agent = EnhancedSliceConstructor()
        # 使用 agent.HypothesisValidatorAgent：原 EnhancedHypothesisValidator 未实现解析/提示等方法，会导致验证阶段异常或永远无结果
        self.validator_agent = HypothesisValidatorAgent()
        self.report_agent = ReportAgent()
        self.evidence_scorer = EvidenceScorer()
        self.name = "EnhancedMetaAgent"
        self.use_cache = use_cache
        
        # 增强功能开关
        self.enable_hypothesis_extraction = enable_hypothesis_extraction
        self.enable_llm_trigger_path = enable_llm_trigger_path
        
        # 初始化 LLM 客户端
        self.llm_client = DeepSeekClient()
        
        # 初始化增强组件
        if enable_hypothesis_extraction:
            self.hypothesis_extractor = HypothesisExtractor()
        if enable_llm_trigger_path:
            self.trigger_path_constructor = LLMDrivenTriggerPathConstructor()
        
        # 增强分析信息收集
        self.enhanced_analysis_info = {
            "hypotheses_extracted": 0,
            "trigger_paths_generated": 0,
            "two_phase_validation_passed": 0,
            "enhanced_features_enabled": {
                "hypothesis_extraction": enable_hypothesis_extraction,
                "llm_trigger_path": enable_llm_trigger_path
            }
        }
        
        # Specialized LLM agents pool
        self.specialized_agents = {}
        self._init_specialized_agents()
        
        # Global analysis cache
        self.analysis_cache = {}
        self._analysis_cache_lock = threading.Lock()
        # 由子类（如 Java）置 True，用于阈值/上下文长度；默认不影响 C 行为
        self._java_mode = False
    
    def _init_specialized_agents(self):
        """Initialize specialized LLM agents"""
        report_agent = ReportAgent()
        cwe_descriptions = report_agent.cwe_descriptions
        
        # Create specialized agents for important CWE types
        important_cwes = [
            "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-126",
            "CWE-134", "CWE-78", "CWE-77", "CWE-22", "CWE-190", "CWE-401",
            "CWE-416", "CWE-476", "CWE-704", "CWE-129", "CWE-369", "CWE-456",
            "CWE-125", "CWE-20", "CWE-189", "CWE-399", "CWE-835", "CWE-264", "CWE-209"
        ]
        
        for cwe in important_cwes:
            description = cwe_descriptions.get(cwe, f"{cwe}类型漏洞")
            self.specialized_agents[cwe] = SpecializedLLMAgent(cwe, description)
        
        print(f"EnhancedMetaAgent: Initialized {len(self.specialized_agents)} specialized agents")
        if self.enable_hypothesis_extraction:
            print(f"EnhancedMetaAgent: Hypothesis extraction enabled")
        if self.enable_llm_trigger_path:
            print(f"EnhancedMetaAgent: LLM-driven trigger path construction enabled")
    
    def _get_specialized_agent(self, cwe_type: str):
        """Get specialized agent for CWE type"""
        if cwe_type in self.specialized_agents:
            return self.specialized_agents[cwe_type]
        
        # Create generic agent if not found
        report_agent = ReportAgent()
        description = report_agent.cwe_descriptions.get(cwe_type, f"{cwe_type}类型漏洞")
        agent = SpecializedLLMAgent(cwe_type, description)
        self.specialized_agents[cwe_type] = agent
        return agent
    
    def _process_with_specialized_agents(self, slices_by_cwe: Dict[str, str], 
                                       full_code_context: str, static_result: Dict,
                                       slice_result: Dict) -> List[Dict]:
        """Process slices with specialized agents"""
        print(f"  [EnhancedMetaAgent] Using specialized agents for {len(slices_by_cwe)} CWE types")
        
        all_results = []
        llm_errors = []
        
        # Parallel processing
        with ThreadPoolExecutor(max_workers=min(8, len(slices_by_cwe))) as executor:
            future_to_cwe = {}
            
            for cwe_type, code_slice in slices_by_cwe.items():
                if len(code_slice) < 50:
                    continue
                
                agent = self._get_specialized_agent(cwe_type)
                future = executor.submit(
                    agent.process,
                    code_slice,
                    full_code_context,
                    static_result,
                    slice_result
                )
                future_to_cwe[future] = cwe_type
            
            # Collect results
            for future in as_completed(future_to_cwe):
                cwe_type = future_to_cwe[future]
                try:
                    results = future.result()
                    if results:
                        # Separate error markers for UI
                        for item in results:
                            if isinstance(item, dict) and item.get("_llm_error"):
                                llm_errors.append(item.get("_llm_error"))
                            else:
                                all_results.append(item)
                        if any(isinstance(i, dict) and i.get("has_vulnerability") for i in results):
                            found_n = sum(1 for i in results if isinstance(i, dict) and i.get("has_vulnerability"))
                            print(f"    [{cwe_type}] Found {found_n} vulnerabilities")
                except Exception as e:
                    print(f"    [{cwe_type}] Analysis failed: {e}")

        if llm_errors:
            # Keep for reporting/UI diagnostics
            slice_result["_llm_errors"] = llm_errors
        
        return all_results
    
    @staticmethod
    def _coerce_line_no(val: Any) -> int:
        """LLM/假设中的 line 可能为 str（如 '18' 或描述文本），统一为 int 供行号比较。"""
        if val is None:
            return 0
        if isinstance(val, int):
            return val
        if isinstance(val, float):
            return int(val)
        if isinstance(val, str):
            m = re.search(r"\d+", val)
            return int(m.group(0)) if m else 0
        return 0

    @staticmethod
    def _coerce_confidence(val: Any) -> int:
        if val is None:
            return 0
        if isinstance(val, (int, float)):
            return int(val)
        if isinstance(val, str):
            m = re.search(r"\d+", val)
            return int(m.group(0)) if m else 0
        return 0

    def _extract_line_number_from_location(self, location: str) -> int:
        """从位置字符串中提取行号"""
        if not location:
            return 0
        
        patterns = [r'line\s*(\d+)', r'(\d+):', r'at\s+line\s*(\d+)']
        for pattern in patterns:
            match = re.search(pattern, location, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    continue
        return 0
    
    def _enrich_reports_with_hypotheses(self, reports: List[Dict], hypotheses: List[Dict]) -> List[Dict]:
        """用提取的假设丰富漏洞报告"""
        if not hypotheses:
            return reports
        
        enriched_reports = []
        for report in reports:
            report_cwe = report.get("cwe", "")
            report_location = report.get("location", "")
            report_line = self._extract_line_number_from_location(report_location)
            
            # 查找匹配的假设
            matching_hypotheses = []
            for hyp in hypotheses:
                hyp_cwe = hyp.get("cwe", "")
                hyp_line = self._coerce_line_no(hyp.get("line", 0))
                
                # 如果 CWE 匹配且行号相近，则认为匹配
                if hyp_cwe == report_cwe and abs(hyp_line - report_line) < 10:
                    matching_hypotheses.append(hyp)
            
            if matching_hypotheses:
                report["_matched_hypotheses"] = matching_hypotheses
                report["_evidence_score"] = max(
                    self._coerce_confidence(report.get("_evidence_score", 0)),
                    max(self._coerce_confidence(h.get("confidence", 0)) for h in matching_hypotheses)
                )
            
            enriched_reports.append(report)
        
        return enriched_reports
    
    def _enrich_reports_with_trigger_paths(self, reports: List[Dict], trigger_paths: List[Dict]) -> List[Dict]:
        """用触发路径丰富漏洞报告"""
        if not trigger_paths:
            return reports
        
        enriched_reports = []
        for report in reports:
            report_cwe = report.get("cwe", "")
            report_location = report.get("location", "")
            report_line = self._extract_line_number_from_location(report_location)
            
            # 查找匹配的触发路径
            matching_paths = []
            for path in trigger_paths:
                path_cwe = path.get("cwe_type", "")
                path_sink = path.get("sink", "")
                
                # 如果 CWE 匹配或 sink 匹配
                if path_cwe == report_cwe or (path_sink and path_sink.lower() in report_location.lower()):
                    matching_paths.append(path)
            
            if matching_paths:
                report["_trigger_paths"] = matching_paths
                # 如果路径可行，提高置信度
                feasible_paths = [p for p in matching_paths if p.get("is_feasible", False)]
                if feasible_paths:
                    report["confidence"] = max(
                        report.get("confidence", 50),
                        max(p.get("confidence", 0) for p in feasible_paths)
                    )
            
            enriched_reports.append(report)
        
        return enriched_reports

    def _build_schema_summary(self, warnings: List[str], stage_validity: Dict[str, bool]) -> Dict[str, Any]:
        return {
            "ok": not warnings,
            "warning_count": len(warnings),
            "warnings": warnings,
            "stage_validity": stage_validity,
        }

    def _validate_stage_static(self, payload: Any, warnings: List[str]) -> bool:
        if not isinstance(payload, dict):
            warnings.append("stage static: must be object")
            return False
        return True

    def _validate_stage_slice(self, payload: Any, warnings: List[str]) -> bool:
        if not isinstance(payload, dict):
            warnings.append("stage slice: must be object")
            return False
        if "suspicious_count" not in payload:
            warnings.append("stage slice: missing suspicious_count")
        return True

    def _validate_stage_llm(self, payload: Any, warnings: List[str]) -> bool:
        if not isinstance(payload, list):
            warnings.append("stage llm: must be list")
            return False
        return True

    def _validate_stage_validation(self, payload: Any, warnings: List[str]) -> bool:
        if not isinstance(payload, list):
            warnings.append("stage validation: must be list")
            return False
        return True

    def _validate_stage_report(self, payload: Any, warnings: List[str]) -> bool:
        if not isinstance(payload, dict):
            warnings.append("stage report: must be object")
            return False
        required = ("total_vulnerabilities", "vulnerabilities", "severity_summary")
        for key in required:
            if key not in payload:
                warnings.append(f"stage report: missing {key}")
        return True

    def _validate_stage_enhanced_analysis(self, payload: Any, warnings: List[str]) -> bool:
        if not isinstance(payload, dict):
            warnings.append("stage enhanced_analysis: must be object")
            return False
        required = ("hypotheses_extracted", "trigger_paths_generated", "two_phase_validation_passed")
        for key in required:
            if key not in payload:
                warnings.append(f"stage enhanced_analysis: missing {key}")
        return True

    def _finalize_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        warnings: List[str] = []
        stage_validity = {
            "static": self._validate_stage_static(result.get("static"), warnings),
            "slice": self._validate_stage_slice(result.get("slice"), warnings),
            "llm": self._validate_stage_llm(result.get("llm"), warnings),
            "validation": self._validate_stage_validation(result.get("validation"), warnings),
            "report": self._validate_stage_report(result.get("report"), warnings),
            "enhanced_analysis": self._validate_stage_enhanced_analysis(result.get("enhanced_analysis"), warnings),
        }
        validator_warnings = getattr(self.validator_agent, "schema_warnings", []) or []
        if validator_warnings:
            warnings.extend([f"validator: {x}" for x in validator_warnings])
        report_schema_warnings = []
        if isinstance(result.get("report"), dict):
            report_schema_warnings = result["report"].get("schema_warnings", []) or []
        if report_schema_warnings:
            warnings.extend([f"report: {x}" for x in report_schema_warnings])
        result["schema_validation"] = self._build_schema_summary(warnings, stage_validity)
        return result

    def _new_observability(self) -> Dict[str, Any]:
        return {
            "cached": False,
            "stage_metrics": {
                "static_analysis_ms": 0.0,
                "slice_construction_ms": 0.0,
                "hypothesis_extraction_ms": 0.0,
                "trigger_path_ms": 0.0,
                "evidence_scoring_ms": 0.0,
                "llm_inference_ms": 0.0,
                "validation_ms": 0.0,
                "report_generation_ms": 0.0,
                "total_analysis_ms": 0.0,
            },
            "counts": {
                "candidate_cwes": 0,
                "llm_input_slices": 0,
                "llm_results_before_filter": 0,
                "llm_results_after_filter": 0,
                "validated_results": 0,
                "report_vulnerability_count": 0,
                "llm_error_count": 0,
                "schema_warning_count": 0,
            },
        }

    def _attach_observability(self, result: Dict[str, Any], observability: Dict[str, Any]) -> Dict[str, Any]:
        schema_warning_count = int(
            ((result.get("schema_validation") or {}).get("warning_count", 0) or 0)
        )
        observability["counts"]["schema_warning_count"] = schema_warning_count
        result["observability"] = observability
        return result
    
    def analyze(
        self,
        code_file: str,
        code_content: str,
        file_info: Dict,
        static_result_override: Optional[Dict[str, Any]] = None,
        context_char_limit: Optional[int] = None,
        progress_cb=None,
    ) -> Dict:
        """Enhanced analysis pipeline with new mechanisms

        static_result_override: 若提供则跳过 StaticAnalyzer（用于 Java 工作区共享 CPG）。
        context_char_limit: 传入 LLM 的代码前缀长度；None 时 C 默认 500，Java 子类可通过 _java_mode 使用 2000。
        """

        analyze_start = time.perf_counter()
        observability = self._new_observability()

        # 重置增强分析信息
        self.enhanced_analysis_info = {
            "hypotheses_extracted": 0,
            "trigger_paths_generated": 0,
            "two_phase_validation_passed": 0,
            "enhanced_features_enabled": {
                "hypothesis_extraction": self.enable_hypothesis_extraction,
                "llm_trigger_path": self.enable_llm_trigger_path
            }
        }
        
        # Generate cache key
        file_mtime = os.path.getmtime(code_file) if os.path.exists(code_file) else 0
        cache_key = f"{code_file}_{file_mtime}"
        
        # Check cache
        if self.use_cache:
            with self._analysis_cache_lock:
                if cache_key in self.analysis_cache:
                    print(f"\nUsing cached result: {file_info.get('file_name')}")
                    cached_result = self.analysis_cache[cache_key]
                    if isinstance(cached_result, dict):
                        cached_obs = dict(cached_result.get("observability", {}) or {})
                        cached_obs.setdefault("stage_metrics", {})
                        cached_obs.setdefault("counts", {})
                        cached_obs["cached"] = True
                        cached_result["observability"] = cached_obs
                    return cached_result
        
        def _progress(step_idx: int, stage_name: str) -> None:
            try:
                if callable(progress_cb):
                    progress_cb(step_idx, stage_name)
            except Exception:
                pass

        print(f"\nEnhanced analysis: {file_info.get('file_name')}")
        _progress(0, "文件预处理")
        
        def _build_sink_window_context(code_text: str, slice_result: Dict[str, Any]) -> str:
            """
            Build LLM global context by extracting windows around sinks (and some source lines)
            instead of truncating the file head. This is critical for very large single-file inputs.
            """
            try:
                lines = code_text.split("\n")
                win = int(os.environ.get("VULN_SINK_WINDOW_LINES", "40"))
                max_total = int(os.environ.get("VULN_MAX_SINK_WINDOWS", "60"))
                per_cwe = int(os.environ.get("VULN_MAX_SINK_WINDOWS_PER_CWE", "20"))
                max_chars = int(os.environ.get("VULN_SINK_CONTEXT_MAX_CHARS", "16000"))
                large_lines = int(os.environ.get("VULN_LARGE_FILE_LINES", "2000"))
                bigfile_mode = str(os.environ.get("VULN_BIGFILE_MODE", "0")).strip().lower() in {"1", "true", "yes", "on"}
                if bigfile_mode:
                    # Expand budgets (still bounded) for production large-file mode.
                    max_total = min(300, max_total * 3)
                    per_cwe = min(120, per_cwe * 3)
                    max_chars = min(80000, max_chars * 3)
                if len(lines) < large_lines:
                    # For small files, the original prefix context is fine.
                    return code_text[:2000]
                
                sinks_by_cwe = (slice_result or {}).get("sinks_by_cwe") or {}
                suspicious = (slice_result or {}).get("suspicious_lines") or {}
                # Collect candidate line numbers, prioritizing sink lines.
                cand: Dict[str, List[int]] = {}
                if isinstance(sinks_by_cwe, dict) and sinks_by_cwe:
                    for cwe, sinks in sinks_by_cwe.items():
                        if not isinstance(sinks, list):
                            continue
                        for s in sinks:
                            try:
                                ln = int(s.get("line", 0))
                            except Exception:
                                ln = 0
                            if ln > 0:
                                cand.setdefault(str(cwe), []).append(ln)
                if isinstance(suspicious, dict) and suspicious:
                    for cwe, arr in suspicious.items():
                        if not isinstance(arr, list):
                            continue
                        for item in arr:
                            if isinstance(item, (list, tuple)) and item:
                                try:
                                    ln = int(item[0])
                                except Exception:
                                    ln = 0
                            elif isinstance(item, dict):
                                try:
                                    ln = int(item.get("line", 0))
                                except Exception:
                                    ln = 0
                            else:
                                ln = 0
                            if ln > 0:
                                cand.setdefault(str(cwe), []).append(ln)
                
                # Normalize and cap.
                for cwe in list(cand.keys()):
                    uniq = []
                    for ln in sorted(set(cand[cwe])):
                        if 1 <= ln <= len(lines):
                            uniq.append(ln)
                        if len(uniq) >= per_cwe:
                            break
                    cand[cwe] = uniq
                
                ranges = []
                taken = 0
                for cwe in sorted(cand.keys()):
                    for ln in cand[cwe]:
                        start = max(1, ln - win)
                        end = min(len(lines), ln + win)
                        ranges.append((start, end, cwe, ln))
                        taken += 1
                        if taken >= max_total:
                            break
                    if taken >= max_total:
                        break
                
                # Merge overlapping ranges (ignore CWE label when merging, keep earliest label).
                ranges.sort(key=lambda x: (x[0], x[1]))
                merged = []
                for r in ranges:
                    if not merged or r[0] > merged[-1][1] + 1:
                        merged.append(list(r))  # [start,end,cwe,anchor]
                    else:
                        merged[-1][1] = max(merged[-1][1], r[1])
                
                out = []
                out.append("=== Context windows around sinks (auto-generated) ===")
                for start, end, cwe, anchor in merged:
                    out.append(f"\n--- window {start}-{end} (anchor {anchor}, {cwe}) ---")
                    for i in range(start, end + 1):
                        out.append(f"{i}: {lines[i-1]}")
                    if sum(len(s) + 1 for s in out) > max_chars:
                        out.append("\n[truncated: context budget exceeded]")
                        break
                text = "\n".join(out)
                return text[:max_chars]
            except Exception:
                return code_text[:2000]
        
        # 1. Static analysis
        _progress(1, "静态分析")
        t0 = time.perf_counter()
        if static_result_override is not None:
            print("  [StaticAnalyzer] 使用预计算静态结果（工作区共享 CPG）")
            static_result = static_result_override
        else:
            static_result = self.static_agent.process(code_file)
        observability["stage_metrics"]["static_analysis_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
        
        # 2. Enhanced slice construction
        _progress(2, "切片构造")
        t0 = time.perf_counter()
        slice_result = self.enhanced_slice_agent.process(code_content, static_result)
        observability["stage_metrics"]["slice_construction_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
        
        # ========== 新增：假设提取阶段 ==========
        hypotheses = []
        if self.enable_hypothesis_extraction and hasattr(self, 'hypothesis_extractor'):
            print(f"  [EnhancedMetaAgent] 执行假设提取...")
            t0 = time.perf_counter()
            try:
                hypotheses = self.hypothesis_extractor.extract_hypotheses(code_content, static_result)
                stats = getattr(self.hypothesis_extractor, "last_stats", {}) or {}
                self.enhanced_analysis_info["hypotheses_extracted"] = int(stats.get("returned", len(hypotheses)))
                if stats:
                    self.enhanced_analysis_info["hypotheses_raw"] = int(stats.get("raw", len(hypotheses)))
                    self.enhanced_analysis_info["hypotheses_truncated"] = bool(stats.get("truncated", False))
                
                if hypotheses:
                    slice_result["extracted_hypotheses"] = hypotheses
                    print(f"  [EnhancedMetaAgent] 提取到 {len(hypotheses)} 个假设")
            except Exception as e:
                print(f"  [EnhancedMetaAgent] 假设提取失败: {e}")
            observability["stage_metrics"]["hypothesis_extraction_ms"] = round(
                (time.perf_counter() - t0) * 1000.0, 2
            )
        
        # ========== 新增：LLM 驱动的触发路径构造 ==========
        trigger_paths = []
        if self.enable_llm_trigger_path and hasattr(self, 'trigger_path_constructor'):
            print(f"  [EnhancedMetaAgent] 构造触发路径...")
            t0 = time.perf_counter()
            try:
                trigger_paths = self.trigger_path_constructor.construct(code_content, static_result)
                self.enhanced_analysis_info["trigger_paths_generated"] = len(trigger_paths)
                
                if trigger_paths:
                    slice_result["llm_trigger_paths"] = trigger_paths
                    print(f"  [EnhancedMetaAgent] 生成 {len(trigger_paths)} 个触发路径")
            except Exception as e:
                print(f"  [EnhancedMetaAgent] 触发路径构造失败: {e}")
            observability["stage_metrics"]["trigger_path_ms"] = round(
                (time.perf_counter() - t0) * 1000.0, 2
            )
        
        if slice_result["suspicious_count"] == 0:
            _progress(4, "验证与报告")
            result = self._empty_result(static_result, slice_result, file_info)
            result["enhanced_analysis"] = self.enhanced_analysis_info
            result = self._finalize_result(result)
            observability["stage_metrics"]["total_analysis_ms"] = round((time.perf_counter() - analyze_start) * 1000.0, 2)
            result = self._attach_observability(result, observability)
            if self.use_cache:
                with self._analysis_cache_lock:
                    self.analysis_cache[cache_key] = result
            return result
        
        # 3. Evidence scoring
        t0 = time.perf_counter()
        candidate_cwes = set(slice_result.get("slices_by_cwe", {}).keys())
        evidence_scores = {}
        
        for cwe in candidate_cwes:
            score_item = self.evidence_scorer.score(cwe, static_result, slice_result, code_content)
            evidence_scores[cwe] = score_item
        observability["counts"]["candidate_cwes"] = len(candidate_cwes)
        observability["stage_metrics"]["evidence_scoring_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
        
        # Filter CWE types for LLM analysis
        llm_input_slices = {}
        for cwe, c_slice in slice_result.get("slices_by_cwe", {}).items():
            s = evidence_scores.get(cwe, {"score": 0})
            if self.evidence_scorer.should_enter_llm(s):
                llm_input_slices[cwe] = c_slice
        observability["counts"]["llm_input_slices"] = len(llm_input_slices)
        
        if not llm_input_slices:
            _progress(4, "验证与报告")
            result = self._empty_result(static_result, slice_result, file_info)
            result["enhanced_analysis"] = self.enhanced_analysis_info
            result = self._finalize_result(result)
            observability["stage_metrics"]["total_analysis_ms"] = round((time.perf_counter() - analyze_start) * 1000.0, 2)
            result = self._attach_observability(result, observability)
            if self.use_cache:
                with self._analysis_cache_lock:
                    self.analysis_cache[cache_key] = result
            return result
        
        if context_char_limit is None:
            # C large files benefit from sink-window context rather than tiny prefix truncation.
            context_char_limit = 2000 if getattr(self, "_java_mode", False) else 500

        # 4. Specialized LLM analysis
        _progress(3, "LLM 推理")
        t0 = time.perf_counter()
        # Replace global prefix context with sink-window context for large files (C/Java).
        effective_context = _build_sink_window_context(code_content, slice_result)
        llm_results = self._process_with_specialized_agents(
            llm_input_slices,
            full_code_context=effective_context,
            static_result=static_result,
            slice_result=slice_result,
        )
        observability["counts"]["llm_results_before_filter"] = len(llm_results)
        
        # Filter low evidence results
        filtered_llm = []
        for r in llm_results:
            cwe = r.get("cwe", "")
            s = evidence_scores.get(cwe, {"score": 0, "evidence_chain": {}})
            
            # 按 CWE 精细化阈值：提升真阳性召回，同时抑制高噪声语义类误报
            cwe_threshold_overrides = {
                # 漏报优先（历史 FN）：指针/空指针/断言/类型相关
                "CWE-476": 15,
                "CWE-252": 15,
                "CWE-690": 15,
                "CWE-617": 12,
                "CWE-704": 12,
                "CWE-287": 12,
                "CWE-401": 15,
                "CWE-190": 18,
                # 高噪声语义类：提高门槛，减少 Chrome 安全样本误报
                "CWE-189": 30,
                "CWE-835": 30,
                "CWE-125": 28,
                "CWE-129": 28,
                "CWE-399": 26,
                "CWE-209": 26,
            }
            if getattr(self, "_java_mode", False):
                cwe_threshold_overrides.update(
                    {
                        "CWE-89": 12,
                        "CWE-88": 12,
                        "CWE-502": 14,
                        "CWE-611": 14,
                        "CWE-78": 14,
                        "CWE-22": 16,
                        # Java web/security common types (keep moderate thresholds to avoid FP explosion)
                        "CWE-79": 16,
                        "CWE-918": 16,
                        # Recall-first additions (heuristic, Java-only)
                        "CWE-287": 16,
                        "CWE-190": 16,
                        # NPE is extremely noisy; require stronger evidence to pass
                        "CWE-476": 22,
                        # Hard-coded credentials / race conditions (Java-only)
                        "CWE-259": 16,
                        "CWE-798": 16,
                        "CWE-362": 18,
                    }
                )
            # 不再使用全局 semantic_pass 放宽，统一使用 CWE 定制阈值
            semantic_pass = False
            regular_threshold = cwe_threshold_overrides.get(cwe, 30)
            regular_pass = s.get("score", 0) >= regular_threshold
            
            if regular_pass or semantic_pass:
                r["_evidence_score"] = s.get("score", 0)
                r["_evidence_chain"] = s.get("evidence_chain", {})
                r["_evidence_reasons"] = s.get("reasons", [])
                filtered_llm.append(r)
        
        llm_results = filtered_llm
        observability["counts"]["llm_results_after_filter"] = len(llm_results)
        observability["stage_metrics"]["llm_inference_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
        
        if not llm_results:
            _progress(4, "验证与报告")
            result = self._empty_result(static_result, slice_result, file_info)
            result["enhanced_analysis"] = self.enhanced_analysis_info
            result = self._finalize_result(result)
            observability["stage_metrics"]["total_analysis_ms"] = round((time.perf_counter() - analyze_start) * 1000.0, 2)
            result = self._attach_observability(result, observability)
            if self.use_cache:
                with self._analysis_cache_lock:
                    self.analysis_cache[cache_key] = result
            return result
        
        # 4.5 用假设和触发路径丰富漏洞报告
        if hypotheses:
            llm_results = self._enrich_reports_with_hypotheses(llm_results, hypotheses)
        if trigger_paths:
            llm_results = self._enrich_reports_with_trigger_paths(llm_results, trigger_paths)
        
        # 5. 假设验证：合并静态结果与切片结果，供证据与 LLM 验证使用
        _progress(4, "验证与报告")
        t0 = time.perf_counter()
        validator_ctx = {**static_result, **slice_result}
        validated_results = self.validator_agent.process(
            llm_results, code_content, validator_ctx
        )
        observability["stage_metrics"]["validation_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
        observability["counts"]["validated_results"] = len(validated_results)
        
        # 更新验证通过数量
        self.enhanced_analysis_info["two_phase_validation_passed"] = len(validated_results)
        
        # 6. Generate report
        t0 = time.perf_counter()
        report = self.report_agent.process(validated_results, file_info, static_result)
        observability["stage_metrics"]["report_generation_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
        # Surface LLM errors to report for UI alert banner.
        llm_errors = slice_result.get("_llm_errors") if isinstance(slice_result, dict) else None
        if llm_errors:
            report["llm_errors"] = llm_errors
        observability["counts"]["llm_error_count"] = len(llm_errors or [])
        
        result = {
            "static": static_result,
            "slice": slice_result,
            "llm": llm_results,
            "validation": validated_results,
            "report": report,
            "enhanced_analysis": self.enhanced_analysis_info
        }
        result = self._finalize_result(result)
        observability["counts"]["report_vulnerability_count"] = int(
            (report.get("total_vulnerabilities", 0) or 0)
        )
        observability["stage_metrics"]["total_analysis_ms"] = round((time.perf_counter() - analyze_start) * 1000.0, 2)
        result = self._attach_observability(result, observability)
        
        # Cache result
        if self.use_cache:
            with self._analysis_cache_lock:
                self.analysis_cache[cache_key] = result
        
        return result
    
    def _empty_result(self, static_result: Dict, slice_result: Dict, file_info: Dict) -> Dict:
        """Create empty result structure"""
        return {
            "static": static_result,
            "slice": slice_result,
            "llm": [],
            "validation": [],
            "report": self.report_agent._empty_report(file_info, static_result),
            "enhanced_analysis": self.enhanced_analysis_info
        }
    
    def clear_cache(self):
        """Clear all caches"""
        with self._analysis_cache_lock:
            self.analysis_cache.clear()
        self.static_agent.cache.clear()
        self.validator_agent.validation_cache.clear()
        print("EnhancedMetaAgent: All caches cleared")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            "analysis_cache_size": len(self.analysis_cache),
            "static_cache_size": len(self.static_agent.cache),
            "validation_cache_size": len(self.validator_agent.validation_cache)
        }
    
    def get_enhanced_analysis_info(self) -> Dict:
        """获取增强分析信息"""
        return self.enhanced_analysis_info
