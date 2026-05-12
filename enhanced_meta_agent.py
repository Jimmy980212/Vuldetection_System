"""
Enhanced Meta Agent integrating the new slice construction and hypothesis validation mechanisms
集成假设提取和 LLM 驱动的触发路径构造
"""

import os
import re
import json
import threading
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
                    return self.analysis_cache[cache_key]
        
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
        if static_result_override is not None:
            print("  [StaticAnalyzer] 使用预计算静态结果（工作区共享 CPG）")
            static_result = static_result_override
        else:
            static_result = self.static_agent.process(code_file)
        
        # 2. Enhanced slice construction
        _progress(2, "切片构造")
        slice_result = self.enhanced_slice_agent.process(code_content, static_result)
        
        # ========== 新增：假设提取阶段 ==========
        hypotheses = []
        if self.enable_hypothesis_extraction and hasattr(self, 'hypothesis_extractor'):
            print(f"  [EnhancedMetaAgent] 执行假设提取...")
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
        
        # ========== 新增：LLM 驱动的触发路径构造 ==========
        trigger_paths = []
        if self.enable_llm_trigger_path and hasattr(self, 'trigger_path_constructor'):
            print(f"  [EnhancedMetaAgent] 构造触发路径...")
            try:
                trigger_paths = self.trigger_path_constructor.construct(code_content, static_result)
                self.enhanced_analysis_info["trigger_paths_generated"] = len(trigger_paths)
                
                if trigger_paths:
                    slice_result["llm_trigger_paths"] = trigger_paths
                    print(f"  [EnhancedMetaAgent] 生成 {len(trigger_paths)} 个触发路径")
            except Exception as e:
                print(f"  [EnhancedMetaAgent] 触发路径构造失败: {e}")
        
        if slice_result["suspicious_count"] == 0:
            _progress(4, "验证与报告")
            result = self._empty_result(static_result, slice_result, file_info)
            result["enhanced_analysis"] = self.enhanced_analysis_info
            if self.use_cache:
                with self._analysis_cache_lock:
                    self.analysis_cache[cache_key] = result
            return result
        
        # 3. Evidence scoring
        candidate_cwes = set(slice_result.get("slices_by_cwe", {}).keys())
        evidence_scores = {}
        
        for cwe in candidate_cwes:
            score_item = self.evidence_scorer.score(cwe, static_result, slice_result, code_content)
            evidence_scores[cwe] = score_item
        
        # Filter CWE types for LLM analysis
        llm_input_slices = {}
        for cwe, c_slice in slice_result.get("slices_by_cwe", {}).items():
            s = evidence_scores.get(cwe, {"score": 0})
            if self.evidence_scorer.should_enter_llm(s):
                llm_input_slices[cwe] = c_slice
        
        if not llm_input_slices:
            _progress(4, "验证与报告")
            result = self._empty_result(static_result, slice_result, file_info)
            result["enhanced_analysis"] = self.enhanced_analysis_info
            if self.use_cache:
                with self._analysis_cache_lock:
                    self.analysis_cache[cache_key] = result
            return result
        
        if context_char_limit is None:
            # C large files benefit from sink-window context rather than tiny prefix truncation.
            context_char_limit = 2000 if getattr(self, "_java_mode", False) else 500

        # 4. Specialized LLM analysis
        _progress(3, "LLM 推理")
        # Replace global prefix context with sink-window context for large files (C/Java).
        effective_context = _build_sink_window_context(code_content, slice_result)
        llm_results = self._process_with_specialized_agents(
            llm_input_slices,
            full_code_context=effective_context,
            static_result=static_result,
            slice_result=slice_result,
        )
        
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
        
        if not llm_results:
            _progress(4, "验证与报告")
            result = self._empty_result(static_result, slice_result, file_info)
            result["enhanced_analysis"] = self.enhanced_analysis_info
            if self.use_cache:
                with self._analysis_cache_lock:
                    self.analysis_cache[cache_key] = result
            return result
        
        # 4.5 用假设和触发路径丰富漏洞报告
        if hypotheses:
            llm_results = self._enrich_reports_with_hypotheses(llm_results, hypotheses)
        if trigger_paths:
            llm_results = self._enrich_reports_with_trigger_paths(llm_results, trigger_paths)
        
        # 5. 假设验证（与 SpecializedMetaAgent 一致）：合并静态结果与切片结果，供证据与 LLM 验证使用
        _progress(4, "验证与报告")
        validator_ctx = {**static_result, **slice_result}
        validated_results = self.validator_agent.process(
            llm_results, code_content, validator_ctx
        )
        
        # 更新验证通过数量
        self.enhanced_analysis_info["two_phase_validation_passed"] = len(validated_results)
        
        # 6. Generate report
        report = self.report_agent.process(validated_results, file_info, static_result)
        # Surface LLM errors to report for UI alert banner.
        llm_errors = slice_result.get("_llm_errors") if isinstance(slice_result, dict) else None
        if llm_errors:
            report["llm_errors"] = llm_errors
        
        result = {
            "static": static_result,
            "slice": slice_result,
            "llm": llm_results,
            "validation": validated_results,
            "report": report,
            "enhanced_analysis": self.enhanced_analysis_info
        }
        
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


# 测试函数
def test_enhanced_agent():
    """Test the enhanced meta agent"""
    print("=== Testing Enhanced Meta Agent ===")
    
    test_code = """
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];
    // Missing boundary check - potential buffer overflow
    strcpy(buffer, user_input);
    printf("Buffer: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
"""
    
    test_file = "test_enhanced.c"
    with open(test_file, 'w') as f:
        f.write(test_code)
    
    try:
        # Initialize agent with all features enabled
        agent = EnhancedMetaAgent(use_cache=False, 
                                  enable_hypothesis_extraction=True,
                                  enable_llm_trigger_path=True)
        
        # Analyze
        file_info = {"file_name": test_file, "project": "test"}
        result = agent.analyze(test_file, test_code, file_info)
        
        # Print results
        print(f"\nAnalysis completed:")
        print(f"  Sinks identified: {result['slice'].get('suspicious_count', 0)}")
        print(f"  LLM results: {len(result['llm'])}")
        print(f"  Validated vulnerabilities: {len(result['validation'])}")
        
        # Print enhanced analysis info
        enhanced_info = result.get('enhanced_analysis', {})
        print(f"\nEnhanced Analysis Info:")
        if enhanced_info.get("hypotheses_truncated"):
            print(
                f"  Hypotheses extracted: {enhanced_info.get('hypotheses_extracted', 0)} "
                f"(truncated from {enhanced_info.get('hypotheses_raw', 0)})"
            )
        else:
            print(f"  Hypotheses extracted: {enhanced_info.get('hypotheses_extracted', 0)}")
        print(f"  Trigger paths generated: {enhanced_info.get('trigger_paths_generated', 0)}")
        print(f"  Two-phase validation passed: {enhanced_info.get('two_phase_validation_passed', 0)}")
        
        if result['validation']:
            print("\nValidated vulnerabilities:")
            for vuln in result['validation']:
                print(f"  - {vuln.get('cwe')} at {vuln.get('location')}")
                if 'validation' in vuln:
                    print(f"    Confidence: {vuln['validation'].get('confidence', 0)}")
        
        return result
        
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)


if __name__ == "__main__":
    test_enhanced_agent()