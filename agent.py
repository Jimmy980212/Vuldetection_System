# agent.py
import os
import json
import re
import requests
import datetime
import hashlib
import threading
import time
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from config import (
    DEEPSEEK_API_KEY, DEEPSEEK_API_URL, DEEPSEEK_MODEL,
    OPENAI_API_KEY, OPENAI_API_URL, OPENAI_MODEL,
    LLM_PROVIDER, LLM_API_KEY, LLM_API_BASE, LLM_API_PATH, LLM_MODEL,
    LLM_FALLBACK_PROVIDERS, normalize_llm_provider,
)
from joern_utils import JoernHandler

# 全局缓存
_analysis_cache = {}
_cache_lock = threading.Lock()

class DeepSeekClient:
    """通用 OpenAI-compatible API 客户端（兼容旧名 DeepSeekClient）"""
    
    def __init__(self):
        self.provider = normalize_llm_provider(LLM_PROVIDER)
        self.provider_chain = self._resolve_provider_chain()
        self.active_provider = self.provider_chain[0]["provider"] if self.provider_chain else self.provider
        self.api_key = self.provider_chain[0]["api_key"] if self.provider_chain else ""
        self.api_url = self.provider_chain[0]["api_url"] if self.provider_chain else ""
        self.model = self.provider_chain[0]["model"] if self.provider_chain else ""
        self.conversation_history = []
        self.cache = {}  # 添加缓存
        self._cache_lock = threading.Lock()
        self.cache_hits = 0
        self.cache_misses = 0
        
        # API调用统计
        self.api_calls = 0
        self.total_response_time = 0
        # Last error info (for UI diagnostics)
        self.last_error = None

    @staticmethod
    def _build_headers(api_key: str):
        return {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def _resolve_provider_config(self, provider_name: str):
        provider = normalize_llm_provider(provider_name)
        provider_presets = {
            "deepseek": ("https://api.deepseek.com/v1", "deepseek-v4-pro"),
            "openai": ("https://api.openai.com/v1", "gpt-4o-mini"),
            "qwen": ("https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen-plus"),
            "wenxin": ("https://qianfan.baidubce.com/v2", "ernie-speed-128k"),
            "doubao": ("https://ark.cn-beijing.volces.com/api/v3", "doubao-pro-32k"),
            "kimi": ("https://api.moonshot.cn/v1", "moonshot-v1-8k"),
            "zhipu": ("https://open.bigmodel.cn/api/paas/v4", "glm-4-flash"),
            "hunyuan": ("https://api.hunyuan.cloud.tencent.com/v1", "hunyuan-turbo"),
        }
        preset_base, preset_model = provider_presets.get(
            provider,
            ("https://api.deepseek.com/v1", "deepseek-v4-pro"),
        )

        # Provider-specific compatibility
        if provider == "deepseek" and DEEPSEEK_API_URL:
            api_url = DEEPSEEK_API_URL
        elif provider == "openai" and OPENAI_API_URL:
            api_url = OPENAI_API_URL
        else:
            base = (LLM_API_BASE or "").rstrip("/") or preset_base
            path = LLM_API_PATH if str(LLM_API_PATH).startswith("/") else f"/{LLM_API_PATH}"
            api_url = f"{base}{path}"
        explicit_model = (LLM_MODEL or "").strip()
        if provider == "deepseek" and not explicit_model:
            model = (DEEPSEEK_MODEL or "").strip() or preset_model
        elif provider == "openai" and not explicit_model:
            model = (OPENAI_MODEL or "").strip() or preset_model
        else:
            model = explicit_model or preset_model
        if provider == "openai":
            api_key = LLM_API_KEY or OPENAI_API_KEY
        else:
            api_key = LLM_API_KEY or DEEPSEEK_API_KEY
        return {"provider": provider, "api_key": api_key, "api_url": api_url, "model": model}

    def _resolve_provider_chain(self):
        chain = []
        seen = set()
        for provider in [self.provider] + list(LLM_FALLBACK_PROVIDERS or []):
            normalized = normalize_llm_provider(provider)
            if normalized in seen:
                continue
            seen.add(normalized)
            chain.append(self._resolve_provider_config(normalized))
        return chain
    
    def chat(self, prompt, system_prompt="你是一个专业的代码安全分析专家", temperature=0.1, use_cache=True):
        """调用DeepSeek API - 带缓存"""
        
        # 生成缓存键
        cache_key = hashlib.md5(f"{prompt}{system_prompt}{temperature}".encode()).hexdigest()
        
        # 检查缓存
        if use_cache:
            with self._cache_lock:
                if cache_key in self.cache:
                    self.cache_hits += 1
                    return self.cache[cache_key]
                self.cache_misses += 1
        
        has_usable_provider = any(
            item.get("api_key") and item.get("api_key") != "your-api-key-here"
            for item in self.provider_chain
        )
        if not has_usable_provider:
            response = self._mock_response(prompt)
            if use_cache:
                with self._cache_lock:
                    self.cache[cache_key] = response
            return response

        provider_errors = []
        for provider_cfg in self.provider_chain:
            api_key = provider_cfg.get("api_key", "")
            if not api_key or api_key == "your-api-key-here":
                continue

            self.active_provider = provider_cfg.get("provider", "unknown")
            self.api_key = api_key
            self.api_url = provider_cfg.get("api_url", "")
            self.model = provider_cfg.get("model", "")
            headers = self._build_headers(self.api_key)

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "temperature": temperature,
                "max_tokens": 4000
            }

            start_time = time.time()
            try:
                with self._cache_lock:
                    self.api_calls += 1
                response = requests.post(self.api_url, headers=headers, json=payload, timeout=120)
                response_time = time.time() - start_time
                with self._cache_lock:
                    self.total_response_time += response_time

                if response.status_code == 200:
                    self.last_error = None
                    content = response.json()["choices"][0]["message"]["content"]
                    if use_cache:
                        with self._cache_lock:
                            self.cache[cache_key] = content
                    return content

                provider_errors.append({
                    "type": "http",
                    "status": int(response.status_code),
                    "provider": self.active_provider,
                })
                print(f"API调用失败: {response.status_code} ({self.active_provider})")
            except Exception as e:
                provider_errors.append({
                    "type": "exception",
                    "message": str(e),
                    "provider": self.active_provider,
                })
                print(f"API调用异常: {e}")

        # Fallback to mock so downstream parsers still get JSON.
        self.last_error = provider_errors[-1] if provider_errors else {"type": "no_provider_available"}
        response = self._mock_response(prompt)
        if use_cache:
            with self._cache_lock:
                self.cache[cache_key] = response
        return response
    
    def batch_chat(self, prompts, system_prompt="你是一个专业的代码安全分析专家", temperature=0.1, max_workers=12):
        """批量调用API - 并行处理"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_prompt = {
                executor.submit(self.chat, prompt, system_prompt, temperature): i 
                for i, prompt in enumerate(prompts)
            }
            
            for future in as_completed(future_to_prompt):
                idx = future_to_prompt[future]
                try:
                    results.append((idx, future.result()))
                except Exception as e:
                    print(f"批量API调用失败: {e}")
                    results.append((idx, "[]"))
        
        # 按原始顺序排序
        results.sort(key=lambda x: x[0])
        return [r[1] for r in results]
    
    def get_cache_stats(self):
        """获取缓存统计"""
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_size": len(self.cache),
            "api_calls": self.api_calls,
            "avg_response_time": self.total_response_time / max(1, self.api_calls)
        }

    def preflight_health_check(self) -> Dict[str, Any]:
        healthy = []
        unavailable = []
        for cfg in self.provider_chain:
            provider = cfg.get("provider", "unknown")
            api_key = str(cfg.get("api_key", "") or "").strip()
            api_url = str(cfg.get("api_url", "") or "").strip()
            model = str(cfg.get("model", "") or "").strip()
            if api_key and api_key != "your-api-key-here" and api_url and model:
                healthy.append(provider)
            else:
                unavailable.append(provider)
        selected = healthy[0] if healthy else None
        return {
            "ready": bool(healthy),
            "selected_provider": selected,
            "healthy_providers": healthy,
            "unavailable_providers": unavailable,
            "provider_chain": [x.get("provider", "unknown") for x in self.provider_chain],
        }
    
    def _mock_response(self, prompt):
        """模拟响应（无API Key时使用）- 支持更多CWE类型"""
        # mock 只在"无API Key/调用失败"时使用。
        # 旧逻辑存在大量通用触发（如 "int" + "+" -> CWE-190），在内核代码里会导致误报。
        # 这里改成"按目标 CWE 精确触发"，避免无关情况下返回 has_vulnerability=true。

        def has_any(substrs):
            return any(s in prompt for s in substrs)

        # CWE-119：缓冲区溢出/数组越界（更偏向内核样本里的拷贝/哨兵索引写法）
        if "CWE-119" in prompt:
            if has_any(["strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy", "memmove", "ib_copy_from_udata", "str_to_key", "kstrdup"]):
                return json.dumps([{
                    "has_vulnerability": True,
                    "cwe": "CWE-119",
                    "confidence": 78,
                    "location": "相关拷贝/索引位置",
                    "description": "缓冲区/索引越界风险：缺少边界或哨兵索引未被正确处理",
                    "suggestion": "加入边界检查并验证索引合法性",
                    "severity": "high"
                }])
            # 额外支持"free=-1 作为数组下标写入"的哨兵模式
            if ("int free" in prompt or "free = -1" in prompt) and ("[free]" in prompt or "table->refs[free]" in prompt):
                return json.dumps([{
                    "has_vulnerability": True,
                    "cwe": "CWE-119",
                    "confidence": 90,
                    "location": "哨兵索引作为数组下标写入处",
                    "description": "数组越界风险：哨兵索引（-1）可能被用于数组下标写入",
                    "suggestion": "确保下标在合法范围内再写入",
                    "severity": "high"
                }])
            return json.dumps([])

        # CWE-190：整数溢出/回绕（仅对"分配大小乘法 + sizeof"触发）
        if "CWE-190" in prompt:
            alloc_ok = has_any(["kzalloc", "kmalloc", "kvzalloc"]) and ("sizeof" in prompt) and ("*" in prompt)
            if alloc_ok:
                return json.dumps([{
                    "has_vulnerability": True,
                    "cwe": "CWE-190",
                    "confidence": 75,
                    "location": "分配大小计算处",
                    "description": "整数溢出风险：分配大小计算未检查乘法溢出",
                    "suggestion": "在乘法前检查溢出并限制分配大小",
                    "severity": "medium"
                }])
            return json.dumps([])

        # CWE-134：格式化字符串（要求存在 %）
        if "CWE-134" in prompt:
            if has_any(["printf", "fprintf", "sprintf", "snprintf", "syslog", "dev_dbg", "dev_info", "pr_info", "pr_err"]) and ("%" in prompt):
                return json.dumps([{
                    "has_vulnerability": True,
                    "cwe": "CWE-134",
                    "confidence": 85,
                    "location": "格式化输出位置",
                    "description": "格式化字符串漏洞风险：格式字符串与输入未正确隔离",
                    "suggestion": "使用固定格式串，并将不可信输入作为参数传入",
                    "severity": "high"
                }])
            return json.dumps([])

        # 其它 CWE：mock 不强行报，避免引入误报
        return json.dumps([])

class StaticAnalyzerAgent:
    """静态分析Agent - 优化版（加入缓存和增量分析）"""
    
    def __init__(self):
        self.joern = JoernHandler()
        self.name = "StaticAnalyzerAgent"
        self.cache = {}  # 缓存分析结果
        self._cache_lock = threading.Lock()
    
    def process(self, code_file):
        """执行静态分析 - 带缓存"""
        
        # 检查缓存（基于文件修改时间）
        file_mtime = os.path.getmtime(code_file) if os.path.exists(code_file) else 0
        cache_key = f"{code_file}_{file_mtime}"
        
        with self._cache_lock:
            if cache_key in self.cache:
                print(f"  [StaticAnalyzer] 使用缓存结果: {os.path.basename(code_file)}")
                return self.cache[cache_key]
        
        print(f"  [StaticAnalyzer] 分析文件: {os.path.basename(code_file)}")
        
        # 执行Joern解析
        result = self.joern.parse_and_export(code_file)
        
        # 提取切片
        slices = self.joern.extract_slices(result.get("dot_file", ""))
        
        # 提取数据流
        data_flows = self.joern.extract_data_flow(result.get("dot_file", ""))
        
        # 提取调用图
        call_graph = self.joern.extract_call_graph(result.get("dot_file", ""))
        
        analysis_result = {
            "status": "success",
            "slices": slices,
            "data_flows": data_flows,
            "call_graph": call_graph,
            "parse_dir": result.get("parse_dir"),
            "export_dir": result.get("export_dir"),
            "dot_file": result.get("dot_file"),
            "file_hash": hashlib.md5(open(code_file, 'rb').read()).hexdigest()
        }
        
        # 保存到缓存
        with self._cache_lock:
            self.cache[cache_key] = analysis_result
        
        return analysis_result


class EvidenceScorer:
    """证据评分器：把规则门控升级为分值决策。"""

    def __init__(self):
        self.name = "EvidenceScorer"
        self.user_input_tokens = [
            "copy_from_user", "get_user", "recv", "read", "ioctl", "argv", "input", "user",
            "sock_recv", "skb", "netlink", "request", "msg", "buffer"
        ]
        self.boundary_check_tokens = [
            "if", "min(", "max(", "sizeof", "strn", "snprintf", "len", "length", "bounds", "check",
            "unlikely", "likely", "clamp", "array_index_nospec"
        ]

    def score(self, cwe: str, static_result: dict, slice_result: dict, code: str) -> dict:
        score = 0
        reasons = []
        evidence_chain = {
            "path": [],
            "variables": [],
            "missing_checks": []
        }

        # 语义类CWE：只要切片不空，给予基础分（保证进入LLM）
        _SEMANTIC_CWES = {
            "CWE-200", "CWE-209", "CWE-264", "CWE-399", "CWE-835",
            "CWE-20", "CWE-189", "CWE-125", "CWE-459", "CWE-400",
        }
        is_semantic = cwe in _SEMANTIC_CWES

        suspicious = (slice_result.get("suspicious_lines", {}) or {}).get(cwe, [])
        if suspicious:
            score += min(25, 8 * len(suspicious))
            reasons.append(f"suspicious_lines={len(suspicious)}")
        if slice_result.get("heuristic_fallback"):
            score += 20
            reasons.append("heuristic_fallback_boost")
        # 语义兜底：给额外基础分，保证语义类CWE可以过门槛
        if slice_result.get("semantic_fallback") and is_semantic:
            score += 20
            reasons.append("semantic_fallback_boost")

        data_flows = static_result.get("data_flows", []) or []
        flow_hits = []
        for flow in data_flows:
            src = str(flow.get("source", "")).lower()
            tgt = str(flow.get("target", "")).lower()
            if self._flow_match_cwe(cwe, src, tgt):
                flow_hits.append(flow)

        if flow_hits:
            # 多路径聚合：命中路径越多，证据越强
            score += min(55, 10 * len(flow_hits))
            reasons.append(f"flow_hits={len(flow_hits)}")
            for f in flow_hits[:3]:
                src = str(f.get("source", ""))[:80]
                tgt = str(f.get("target", ""))[:80]
                evidence_chain["path"].append(f"{src} -> {tgt}")
                if src:
                    evidence_chain["variables"].append(src)
                if tgt:
                    evidence_chain["variables"].append(tgt)

        # Cross-file CPG path boost (vulnscan workspace CPG).
        cpg_flow_hits = []
        for p in (slice_result.get("data_flow_paths", {}) or {}).get(cwe, []):
            if not isinstance(p, dict):
                continue
            if str(p.get("origin", "")).strip() == "joern_reachableByFlows":
                cpg_flow_hits.append(p)
        if cpg_flow_hits:
            score += min(30, 8 * len(cpg_flow_hits))
            reasons.append(f"joern_reachableByFlows={len(cpg_flow_hits)}")
            rich_chain = any(len((h.get("path", []) or [])) >= 3 for h in cpg_flow_hits if isinstance(h, dict))
            if rich_chain:
                score += 8
                reasons.append("joern_rich_chain")

        # 输入可控性加分
        code_lower = code.lower()
        if any(tok in code_lower for tok in self.user_input_tokens):
            score += 10
            reasons.append("input_controllable_signal")

        # 边界检查缺失：对 CWE-119 重点检查
        if cwe in {"CWE-119", "CWE-120", "CWE-122", "CWE-126"}:
            if not any(tok in code_lower for tok in self.boundary_check_tokens):
                score += 20
                reasons.append("boundary_check_missing")
                evidence_chain["missing_checks"].append("boundary/length check")
            # 有锚点但缺少明确保护时给弱加分，便于后续"弱路径+强锚点"策略生效
            if suspicious and not any(tok in code_lower for tok in ["strn", "snprintf", "sizeof"]):
                score += 8
                reasons.append("suspicious_anchor_without_strong_guard")

        # 语义类CWE的额外信号检测
        if is_semantic:
            # CWE-835: 循环信号
            if cwe == "CWE-835":
                if any(tok in code_lower for tok in ["while", "for", "loop"]):
                    score += 15
                    reasons.append("loop_signal")
            # CWE-200/CWE-209: 输出函数信号
            elif cwe in {"CWE-200", "CWE-209"}:
                if any(tok in code_lower for tok in ["printf", "fprintf", "sprintf", "printk", "puts", "write"]):
                    score += 15
                    reasons.append("output_function_signal")
            # CWE-399: 资源管理信号
            elif cwe == "CWE-399":
                if any(tok in code_lower for tok in ["malloc", "kmalloc", "free", "kfree", "alloc"]):
                    score += 15
                    reasons.append("resource_management_signal")
            # CWE-20: 输入验证信号
            elif cwe == "CWE-20":
                if any(tok in code_lower for tok in ["strlen", "sizeof", "assert", "bug_on"]):
                    score += 10
                    reasons.append("validation_signal")

        # 去重变量列表
        evidence_chain["variables"] = sorted(set(v for v in evidence_chain["variables"] if v))
        return {
            "score": min(100, score),
            "reasons": reasons,
            "evidence_chain": evidence_chain
        }

    def should_enter_llm(self, evidence_score: dict) -> bool:
        # 进一步放宽证据门槛，以提升召回率（针对PrimeVul数据集）
        # 从10降低到5，让更多可疑代码进入LLM分析
        return evidence_score.get("score", 0) >= 5

    def should_pass_validation(self, evidence_score: dict) -> bool:
        # 进一步降低验证阈值，从45降低到35，让更多真实漏洞通过验证
        return evidence_score.get("score", 0) >= 35



    def _flow_match_cwe(self, cwe: str, src: str, tgt: str) -> bool:
        joined = f"{src} {tgt}"
        if cwe in {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-126"}:
            return any(k in joined for k in [
                "strcpy", "strcat", "sprintf", "memcpy", "memmove",
                "copy_from_user"
            ])
        if cwe == "CWE-134":
            return any(k in joined for k in ["printf", "fprintf", "snprintf", "%"])
        if cwe == "CWE-78":
            return any(k in joined for k in ["system", "exec", "popen"])
        if cwe == "CWE-22":
            return "fopen" in joined or ".." in joined
        return False

class SpecializedLLMAgent:
    """专门化LLM推理Agent - 每个实例只处理一种CWE类型"""
    
    def __init__(self, cwe_type, cwe_description):
        self.llm = DeepSeekClient()
        self.cwe_type = cwe_type
        self.cwe_description = cwe_description
        self.name = f"SpecializedLLMAgent-{cwe_type}"
        # 语义类CWE使用更低的置信度阈值（60），内存/指针类使用75
        _SEMANTIC_CWES = {
            "CWE-200", "CWE-209", "CWE-264", "CWE-399", "CWE-835",
            "CWE-20", "CWE-189", "CWE-125", "CWE-459", "CWE-400",
        }
        self.confidence_threshold = 60 if cwe_type in _SEMANTIC_CWES else 70
        
        # 专门化提示词模板
        self.specialized_prompt_templates = {
            "CWE-119": self._build_buffer_overflow_prompt,
            "CWE-120": self._build_buffer_overflow_prompt,
            "CWE-121": self._build_buffer_overflow_prompt,
            "CWE-122": self._build_buffer_overflow_prompt,
            "CWE-124": self._build_buffer_overflow_prompt,
            "CWE-126": self._build_buffer_overflow_prompt,
            "CWE-134": self._build_format_string_prompt,
            "CWE-78": self._build_command_injection_prompt,
            "CWE-77": self._build_command_injection_prompt,
            "CWE-22": self._build_path_traversal_prompt,
            "CWE-190": self._build_integer_overflow_prompt,
            "CWE-401": self._build_memory_leak_prompt,
            "CWE-416": self._build_use_after_free_prompt,
            "CWE-476": self._build_null_pointer_prompt,
            "CWE-704": self._build_type_confusion_prompt,
            "default": self._build_general_prompt
        }
    
    def process(self, code_slice, full_code_context="", static_result: dict = None, slice_result: dict = None):
        """处理特定CWE类型的代码切片"""
        print(f"  [{self.name}] 分析{self.cwe_type}漏洞...")
        
        if not code_slice or len(code_slice) < 50:
            return []
        
        # 获取专门化提示词构建函数
        prompt_builder = self.specialized_prompt_templates.get(
            self.cwe_type, 
            self.specialized_prompt_templates["default"]
        )
        
        # 构建专门化提示词
        prompt = prompt_builder(code_slice, full_code_context, static_result)
        
        # 调用LLM
        response = self.llm.chat(prompt, system_prompt=self._get_system_prompt())
        if getattr(self.llm, "last_error", None):
            # Provide a machine-readable error item for UI
            err = dict(self.llm.last_error)
            err["cwe"] = self.cwe_type
            err["stage"] = "llm"
            return [{"_llm_error": err, "has_vulnerability": False, "cwe": self.cwe_type, "confidence": 0}]
        
        # 解析响应
        results = self._parse_response(response)
        
        # 过滤低置信度结果
        filtered_results = [
            r for r in results 
            if r.get("confidence", 0) >= self.confidence_threshold
        ]
        
        return filtered_results
    
    def _get_system_prompt(self):
        """获取专门化的系统提示词"""
        return f"""你是一个专注于{self.cwe_type} ({self.cwe_description})漏洞检测的专家。
你的任务是分析代码中是否存在{self.cwe_type}类型的漏洞。
请专注于{self.cwe_description}的特定模式，忽略其他类型的漏洞。
请提供准确、专业的分析结果。"""
    
    def _build_buffer_overflow_prompt(self, code_slice, full_code_context, static_result):
        """构建缓冲区溢出漏洞的专门化提示词"""
        return f"""
作为缓冲区溢出漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. 内存拷贝操作（strcpy, memcpy, strcat等）是否缺少边界检查
2. 数组访问是否越界
3. 用户输入是否直接用于内存操作
4. 分配大小计算是否正确

代码切片：
{code_slice}

完整代码上下文（前500字符）：
{full_code_context[:500]}

静态分析信息：
- 数据流数量: {len(static_result.get('data_flows', [])) if static_result else 0}
- 调用图函数数量: {len(static_result.get('call_graph', {}).get('functions', [])) if static_result and static_result.get('call_graph') else 0}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置（如行号或函数名）",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_format_string_prompt(self, code_slice, full_code_context, static_result):
        """构建格式化字符串漏洞的专门化提示词"""
        return f"""
作为格式化字符串漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. printf、sprintf、fprintf等格式化函数的使用
2. 用户输入是否直接作为格式字符串
3. 格式字符串是否包含用户可控的%符号
4. 日志函数（syslog、dev_dbg等）是否使用用户输入

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_command_injection_prompt(self, code_slice, full_code_context, static_result):
        """构建命令注入漏洞的专门化提示词"""
        return f"""
作为命令注入漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. system、exec、popen等命令执行函数
2. 用户输入是否直接拼接到命令中
3. 命令参数是否经过适当过滤
4. Shell命令执行是否安全

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_path_traversal_prompt(self, code_slice, full_code_context, static_result):
        """构建路径遍历漏洞的专门化提示词"""
        return f"""
作为路径遍历漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. fopen、open、access等文件操作函数
2. 用户输入是否直接用于文件路径
3. 是否包含".."等路径遍历字符
4. 路径是否经过规范化处理

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_integer_overflow_prompt(self, code_slice, full_code_context, static_result):
        """构建整数溢出漏洞的专门化提示词"""
        return f"""
作为整数溢出漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. 整数乘法计算分配大小
2. 数组索引计算
3. 循环边界计算
4. 类型转换和符号扩展

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_memory_leak_prompt(self, code_slice, full_code_context, static_result):
        """构建内存泄漏漏洞的专门化提示词"""
        return f"""
作为内存泄漏漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. malloc/calloc分配的内存是否释放
2. 错误路径是否释放内存
3. 循环中是否释放内存
4. 资源管理是否正确

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_use_after_free_prompt(self, code_slice, full_code_context, static_result):
        """构建释放后使用漏洞的专门化提示词"""
        return f"""
作为释放后使用漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. 释放内存后是否继续使用
2. 指针别名问题
3. 双重释放风险
4. 悬垂指针使用

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_null_pointer_prompt(self, code_slice, full_code_context, static_result):
        """构建空指针解引用漏洞的专门化提示词"""
        return f"""
作为空指针解引用漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. 指针使用前是否检查NULL
2. 函数返回值是否检查
3. 错误处理路径
4. 初始化问题

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_type_confusion_prompt(self, code_slice, full_code_context, static_result):
        """构建类型混淆漏洞的专门化提示词"""
        return f"""
作为类型混淆漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

重点关注：
1. 类型转换是否正确
2. union使用是否安全
3. 类型检查是否充分
4. 内存布局理解

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _build_general_prompt(self, code_slice, full_code_context, static_result):
        """构建通用提示词"""
        return f"""
作为{self.cwe_type}漏洞专家，请分析以下代码是否存在{self.cwe_type} ({self.cwe_description})漏洞：

代码切片：
{code_slice}

请返回JSON列表：
[
    {{
        "has_vulnerability": true/false,
        "cwe": "{self.cwe_type}",
        "confidence": 0-100,
        "location": "具体位置",
        "description": "漏洞详细描述",
        "suggestion": "修复建议",
        "severity": "critical/high/medium/low"
    }}
]
如果不存在漏洞，返回空列表[]。
"""
    
    def _parse_response(self, response):
        """解析API响应"""
        results = []
        
        if not response or response.strip() == "[]":
            return results
        
        try:
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get("has_vulnerability"):
                            item["cwe"] = self.cwe_type  # 确保CWE类型正确
                            results.append(item)
        except:
            pass
        
        return results


class HypothesisValidatorAgent:
    """假设验证Agent - 优化版（快速验证）"""
    
    def __init__(self):
        self.llm = DeepSeekClient()
        self.name = "HypothesisValidatorAgent"
        # 提高验证阈值，降低误报
        # 略微下调验证阈值，避免真实漏洞在验证阶段被过度过滤
        self.validation_threshold = 60
        
        # 验证缓存
        self.validation_cache = {}
        self._cache_lock = threading.Lock()
        self.schema_warnings = []
    
    # CWE 类型集合：语义类漏洞（无需 source->sink 数据流即可触发）
    _SEMANTIC_CWES = {
        "CWE-200", "CWE-209", "CWE-264", "CWE-399", "CWE-835",
        "CWE-20", "CWE-189", "CWE-125", "CWE-459", "CWE-400",
    }

    def process(self, vuln_reports, original_code, static_info):
        """验证多个漏洞假设 - 并行验证"""
        print(f"  [HypothesisValidator] 验证 {len(vuln_reports)} 个漏洞假设...")
        self.schema_warnings = []

        if not vuln_reports:
            return []

        validated_reports = []

        # 准备批量验证
        validation_tasks = []

        for report in vuln_reports:
            if not report.get("has_vulnerability"):
                continue
            # 降低最低证据分要求：从25降至10，减少漏洞在验证前被剔除
            if report.get("_evidence_score", 0) < 10:
                continue

            location = report.get("location", "")
            report_cwe = report.get("cwe", "")
            context_code = self._extract_context(
                original_code,
                location,
                report_cwe=report_cwe,
                static_info=static_info,
            )

            # 对于语义类CWE，即使上下文不足也不直接丢弃，用原始代码前300字符兜底
            if not context_code or len(context_code.strip()) < 20:
                if report_cwe in self._SEMANTIC_CWES:
                    context_code = original_code[:600]
                else:
                    continue

            structured = self._build_structured_evidence(report, context_code, static_info)

            cwe = report.get("cwe", "")

            # 语义类CWE：不要求 has_data_path / has_suspicious_anchor，直接允许进入LLM验证
            if cwe in self._SEMANTIC_CWES:
                pass  # 不设硬约束，允许通过
            else:
                # 结构化证据硬约束（仅对内存/指针类CWE）
                if not structured.get("has_data_path") and not structured.get("has_suspicious_anchor"):
                    continue
                if cwe in {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-126"} and not (
                    structured.get("boundary_check_missing")
                    or structured.get("has_data_path")
                    or structured.get("has_suspicious_anchor")
                ):
                    continue
                # 第二轮：边界类漏洞要求至少有一定证据密度，避免低质量噪声进入最终报告
                if cwe in {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-126"}:
                    density = structured.get("flow_hit_count", 0) + structured.get("suspicious_count", 0)
                    if density < 1:
                        continue

            # 第三轮：高证据直通验证（减少二次LLM格式/响应不稳定造成的漏报）
            evidence_score = report.get("_evidence_score", 0)
            # 语义类CWE降低直通门槛（30分即可直通）
            direct_pass_threshold = 30 if cwe in self._SEMANTIC_CWES else 40
            if evidence_score >= direct_pass_threshold and (
                cwe in self._SEMANTIC_CWES
                or structured.get("has_data_path")
                or (structured.get("has_suspicious_anchor") and structured.get("boundary_check_missing"))
            ):
                direct_validation = {
                    "is_real": True,
                    "confidence": max(self.validation_threshold, min(95, evidence_score)),
                    "evidence": "high-structured-evidence",
                    "structured_evidence": structured
                }
                ok, normalized, errs = self._validate_validation_schema(direct_validation)
                if not ok:
                    self.schema_warnings.extend(errs)
                    continue
                report["validation"] = normalized
                validated_reports.append(report)
                continue
            
            # 生成缓存键
            cache_key = hashlib.md5(f"{json.dumps(report, sort_keys=True)}{context_code[:200]}".encode()).hexdigest()
            
            # 检查缓存
            with self._cache_lock:
                if cache_key in self.validation_cache:
                    validation = self.validation_cache[cache_key]
                else:
                    validation = None

            if validation is not None:
                validation["structured_evidence"] = structured
                ok, normalized, errs = self._validate_validation_schema(validation)
                if not ok:
                    self.schema_warnings.extend(errs)
                    continue
                if normalized.get("is_real"):
                    report["validation"] = normalized
                    validated_reports.append(report)
                continue
            
            validation_tasks.append((report, context_code, cache_key, structured))
        
        # 并行验证
        if validation_tasks:
            prompts = []
            task_info = []
            
            for report, context_code, cache_key, structured in validation_tasks:
                prompt = self._build_validation_prompt(report, context_code, static_info, structured)
                prompts.append(prompt)
                task_info.append((report, cache_key, structured))
            
            # 批量调用
            responses = self.llm.batch_chat(prompts, max_workers=12)
            
            for i, response in enumerate(responses):
                report, cache_key, structured = task_info[i]
                try:
                    json_match = re.search(r'\{.*\}', response, re.DOTALL)
                    if json_match:
                        validation = json.loads(json_match.group())
                        validation["structured_evidence"] = structured
                        ok, normalized, errs = self._validate_validation_schema(validation)
                        if not ok:
                            self.schema_warnings.extend(errs)
                            continue
                        with self._cache_lock:
                            self.validation_cache[cache_key] = normalized
                        
                        if normalized.get("is_real") and normalized.get("confidence", 0) >= self.validation_threshold:
                            report["validation"] = normalized
                            validated_reports.append(report)
                except:
                    pass
        
        print(f"  [HypothesisValidator] 验证通过 {len(validated_reports)} 个漏洞")
        if self.schema_warnings:
            print(f"  [HypothesisValidator] schema warnings: {len(self.schema_warnings)}")
        return validated_reports

    def _validate_validation_schema(self, payload: Dict[str, Any]):
        errors = []
        if not isinstance(payload, dict):
            return False, {}, ["validation schema: payload must be object"]

        is_real = payload.get("is_real")
        if not isinstance(is_real, bool):
            errors.append("validation schema: is_real must be bool")

        confidence = payload.get("confidence", 0)
        try:
            confidence = int(float(confidence))
        except Exception:
            errors.append("validation schema: confidence must be number")
            confidence = 0

        evidence = str(payload.get("evidence", "") or "").strip()
        if not evidence:
            errors.append("validation schema: evidence is required")

        structured = payload.get("structured_evidence", {})
        if not isinstance(structured, dict):
            errors.append("validation schema: structured_evidence must be object")
            structured = {}

        if errors:
            return False, {}, errors

        normalized = {
            "is_real": bool(is_real),
            "confidence": max(0, min(100, confidence)),
            "evidence": evidence[:120],
            "structured_evidence": structured,
        }
        return True, normalized, []
    
    def _build_validation_prompt(self, report, context_code, static_info, structured_evidence):
        """构建验证提示"""
        # 静态分析摘要：帮助验证阶段避免"关键词误触发"
        static_hint_lines = []
        if static_info:
            data_flows = static_info.get("data_flows", []) or []
            call_graph = static_info.get("call_graph", {}) or {}
            functions = call_graph.get("functions", []) if isinstance(call_graph, dict) else []
            static_hint_lines.append(f"data_flows_count: {len(data_flows)}")
            static_hint_lines.append(f"call_graph_functions_count: {len(functions) if functions else 0}")

        static_hint = "\n".join(static_hint_lines).strip()
        if not static_hint:
            static_hint = "static_info: (none)"

        return f"""
快速验证漏洞：

CWE: {report.get('cwe', '未知')}
位置: {report.get('location', '未知')}
描述: {report.get('description', '无')}

代码上下文：
{context_code[:500]}

静态分析摘要（辅助证据）：
{static_hint}

结构化证据约束：
- input_controllable: {structured_evidence.get("input_controllable")}
- boundary_check_missing: {structured_evidence.get("boundary_check_missing")}
- has_data_path: {structured_evidence.get("has_data_path")}
- path_excerpt: {structured_evidence.get("path_excerpt", "")}

返回JSON：
{{
    "is_real": true/false,
    "confidence": 0-100,
    "evidence": "简要证据（20字以内）"
}}
"""

    def _build_structured_evidence(self, report, context_code: str, static_info: dict):
        cwe = report.get("cwe", "")
        pre_chain = report.get("_evidence_chain", {}) or {}
        code_l = (context_code or "").lower()
        data_paths = (static_info.get("semantic_evidence_by_cwe", {}) or {}).get(cwe, [])
        suspicious = (static_info.get("suspicious_lines", {}) or {}).get(cwe, [])
        has_data_path = len(data_paths) > 0
        has_suspicious_anchor = len(suspicious) > 0
        path_excerpt = ""
        if has_data_path:
            first = data_paths[0]
            path_excerpt = first.get("path", "") or ""
        elif pre_chain.get("path"):
            path_excerpt = str(pre_chain.get("path", [""])[0])
            has_data_path = True

        input_controllable = any(x in code_l for x in [
            "copy_from_user", "get_user", "recv", "read", "ioctl", "argv", "input", "user"
        ])
        boundary_check_missing = not any(x in code_l for x in [
            "sizeof", "strn", "snprintf", "min(", "max(", "if (", "if("
        ])
        variables = []
        if has_data_path:
            if data_paths:
                f = data_paths[0]
                if f.get("source"):
                    variables.append(str(f.get("source"))[:80])
                if f.get("target"):
                    variables.append(str(f.get("target"))[:80])
            variables.extend(pre_chain.get("variables", []) or [])

        return {
            "input_controllable": input_controllable,
            "boundary_check_missing": boundary_check_missing,
            "has_data_path": has_data_path,
            "has_suspicious_anchor": has_suspicious_anchor,
            "flow_hit_count": len(data_paths),
            "suspicious_count": len(suspicious),
            "path_excerpt": path_excerpt,
            "variables": variables[:4],
            "missing_checks": (pre_chain.get("missing_checks", []) or []) + (["boundary/length check"] if boundary_check_missing else [])
        }
    
    def _extract_context(self, code, location, report_cwe: str = "", static_info: dict = None, lines=3):
        """提取指定位置附近的代码上下文 - 快速提取

        说明：
        - LLM 的 location 字段很多时候不包含行号（例如"strcpy调用处"），此时容易导致验证输入缺上下文从而误判。
        - 因此增加一个回退：当拿不到行号时，基于切片阶段的 `static_info.suspicious_lines` 选择该 CWE 的可疑行附近内容。
        """
        lines_list = code.split('\n')

        def _build_around(ln: int) -> str:
            start = max(0, ln - lines - 1)
            end = min(len(lines_list), ln + lines)
            context = []
            for i in range(start, end):
                prefix = "→ " if i + 1 == ln else "  "
                context.append(f"{prefix}{i+1}: {lines_list[i]}")
            return "\n".join(context)

        # 1) 优先从 location 解析行号
        line_num = None
        if location:
            loc = location.lower()
            if "line" in loc:
                match = re.search(r'line\s*(\d+)', loc)
                if match:
                    line_num = int(match.group(1))
            elif ":" in location:
                match = re.search(r'(\d+):', location)
                if match:
                    line_num = int(match.group(1))

            # 兜底：提取 location 中出现的数字作为可能行号
            if line_num is None:
                match = re.search(r'(\d+)', location)
                if match:
                    possible = int(match.group(1))
                    if 1 <= possible <= len(lines_list):
                        line_num = possible

        if line_num is not None and 1 <= line_num <= len(lines_list):
            return _build_around(line_num)

        # 2) 回退：基于切片阶段 suspicious_lines 提供上下文
        if static_info and report_cwe:
            suspicious_lines = static_info.get("suspicious_lines", {}).get(report_cwe, [])
            # suspicious_lines: [(line_num, line_stripped), ...]
            # 仅取前几个，避免过长
            for ln, _ in suspicious_lines[:3]:
                if 1 <= ln <= len(lines_list):
                    return _build_around(int(ln))

        return ""

class ReportAgent:
    """报告生成Agent - 修复版，包含完整CWE描述"""
    
    def __init__(self):
        self.name = "ReportAgent"
        # 完整的CWE描述字典
        self.cwe_descriptions = {
            # 缓冲区溢出相关
            "CWE-119": "缓冲区溢出：内存操作未正确限制",
            "CWE-120": "缓冲区复制无边界检查",
            "CWE-121": "栈缓冲区溢出",
            "CWE-122": "堆缓冲区溢出",
            "CWE-124": "缓冲区下溢",
            "CWE-126": "缓冲区过度读取",
            
            # 内存管理相关
            "CWE-401": "内存泄漏：未释放动态分配的内存",
            "CWE-404": "资源未正确释放",
            "CWE-415": "双重释放：对同一内存块多次释放",
            "CWE-416": "释放后使用：访问已释放的内存",
            "CWE-590": "释放非堆内存",
            "CWE-761": "释放已释放的内存",
            "CWE-762": "内存释放不匹配",
            
            # 指针相关
            "CWE-476": "空指针解引用",
            "CWE-690": "未检查返回值导致空指针解引用",
            "CWE-252": "未检查返回值",
            
            # 整数相关
            "CWE-190": "整数溢出或回绕",
            "CWE-191": "整数下溢",
            "CWE-194": "未预期的符号扩展",
            "CWE-195": "有符号到无符号转换错误",
            "CWE-197": "数值截断错误",
            "CWE-681": "数值类型转换错误",
            
            # 注入相关
            "CWE-77": "命令注入",
            "CWE-78": "OS命令注入",
            "CWE-88": "参数注入",
            "CWE-89": "SQL注入",
            
            # 路径相关
            "CWE-22": "路径遍历",
            "CWE-23": "相对路径遍历",
            "CWE-35": "路径遍历: '.../...//'",
            "CWE-59": "链接跟随",
            "CWE-73": "文件名外部控制",
            
            # 格式化字符串
            "CWE-134": "格式化字符串漏洞",
            
            # 并发相关
            "CWE-362": "竞态条件",
            "CWE-363": "基于竞争条件的符号链接跟随",
            "CWE-364": "信号处理程序竞争条件",
            "CWE-366": "竞争条件中的逻辑错误",
            "CWE-367": "检查时间与使用时间竞争",
            
            # 文件处理
            "CWE-377": "不安全的临时文件",
            "CWE-378": "不安全的临时文件创建",
            "CWE-379": "临时文件权限问题",
            
            # 信息泄露
            "CWE-200": "信息泄露",
            "CWE-201": "通过错误信息的信息泄露",
            "CWE-202": "通过数据查询的信息泄露",
            "CWE-203": "通过行为差异的信息泄露",
            
            # 权限相关
            "CWE-250": "不必要的权限执行",
            "CWE-264": "权限、特权和访问控制",
            "CWE-265": "权限逻辑错误",
            "CWE-266": "权限继承错误",
            "CWE-267": "权限提升",
            
            # 硬编码凭证
            "CWE-259": "硬编码密码",
            "CWE-260": "硬编码密码配置文件",
            "CWE-261": "弱加密密钥",
            "CWE-262": "硬编码默认密码",
            "CWE-263": "密码硬编码",
            "CWE-321": "硬编码加密密钥",
            "CWE-522": "凭证保护不足",
            "CWE-798": "硬编码凭证",
            
            # 加密相关
            "CWE-322": "密钥交换缺乏认证",
            "CWE-323": "重用一次性密钥",
            "CWE-324": "密钥存储使用不当",
            "CWE-325": "加密密钥缺失",
            "CWE-326": "不充分的加密强度",
            "CWE-327": "已损坏或有风险的加密算法",
            "CWE-328": "可逆的单向哈希",
            
            # 死代码
            "CWE-561": "死代码",
            "CWE-563": "未使用的变量赋值",
            "CWE-570": "永远为真的表达式",
            "CWE-571": "永远为假的表达式",
            
            # 类型混淆
            "CWE-704": "不正确的类型转换",
            "CWE-843": "类型混淆",
            
            # 资源耗尽
            "CWE-770": "无限制的资源分配",
            "CWE-771": "资源释放缺失",
            "CWE-772": "资源释放缺失",
            "CWE-773": "资源引用缺失",
            "CWE-774": "文件描述符泄漏",
            
            # 数组相关
            "CWE-129": "数组索引验证不正确",
            
            # 除零错误
            "CWE-369": "除零错误",
            
            # 初始化相关
            "CWE-456": "缺少初始化",
            "CWE-457": "使用未初始化变量",
            "CWE-665": "不正确的初始化",
            
            # 其他
            "CWE-478": "switch语句中缺少default",
            "CWE-479": "未初始化的信号处理器",
            "CWE-480": "使用错误的运算符",
            "CWE-481": "赋值运算符使用错误",
            "CWE-482": "比较与赋值混淆",
            "CWE-483": "错误的括号",
            "CWE-484": "switch语句中break缺失",
            
            # 特定于你例子中的CWE
            "CWE-404": "资源未正确释放",
            "CWE-762": "内存释放不匹配",
            "CWE-457": "使用未初始化变量",
        }
    
    def process(self, validated_reports, sample_info, static_info):
        """生成漏洞报告 - 快速生成"""
        
        if not validated_reports:
            return self._empty_report(sample_info, static_info)

        def _split_multi_locations(reports: list) -> list:
            """
            Some LLM outputs aggregate many hit locations into a single item, e.g.
              "第67行、 第181行、 ...（约120个sink点）"
            This makes UI look like "one vuln" while actually multiple distinct sites exist.
            Split such aggregated entries into multiple entries by extracting line numbers.
            """
            try:
                max_splits = int(os.environ.get("VULN_MAX_LOCATION_SPLITS", "80"))
            except Exception:
                max_splits = 80

            out = []
            for v in reports or []:
                if not isinstance(v, dict):
                    out.append(v)
                    continue
                loc = str(v.get("location", "") or "")
                cwe = str(v.get("cwe", "") or "").strip().upper()
                # Heuristic: if the location string is long and contains many numbers, split.
                # NOTE: do NOT use word-boundaries here; Python \w is Unicode-aware and
                # will treat Chinese characters as word chars, making "67行" fail to match.
                nums = re.findall(r"(\d{1,6})", loc)
                # Filter obvious false positives: keep reasonable line numbers only.
                line_nums = []
                for n in nums:
                    try:
                        x = int(n)
                    except Exception:
                        continue
                    if 1 <= x <= 1000000:
                        line_nums.append(x)
                # Unique preserve order
                seen = set()
                uniq = []
                for x in line_nums:
                    if x not in seen:
                        seen.add(x)
                        uniq.append(x)
                has_list_sep = any(sep in loc for sep in ("、", ",", "，", ";", "；"))
                has_range = bool(re.search(r"\d+\s*-\s*\d+", loc))
                # Split when the model aggregates multiple distinct hit sites into one entry.
                # Use a looser threshold for common sink-based CWEs (command/path/memory APIs).
                sink_cwes = {"CWE-78", "CWE-22", "CWE-119", "CWE-134", "CWE-401", "CWE-416", "CWE-415"}
                # For these CWEs, if the model lists multiple line numbers, we prefer splitting
                # even when separators are unstable (spaces/non-ascii punctuation).
                should_split = (
                    (len(uniq) >= 2 and (has_list_sep or cwe in sink_cwes) and not has_range and len(loc) >= 8)
                    or (len(uniq) >= 6 and len(loc) >= 60)
                )
                if should_split and (cwe in sink_cwes or len(uniq) >= 6):
                    for x in uniq[:max_splits]:
                        nv = dict(v)
                        nv["location"] = f"line {x}"
                        nv["_split_from_location"] = loc[:3000]
                        out.append(nv)
                    continue
                out.append(v)
            return out

        # Normalize: split aggregated multi-location entries before counting/sorting.
        validated_reports = _split_multi_locations(list(validated_reports or []))
        
        # 统计（使用字典快速统计）
        vulns_by_cwe = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for vuln in validated_reports:
            cwe = vuln.get("cwe", "unknown")
            vulns_by_cwe[cwe] = vulns_by_cwe.get(cwe, 0) + 1
            
            severity = vuln.get("severity", "medium")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # 按严重性排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        validated_reports.sort(key=lambda x: severity_order.get(x.get("severity", "medium"), 2))
        
        report = {
            "file": sample_info.get("file_name", "unknown"),
            "project": sample_info.get("project", "unknown"),
            "scan_time": datetime.datetime.now().isoformat(),
            "total_vulnerabilities": len(validated_reports),
            "vulnerabilities_by_cwe": vulns_by_cwe,
            "severity_summary": severity_counts,
            "vulnerabilities": [],
            "static_analysis_summary": {
                "slices_count": len(static_info.get("slices", [])),
                "data_flows_count": len(static_info.get("data_flows", [])),
                "functions_count": len(static_info.get("call_graph", {}).get("functions", []))
            }
        }
        
        for vuln in validated_reports:
            cwe = vuln.get("cwe", "未知")
            validation = vuln.get("validation", {}) or {}
            structured = validation.get("structured_evidence", {}) or {}
            evidence_chain = {
                "path": [structured.get("path_excerpt")] if structured.get("path_excerpt") else [],
                "variables": structured.get("variables", []) or [],
                "missing_checks": structured.get("missing_checks", []) or []
            }
            vuln_entry = {
                "cwe": cwe,
                "cwe_description": self._get_cwe_description(cwe),
                "confidence": vuln.get("confidence", 0),
                "severity": vuln.get("severity", "medium"),
                "evidence_score": vuln.get("_evidence_score", 0),
                "evidence_reasons": vuln.get("_evidence_reasons", []),
                "location": vuln.get("location", "未知"),
                "description": vuln.get("description", "无")[:300],
                "suggestion": vuln.get("suggestion", "无")[:120],
                "validation": validation,
                "evidence_chain": evidence_chain
            }
            ok_entry, normalized_entry, _ = self._validate_vulnerability_entry(vuln_entry)
            if ok_entry:
                report["vulnerabilities"].append(normalized_entry)

        report["total_vulnerabilities"] = len(report["vulnerabilities"])
        report["vulnerabilities_by_cwe"] = {}
        report["severity_summary"] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in report["vulnerabilities"]:
            cwe = item.get("cwe", "unknown")
            report["vulnerabilities_by_cwe"][cwe] = report["vulnerabilities_by_cwe"].get(cwe, 0) + 1
            sev = item.get("severity", "medium")
            report["severity_summary"][sev] = report["severity_summary"].get(sev, 0) + 1

        ok_report, normalized_report, warnings = self._validate_report_schema(report)
        if warnings:
            normalized_report["schema_warnings"] = warnings
        return normalized_report if ok_report else self._empty_report(sample_info, static_info)
    
    def _get_cwe_description(self, cwe_id):
        """获取CWE描述 - 带默认值"""
        if not cwe_id or cwe_id == "未知":
            return "未知CWE类型"
        
        # 尝试直接获取
        if cwe_id in self.cwe_descriptions:
            return self.cwe_descriptions[cwe_id]
        
        # 尝试提取数字部分（处理如 "CWE-404" 格式）
        match = re.search(r'CWE[-\s]?(\d+)', cwe_id, re.IGNORECASE)
        if match:
            cwe_num = f"CWE-{match.group(1)}"
            if cwe_num in self.cwe_descriptions:
                return self.cwe_descriptions[cwe_num]
        
        return f"{cwe_id}类型漏洞"
    
    def _empty_report(self, sample_info, static_info):
        """快速生成空报告"""
        return {
            "file": sample_info.get("file_name", "unknown"),
            "project": sample_info.get("project", "unknown"),
            "scan_time": datetime.datetime.now().isoformat(),
            "total_vulnerabilities": 0,
            "vulnerabilities_by_cwe": {},
            "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "vulnerabilities": [],
            "static_analysis_summary": {
                "slices_count": len(static_info.get("slices", [])),
                "data_flows_count": len(static_info.get("data_flows", [])),
                "functions_count": len(static_info.get("call_graph", {}).get("functions", []))
            }
        }

    def _validate_vulnerability_entry(self, entry: Dict[str, Any]):
        try:
            confidence = int(float(entry.get("confidence", 0) or 0))
            evidence_score = int(float(entry.get("evidence_score", 0) or 0))
        except Exception:
            return False, {}, ["vulnerability entry: confidence/evidence_score must be number"]

        cwe = str(entry.get("cwe", "") or "").strip()
        location = str(entry.get("location", "") or "").strip()
        if not cwe or not location:
            return False, {}, ["vulnerability entry: cwe/location required"]

        severity = str(entry.get("severity", "medium") or "medium").lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "medium"

        normalized = dict(entry)
        normalized["confidence"] = max(0, min(100, confidence))
        normalized["evidence_score"] = max(0, min(100, evidence_score))
        normalized["severity"] = severity
        return True, normalized, []

    def _validate_report_schema(self, report: Dict[str, Any]):
        warnings = []
        if not isinstance(report, dict):
            return False, {}, ["report schema: report must be object"]

        required_keys = [
            "file",
            "project",
            "scan_time",
            "total_vulnerabilities",
            "vulnerabilities_by_cwe",
            "severity_summary",
            "vulnerabilities",
            "static_analysis_summary",
        ]
        for key in required_keys:
            if key not in report:
                warnings.append(f"report schema: missing key={key}")

        if not isinstance(report.get("vulnerabilities", []), list):
            warnings.append("report schema: vulnerabilities must be list")
            report["vulnerabilities"] = []
        if not isinstance(report.get("vulnerabilities_by_cwe", {}), dict):
            warnings.append("report schema: vulnerabilities_by_cwe must be object")
            report["vulnerabilities_by_cwe"] = {}
        if not isinstance(report.get("severity_summary", {}), dict):
            warnings.append("report schema: severity_summary must be object")
            report["severity_summary"] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        if not isinstance(report.get("static_analysis_summary", {}), dict):
            warnings.append("report schema: static_analysis_summary must be object")
            report["static_analysis_summary"] = {"slices_count": 0, "data_flows_count": 0, "functions_count": 0}

        return True, report, warnings
