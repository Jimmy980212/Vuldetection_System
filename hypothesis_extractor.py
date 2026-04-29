"""
独立的假设提取阶段：HypothesisExtractor 类
用于从代码中提取潜在的漏洞假设，为后续验证阶段提供输入
"""

import re
import json
import os
from typing import Dict, List, Any, Tuple, Set
from collections import defaultdict
from agent import DeepSeekClient

class HypothesisExtractor:
    """假设提取器：从代码中提取潜在的漏洞假设"""
    
    def __init__(self):
        self.llm = DeepSeekClient()
        self.name = "HypothesisExtractor"
        self.last_stats = {}
        
        # 漏洞模式关键词
        self.vulnerability_patterns = {
            "buffer_overflow": [
                r'\b(strcpy|strcat|sprintf|vsprintf|gets|memcpy|memmove)\s*\(',
                r'\b(copy_from_user|get_user)\s*\(',
                r'\[.*\]\s*=',
                r'array\[.*\]'
            ],
            "format_string": [
                r'\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(',
                r'%[^%]*%'
            ],
            "command_injection": [
                r'\b(system|exec|popen)\s*\(',
                r'ShellExecute\s*\('
            ],
            "path_traversal": [
                r'\b(fopen|open|access|stat)\s*\(',
                r'\.\./',
                r'\.\.\\'
            ],
            "integer_overflow": [
                r'\b(kzalloc|kmalloc|kvzalloc)\s*\([^)]*\*[^)]*sizeof\s*\(',
                r'malloc\s*\([^)]*\*[^)]*sizeof\s*\('
            ],
            "memory_leak": [
                r'\b(malloc|calloc|realloc|kmalloc|kzalloc)\s*\(',
                r'\b(free|kfree)\s*\('
            ],
            "use_after_free": [
                r'free\s*\([^)]+\)\s*;.*\1\b',
                r'kfree\s*\([^)]+\)\s*;.*\1\b'
            ],
            "null_pointer": [
                r'\*[a-zA-Z_][a-zA-Z0-9_]*\s*=',
                r'->[a-zA-Z_][a-zA-Z0-9_]*\s*='
            ]
        }
        
        # 编译正则表达式
        self.compiled_patterns = {}
        for vuln_type, patterns in self.vulnerability_patterns.items():
            compiled = []
            for pattern in patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    # 跳过无效的正则表达式
                    pass
            self.compiled_patterns[vuln_type] = compiled
    
    def extract_hypotheses(self, code: str, static_info: Dict) -> List[Dict]:
        """从代码中提取漏洞假设"""
        print(f"  [HypothesisExtractor] 从代码中提取漏洞假设")
        
        # 步骤1：基于模式的初步提取
        pattern_hypotheses = self._extract_by_patterns(code)
        
        # 步骤2：基于静态分析的提取
        static_hypotheses = self._extract_by_static_analysis(code, static_info)
        
        # 步骤3：LLM驱动的假设生成
        llm_hypotheses = self._extract_by_llm(code, static_info)
        
        # 合并所有假设
        all_hypotheses = pattern_hypotheses + static_hypotheses + llm_hypotheses
        
        # 去重和排序
        unique_hypotheses = self._deduplicate_hypotheses(all_hypotheses)
        raw_n = len(unique_hypotheses)
        self.last_stats = {
            "raw": raw_n,
            "returned": raw_n,
            "max": raw_n,
            "truncated": False,
        }

        print(f"  [HypothesisExtractor] 提取到 {raw_n} 个唯一假设")
        return unique_hypotheses
    
    def _extract_by_patterns(self, code: str) -> List[Dict]:
        """基于模式匹配提取假设"""
        hypotheses = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith(('//', '/*', '*', '#')):
                continue
            
            # 检查每种漏洞模式
            for vuln_type, patterns in self.compiled_patterns.items():
                for pattern in patterns:
                    if pattern.search(line_stripped):
                        # 映射到CWE类型
                        cwe_type = self._map_vuln_type_to_cwe(vuln_type)
                        
                        hypothesis = {
                            "type": "pattern_based",
                            "cwe": cwe_type,
                            "line": line_num,
                            "code": line_stripped[:200],
                            "pattern": vuln_type,
                            "confidence": 40,  # 模式匹配的基础置信度
                            "description": f"检测到{vuln_type}模式: {line_stripped[:100]}",
                            "evidence": [f"模式匹配: {pattern.pattern[:50]}"]
                        }
                        hypotheses.append(hypothesis)
                        break  # 每个漏洞类型只匹配一次
        
        return hypotheses
    
    def _extract_by_static_analysis(self, code: str, static_info: Dict) -> List[Dict]:
        """基于静态分析结果提取假设"""
        hypotheses = []
        
        # 使用数据流信息
        data_flows = static_info.get("data_flows", [])
        if data_flows:
            # 分析数据流中的潜在漏洞
            for flow in data_flows:
                src = str(flow.get("source", "")).lower()
                tgt = str(flow.get("target", "")).lower()
                
                # 检查危险的数据流
                cwe_type = self._infer_cwe_from_data_flow(src, tgt)
                if cwe_type:
                    hypothesis = {
                        "type": "data_flow_based",
                        "cwe": cwe_type,
                        "source": src[:100],
                        "sink": tgt[:100],
                        "confidence": 50,
                        "description": f"危险数据流: {src[:50]} -> {tgt[:50]}",
                        "evidence": [f"数据流分析: {src[:30]} -> {tgt[:30]}"]
                    }
                    hypotheses.append(hypothesis)
        
        # 使用调用图信息
        call_graph = static_info.get("call_graph", {})
        functions = call_graph.get("functions", [])
        calls = call_graph.get("calls", [])
        
        # 分析危险函数调用
        dangerous_functions = ["strcpy", "strcat", "sprintf", "system", "exec", "popen", "gets"]
        for func in functions:
            for dangerous in dangerous_functions:
                if dangerous in func.lower():
                    cwe_type = self._map_function_to_cwe(dangerous)
                    hypothesis = {
                        "type": "function_based",
                        "cwe": cwe_type,
                        "function": func,
                        "confidence": 45,
                        "description": f"检测到危险函数: {func}",
                        "evidence": [f"危险函数: {dangerous}"]
                    }
                    hypotheses.append(hypothesis)
                    break
        
        return hypotheses
    
    def _extract_by_llm(self, code: str, static_info: Dict) -> List[Dict]:
        """使用LLM提取漏洞假设"""
        hypotheses = []
        
        # 如果代码太长，只取前一部分
        code_sample = code[:2000] if len(code) > 2000 else code
        
        # 构建提示词
        prompt = self._build_llm_prompt(code_sample, static_info)
        
        try:
            # 调用LLM
            response = self.llm.chat(
                prompt,
                system_prompt="你是一个专业的代码安全分析专家，专门从代码中提取潜在的漏洞假设。"
            )
            
            # 解析响应
            llm_hypotheses = self._parse_llm_response(response)
            hypotheses.extend(llm_hypotheses)
            
        except Exception as e:
            print(f"  [HypothesisExtractor] LLM提取失败: {e}")
        
        return hypotheses
    
    def _build_llm_prompt(self, code: str, static_info: Dict) -> str:
        """构建LLM提示词"""
        # 静态分析摘要
        static_summary = ""
        data_flows = static_info.get("data_flows", [])
        call_graph = static_info.get("call_graph", {})
        
        if data_flows:
            static_summary += f"数据流数量: {len(data_flows)}\n"
            # 添加示例数据流
            for flow in data_flows[:3]:
                src = flow.get("source", "")
                tgt = flow.get("target", "")
                static_summary += f"  {src[:50]} -> {tgt[:50]}\n"
        
        if call_graph:
            functions = call_graph.get("functions", [])
            static_summary += f"函数数量: {len(functions)}\n"
            # 添加示例函数
            for func in functions[:5]:
                static_summary += f"  {func}\n"
        
        return f"""
请分析以下C/C++代码，提取潜在的漏洞假设：

代码片段：
{code}

静态分析摘要：
{static_summary}

请提取潜在的漏洞假设，重点关注：
1. 缓冲区溢出（strcpy, memcpy等）
2. 格式化字符串漏洞（printf, sprintf等）
3. 命令注入（system, exec等）
4. 路径遍历（fopen, open等）
5. 整数溢出（分配大小计算）
6. 内存泄漏（malloc/free不匹配）
7. 释放后使用
8. 空指针解引用

返回JSON列表：
[
  {{
    "cwe": "CWE类型（如CWE-119）",
    "line": "行号或位置描述",
    "description": "漏洞假设描述",
    "confidence": "置信度0-100",
    "evidence": ["证据1", "证据2"],
    "type": "llm_based"
  }}
]

如果未发现潜在漏洞，返回空列表[]。
"""
    
    def _parse_llm_response(self, response: str) -> List[Dict]:
        """解析LLM响应"""
        hypotheses = []
        
        if not response or response.strip() == "[]":
            return hypotheses
        
        try:
            # 查找JSON数组
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get("cwe"):
                            # 确保必要字段
                            item.setdefault("type", "llm_based")
                            item.setdefault("confidence", 60)
                            item.setdefault("evidence", [])
                            item.setdefault("description", "LLM提取的漏洞假设")
                            # line / confidence 可能被模型写成字符串，下游需数值比较
                            item["line"] = self._coerce_line_field(item.get("line"))
                            item["confidence"] = self._coerce_conf_int(item.get("confidence", 60))
                            hypotheses.append(item)
        except Exception as e:
            print(f"  [HypothesisExtractor] 解析LLM响应失败: {e}")
        
        return hypotheses
    
    @staticmethod
    def _coerce_line_field(val: Any) -> Any:
        if val is None:
            return 0
        if isinstance(val, int):
            return val
        if isinstance(val, str):
            m = re.search(r"\d+", val)
            return int(m.group(0)) if m else 0
        return 0

    @staticmethod
    def _coerce_conf_int(val: Any) -> int:
        if isinstance(val, (int, float)):
            return int(val)
        if isinstance(val, str):
            m = re.search(r"\d+", val)
            return int(m.group(0)) if m else 0
        return 0

    def _map_vuln_type_to_cwe(self, vuln_type: str) -> str:
        """映射漏洞类型到CWE"""
        mapping = {
            "buffer_overflow": "CWE-119",
            "format_string": "CWE-134",
            "command_injection": "CWE-78",
            "path_traversal": "CWE-22",
            "integer_overflow": "CWE-190",
            "memory_leak": "CWE-401",
            "use_after_free": "CWE-416",
            "null_pointer": "CWE-476"
        }
        return mapping.get(vuln_type, "CWE-未知")
    
    def _map_function_to_cwe(self, function: str) -> str:
        """映射函数到CWE"""
        function_lower = function.lower()
        
        if "strcpy" in function_lower or "strcat" in function_lower or "memcpy" in function_lower:
            return "CWE-119"
        elif "printf" in function_lower or "sprintf" in function_lower:
            return "CWE-134"
        elif "system" in function_lower or "exec" in function_lower or "popen" in function_lower:
            return "CWE-78"
        elif "fopen" in function_lower or "open" in function_lower:
            return "CWE-22"
        elif "malloc" in function_lower or "calloc" in function_lower:
            return "CWE-401"
        elif "free" in function_lower:
            return "CWE-416"
        else:
            return "CWE-未知"
    
    def _infer_cwe_from_data_flow(self, src: str, tgt: str) -> str:
        """从数据流推断CWE类型"""
        joined = f"{src} {tgt}".lower()
        
        if any(k in joined for k in ["strcpy", "strcat", "sprintf", "memcpy", "memmove", "copy_from_user"]):
            return "CWE-119"
        elif any(k in joined for k in ["printf", "fprintf", "snprintf"]) or "%" in joined:
            return "CWE-134"
        elif any(k in joined for k in ["system", "exec", "popen"]):
            return "CWE-78"
        elif "fopen" in joined:
            return "CWE-22"
        elif "malloc" in joined and "free" in joined:
            return "CWE-401"
        else:
            return ""
    
    def _deduplicate_hypotheses(self, hypotheses: List[Dict]) -> List[Dict]:
        """去重假设"""
        unique_hypotheses = []
        seen_keys = set()
        
        for hypothesis in hypotheses:
            # 创建唯一键：CWE类型 + 行号/位置
            cwe = hypothesis.get("cwe", "")
            location = hypothesis.get("line", hypothesis.get("source", ""))
            key = f"{cwe}_{location}"
            
            if key not in seen_keys:
                seen_keys.add(key)
                unique_hypotheses.append(hypothesis)
            else:
                # 合并证据
                for existing in unique_hypotheses:
                    existing_key = f"{existing.get('cwe', '')}_{existing.get('line', existing.get('source', ''))}"
                    if existing_key == key:
                        # 合并证据列表
                        existing_evidence = existing.get("evidence", [])
                        new_evidence = hypothesis.get("evidence", [])
                        combined_evidence = list(set(existing_evidence + new_evidence))
                        existing["evidence"] = combined_evidence
                        
                        # 更新置信度（取最高值）
                        existing["confidence"] = max(
                            self._coerce_conf_int(existing.get("confidence", 0)),
                            self._coerce_conf_int(hypothesis.get("confidence", 0)),
                        )
                        break
        
        # 按置信度排序
        unique_hypotheses.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return unique_hypotheses
