"""
LLM + Joern 综合驱动的触发路径构造
将 Joern 的结构化分析与 LLM 的语义分析相结合
"""

import re
import json
from typing import Dict, List, Any, Tuple, Set
from collections import defaultdict, deque
from agent import DeepSeekClient

class LLMDrivenTriggerPathConstructor:
    """LLM + Joern 综合驱动的触发路径构造"""
    
    def __init__(self):
        self.llm = DeepSeekClient()
        self.name = "LLMDrivenTriggerPathConstructor"
        
        # 攻击者可控的输入模式
        self.attacker_controlled_patterns = [
            r'\b(copy_from_user|get_user|recv|read|ioctl)\s*\(',
            r'\b(argv|argc)\b',
            r'\b(input|user|buffer|data|param)\b',
            r'\b(fgets|scanf|gets|readline)\s*\(',
            r'\b(sock_recv|skb|netlink)\b',
            r'\b(request|msg|packet)\b'
        ]
        
        # 编译正则表达式
        self.compiled_attacker_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.attacker_controlled_patterns
        ]
    
    def construct(self, code: str, static_info: Dict) -> List[Dict]:
        """
        综合使用 Joern 和 LLM 构造触发路径
        """
        print(f"  [LLMDrivenTriggerPathConstructor] 开始构造触发路径")
        
        # ========== Step 1: Joern 提供结构信息 ==========
        
        # 1.1 从 Joern 获取所有 sink 节点
        sinks = self._extract_sinks_from_joern(static_info)
        
        if not sinks:
            print(f"  [LLMDrivenTriggerPathConstructor] 未找到 sink 节点")
            return []
        
        print(f"  [LLMDrivenTriggerPathConstructor] 从 Joern 找到 {len(sinks)} 个 sink 节点")
        
        # 1.2 从 Joern 获取数据流边
        data_flows = static_info.get("data_flows", [])
        
        # 1.3 从 Joern 构建可达性图
        reachability_graph = self._build_reachability_graph(data_flows)
        
        # ========== Step 2: LLM 进行语义分析和路径筛选 ==========
        
        all_trigger_paths = []
        
        for sink_idx, sink in enumerate(sinks[:5]):  # 限制处理前5个sink
            print(f"  [LLMDrivenTriggerPathConstructor] 处理 sink {sink_idx+1}/{min(5, len(sinks))}: {sink.get('function', 'unknown')}")
            
            # 2.1 使用 Joern 数据流找到所有可能的 source（粗筛）
            candidate_sources = self._find_candidate_sources(sink, reachability_graph)
            
            if not candidate_sources:
                print(f"    [LLMDrivenTriggerPathConstructor] 未找到候选 source")
                continue
            
            print(f"    [LLMDrivenTriggerPathConstructor] 找到 {len(candidate_sources)} 个候选 source")
            
            # 2.2 LLM 分析每个候选路径的语义合理性
            try:
                prompt = self._build_trigger_path_prompt(
                    code=code,
                    sink=sink,
                    candidate_sources=candidate_sources,
                    data_flows=data_flows
                )
                
                # 2.3 LLM 输出结构化触发路径
                llm_result = self.llm.chat(prompt, system_prompt=self._get_system_prompt())
                
                # 2.4 解析 LLM 输出
                trigger_paths = self._parse_llm_response(llm_result)
                
                # 2.5 将 LLM 输出与 Joern 验证结合
                validated_paths = self._validate_with_joern(trigger_paths, reachability_graph)
                
                all_trigger_paths.extend(validated_paths)
                
                print(f"    [LLMDrivenTriggerPathConstructor] 生成 {len(validated_paths)} 个验证后的触发路径")
                
            except Exception as e:
                print(f"    [LLMDrivenTriggerPathConstructor] LLM 分析失败: {e}")
                continue
        
        print(f"  [LLMDrivenTriggerPathConstructor] 总共生成 {len(all_trigger_paths)} 个触发路径")
        return all_trigger_paths
    
    def _extract_sinks_from_joern(self, static_info: Dict) -> List[Dict]:
        """从 Joern 静态分析结果中提取 sink 节点"""
        sinks = []
        
        # 从数据流中提取 sink（目标节点）
        data_flows = static_info.get("data_flows", [])
        
        # 收集所有目标节点作为潜在的 sink
        sink_nodes = set()
        for flow in data_flows:
            target = flow.get("target", "")
            if target and self._is_potential_sink(target):
                sink_nodes.add(target)
        
        # 转换为 sink 信息结构
        for sink_node in list(sink_nodes)[:20]:  # 限制数量
            sinks.append({
                "node": sink_node,
                "function": self._extract_function_from_node(sink_node),
                "type": self._classify_sink_type(sink_node),
                "line": self._extract_line_from_node(sink_node)
            })
        
        # 如果没有从数据流中找到 sink，尝试从调用图中找
        if not sinks:
            call_graph = static_info.get("call_graph", {})
            functions = call_graph.get("functions", [])
            
            for func in functions[:10]:  # 限制数量
                if self._is_potential_sink(func):
                    sinks.append({
                        "node": func,
                        "function": func,
                        "type": self._classify_sink_type(func),
                        "line": "unknown"
                    })
        
        return sinks
    
    def _build_reachability_graph(self, data_flows: List[Dict]) -> Dict[str, List[str]]:
        """从数据流构建可达性图"""
        graph = defaultdict(list)
        
        for flow in data_flows:
            src = flow.get("source", "")
            tgt = flow.get("target", "")
            
            if src and tgt:
                # 添加正向边（source -> target）
                graph[src].append(tgt)
                # 添加反向边用于回溯（target -> source）
                if tgt not in graph:
                    graph[tgt] = []
        
        return dict(graph)
    
    def _find_candidate_sources(self, sink: Dict, reachability_graph: Dict[str, List[str]]) -> List[Dict]:
        """从可达性图中找到候选 source 节点"""
        candidate_sources = []
        sink_node = sink.get("node", "")
        
        if not sink_node or sink_node not in reachability_graph:
            return candidate_sources
        
        # 使用 BFS 回溯找到所有可能的 source
        visited = set()
        queue = deque([(sink_node, [sink_node])])
        
        while queue:
            current_node, path = queue.popleft()
            
            # 检查当前节点是否是攻击者可控的 source
            if self._is_attacker_controlled(current_node) and current_node != sink_node:
                candidate_sources.append({
                    "node": current_node,
                    "path_to_sink": path,
                    "distance": len(path) - 1,
                    "is_attacker_controlled": True
                })
            
            # 继续回溯
            for src, targets in reachability_graph.items():
                if current_node in targets and src not in visited:
                    visited.add(src)
                    queue.append((src, [src] + path))
        
        # 按距离排序（距离越短优先级越高）
        candidate_sources.sort(key=lambda x: x["distance"])
        
        return candidate_sources[:10]
    
    def _build_trigger_path_prompt(self, code: str, sink: Dict, 
                                 candidate_sources: List[Dict], data_flows: List[Dict]) -> str:
        """构建让 LLM 分析触发路径的提示词"""
        
        # 限制代码长度
        code_sample = code[:3000] if len(code) > 3000 else code
        
        # 格式化 sink 信息
        sink_info = f"""
函数: {sink.get('function', 'unknown')}
类型: {sink.get('type', 'unknown')}
节点: {sink.get('node', 'unknown')}
行号: {sink.get('line', 'unknown')}
"""
        
        # 格式化候选 source 信息
        sources_info = ""
        for i, source in enumerate(candidate_sources[:5]):  # 只显示前5个
            sources_info += f"""
候选 Source {i+1}:
  节点: {source.get('node', 'unknown')}
  到 sink 的距离: {source.get('distance', 'unknown')} 步
  路径: {' -> '.join(source.get('path_to_sink', []))}
  攻击者可控: {source.get('is_attacker_controlled', False)}
"""
        
        # 格式化数据流信息
        flows_info = ""
        for i, flow in enumerate(data_flows[:10]):  # 只显示前10个
            flows_info += f"  {flow.get('source', '?')} -> {flow.get('target', '?')}\n"
        
        return f"""
你是漏洞分析专家。请结合以下静态分析结果，构造从 source 到 sink 的触发路径。

## 代码
{code_sample}

## Joern 识别的 Sink
{sink_info}

## Joern 识别的候选 Source
{sources_info}

## Joern 数据流边（前10个）
{flows_info}

## 任务
1. 从候选 source 中选择真正可控的输入
2. 沿着数据流边，构造完整的触发路径
3. 标注路径上的关键步骤（赋值、运算、条件判断）
4. 评估路径的可行性

## 输出 JSON 格式
{{
    "trigger_paths": [
        {{
            "source": "source_node_name",
            "sink": "sink_node_name",
            "steps": [
                {{"node": "node1", "type": "source", "description": "攻击者输入点"}},
                {{"node": "node2", "type": "propagation", "description": "数据传播"}},
                {{"node": "node3", "type": "sink", "description": "漏洞触发点"}}
            ],
            "is_feasible": true,
            "confidence": 85,
            "reasoning": "路径分析说明",
            "cwe_type": "CWE-119"
        }}
    ]
}}

请只返回 JSON 格式的输出。
"""
    
    def _parse_llm_response(self, response: str) -> List[Dict]:
        """解析 LLM 响应"""
        trigger_paths = []
        
        if not response:
            return trigger_paths
        
        try:
            # 查找 JSON 部分
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                
                if "trigger_paths" in data and isinstance(data["trigger_paths"], list):
                    for path in data["trigger_paths"]:
                        # 确保必要字段
                        path.setdefault("source", "unknown")
                        path.setdefault("sink", "unknown")
                        path.setdefault("steps", [])
                        path.setdefault("is_feasible", False)
                        path.setdefault("confidence", 0)
                        path.setdefault("reasoning", "")
                        path.setdefault("cwe_type", "CWE-未知")
                        
                        trigger_paths.append(path)
        except Exception as e:
            print(f"    [LLMDrivenTriggerPathConstructor] 解析 LLM 响应失败: {e}")
        
        return trigger_paths
    
    def _validate_with_joern(self, trigger_paths: List[Dict], 
                           reachability_graph: Dict[str, List[str]]) -> List[Dict]:
        """使用 Joern 图验证 LLM 生成的路径"""
        validated_paths = []
        
        for path in trigger_paths:
            if not path.get("is_feasible", False):
                continue
            
            source = path.get("source", "")
            sink = path.get("sink", "")
            
            # 检查 source 和 sink 是否在图中
            if source not in reachability_graph or sink not in reachability_graph:
                path["joern_validation"] = "节点不在图中"
                continue
            
            # 检查路径是否可达（简化验证）
            is_reachable = self._check_reachability(source, sink, reachability_graph)
            
            if is_reachable:
                path["joern_validation"] = "路径可达"
                path["joern_validated"] = True
                validated_paths.append(path)
            else:
                path["joern_validation"] = "路径不可达"
                path["joern_validated"] = False
        
        return validated_paths
    
    def _check_reachability(self, source: str, sink: str, 
                          reachability_graph: Dict[str, List[str]]) -> bool:
        """检查从 source 到 sink 是否可达"""
        if source == sink:
            return True
        
        visited = set()
        queue = deque([source])
        
        while queue:
            current = queue.popleft()
            
            if current == sink:
                return True
            
            if current in visited:
                continue
            
            visited.add(current)
            
            # 添加所有可达的节点
            for neighbor in reachability_graph.get(current, []):
                if neighbor not in visited:
                    queue.append(neighbor)
        
        return False
    
    def _is_potential_sink(self, node: str) -> bool:
        """检查节点是否是潜在的 sink"""
        node_lower = node.lower()
        
        sink_keywords = [
            'strcpy', 'strcat', 'sprintf', 'memcpy', 'memmove',
            'printf', 'fprintf', 'snprintf', 'syslog',
            'system', 'exec', 'popen',
            'fopen', 'open', 'access',
            'malloc', 'calloc', 'realloc', 'kmalloc',
            'free', 'kfree'
        ]
        
        return any(keyword in node_lower for keyword in sink_keywords)
    
    def _extract_function_from_node(self, node: str) -> str:
        """从节点中提取函数名"""
        if '(' in node:
            return node.split('(', 1)[0].strip()
        return node
    
    def _classify_sink_type(self, node: str) -> str:
        """分类 sink 类型"""
        node_lower = node.lower()
        
        if any(k in node_lower for k in ['strcpy', 'strcat', 'sprintf', 'memcpy', 'memmove']):
            return "buffer_overflow"
        elif any(k in node_lower for k in ['printf', 'fprintf', 'snprintf', 'syslog']):
            return "format_string"
        elif any(k in node_lower for k in ['system', 'exec', 'popen']):
            return "command_injection"
        elif any(k in node_lower for k in ['fopen', 'open', 'access']):
            return "path_traversal"
        elif any(k in node_lower for k in ['malloc', 'calloc', 'realloc', 'kmalloc']):
            return "memory_allocation"
        elif any(k in node_lower for k in ['free', 'kfree']):
            return "memory_free"
        else:
            return "unknown"
    
    def _extract_line_from_node(self, node: str) -> str:
        """从节点中提取行号信息"""
        line_match = re.search(r'line[:\s]*(\d+)', node, re.IGNORECASE)
        if line_match:
            return line_match.group(1)
        
        colon_match = re.search(r':(\d+)[:\s]', node)
        if colon_match:
            return colon_match.group(1)
        
        return "unknown"
    
    def _is_attacker_controlled(self, node: str) -> bool:
        """检查节点是否是攻击者可控的"""
        node_lower = node.lower()
        
        for pattern in self.compiled_attacker_patterns:
            if pattern.search(node_lower):
                return True
        
        attacker_keywords = ['argv', 'input', 'user', 'buffer', 'data', 'param', 
                           'request', 'msg', 'packet', 'ioctl', 'recv']
        
        return any(keyword in node_lower for keyword in attacker_keywords)
    
    def _get_system_prompt(self) -> str:
        """获取系统提示词"""
        return """你是一个专业的漏洞分析专家，专门分析代码中的触发路径。
你的任务是结合静态分析结果（Joern）和代码语义，构造从攻击者可控输入到漏洞触发点的完整路径。

重点关注：
1. 识别真正的攻击者可控输入点
2. 跟踪数据在代码中的传播路径
3. 识别路径上的关键操作（赋值、运算、条件判断）
4. 评估路径的可行性和触发条件

请基于提供的静态分析结果进行推理，不要凭空想象。"""


# 测试函数
def test_llm_trigger_path_constructor():
    """测试 LLM 驱动的触发路径构造器"""
    print("=== 测试 LLMDrivenTriggerPathConstructor ===")
    
    test_code = """
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];
    // 缺少边界检查 - 潜在的缓冲区溢出
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
    
    # 模拟静态分析信息
    static_info = {
        "data_flows": [
            {"source": "argv[1]", "target": "user_input"},
            {"source": "user_input", "target": "buffer"},
            {"source": "buffer", "target": "strcpy"}
        ],
        "call_graph": {
            "functions": ["main", "vulnerable_function"],
            "calls": [{"caller": "main", "callee": "vulnerable_function"}]
        }
    }
    
    constructor = LLMDrivenTriggerPathConstructor()
    trigger_paths = constructor.construct(test_code, static_info)
    
    print(f"生成 {len(trigger_paths)} 个触发路径")
    for i, path in enumerate(trigger_paths, 1):
        print(f"\n路径 {i}:")
        print(f"  Source: {path.get('source')}")
        print(f"  Sink: {path.get('sink')}")
        print(f"  可行性: {path.get('is_feasible')}")
        print(f"  置信度: {path.get('confidence')}")
    
    return trigger_paths


if __name__ == "__main__":
    test_llm_trigger_path_constructor()