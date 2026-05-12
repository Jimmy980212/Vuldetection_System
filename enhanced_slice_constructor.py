"""
Enhanced Slice Constructor with Sink Identification and Data Flow Backtracking
Implements: Identify sink → backtrack data flow → track attacker-controllable input → record intermediate steps
Key principle: Do NOT filter paths based on protection, boundary checks, or error handling (leave these for validation phase)
"""

import os
import re
import json
from typing import Dict, List, Any, Tuple, Set
from collections import defaultdict, deque
from config import VULN_KEYWORDS

class EnhancedSliceConstructor:
    """Enhanced slice constructor with sink identification and data flow backtracking"""
    
    def __init__(self):
        self.name = "EnhancedSliceConstructor"
        self.min_context_lines = 3
        self.max_fallback_hits_per_cwe = 4
        # For large files, show more sinks per CWE in slices.
        # These control what gets fed into LLM prompts (slice text), not the raw sink detection.
        self.large_file_lines = int(os.environ.get("VULN_LARGE_FILE_LINES", "2000"))
        self.max_sinks_per_cwe = int(os.environ.get("VULN_MAX_SINKS_PER_CWE", "5"))
        self.max_sinks_per_cwe_large = int(os.environ.get("VULN_MAX_SINKS_PER_CWE_LARGE", "20"))
        # 仅对这些 CWE 开启关键词兜底，避免把弱相关关键词带入高误报
        self.allowed_keyword_fallback_cwes = {
            "CWE-476", "CWE-401", "CWE-190", "CWE-399", "CWE-209",
            "CWE-20", "CWE-125", "CWE-129", "CWE-189", "CWE-835",
            "CWE-704", "CWE-287", "CWE-617",
        }
        # 对高噪声 CWE 要求更高命中数后再触发 fallback
        self.min_hits_for_fallback = {
            "CWE-189": 3,
            "CWE-835": 2,
            "CWE-125": 2,
            "CWE-129": 2,
            "CWE-399": 2,
            "CWE-209": 2,
        }
        
        # Sink functions for different CWE types
        self.sink_patterns = {
            "CWE-119": re.compile(r'\b(strcpy|strcat|sprintf|vsprintf|gets|memcpy|memmove|ib_copy_from_udata|str_to_key|kstrdup)\s*\(', re.IGNORECASE),
            "CWE-134": re.compile(r'\b(printf|fprintf|sprintf|snprintf|syslog|dev_dbg|dev_info|pr_info|pr_err)\s*\(', re.IGNORECASE),
            "CWE-78": re.compile(r'\b(system|exec|popen)\s*\(', re.IGNORECASE),
            "CWE-22": re.compile(r'\b(fopen|open|access|stat|chdir|chmod|rename|remove)\s*\(', re.IGNORECASE),
            "CWE-190": re.compile(r'\b(kzalloc|kmalloc|kvzalloc)\s*\([^)]*\*[^)]*sizeof\s*\(', re.IGNORECASE),
            "CWE-401": re.compile(r'\b(malloc|calloc|realloc|kmalloc|kzalloc)\s*\(', re.IGNORECASE),
            "CWE-416": re.compile(r'\b(free|kfree)\s*\(', re.IGNORECASE),
            "CWE-476": re.compile(r'\*[a-zA-Z_][a-zA-Z0-9_]*\s*=', re.IGNORECASE),
        }
        
        # Source functions (attacker-controllable inputs)
        self.source_patterns = re.compile(
            r'\b(copy_from_user|get_user|recv|read|ioctl|argv|input|user|'
            r'sock_recv|skb|netlink|request|msg|buffer|fgets|scanf|gets)\s*\(',
            re.IGNORECASE
        )
        
        # Variable assignment patterns for data flow tracking
        self.assignment_pattern = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);')
        self.pointer_deref_pattern = re.compile(r'\*([a-zA-Z_][a-zA-Z0-9_]*)')
        self.array_access_pattern = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\[([^\]]+)\]')
        
        # Control flow keywords
        self.control_flow_keywords = {'if', 'else', 'while', 'for', 'switch', 'case', 'return', 'goto'}

        # 兜底关键词（来自 config.VULN_KEYWORDS）：当严格 sink 没命中时，仍构造可疑切片进入后续链路
        self.keyword_patterns = {}
        for cwe, keywords in VULN_KEYWORDS.items():
            if not keywords:
                continue
            if cwe not in self.allowed_keyword_fallback_cwes:
                continue
            try:
                self.keyword_patterns[cwe] = re.compile("|".join(keywords), re.IGNORECASE)
            except re.error:
                escaped = [re.escape(k) for k in keywords if k]
                if escaped:
                    self.keyword_patterns[cwe] = re.compile("|".join(escaped), re.IGNORECASE)
        
    def process(self, code: str, static_info: Dict) -> Dict:
        """Enhanced slice construction with sink identification and data flow backtracking"""
        print(f"  [EnhancedSliceConstructor] Constructing enhanced slices with data flow backtracking")
        
        lines = code.split('\n')
        
        # Step 1: Identify all sinks in the code
        sinks_by_cwe = self._identify_sinks(lines)
        
        if not sinks_by_cwe:
            # 兜底1：关键词命中（提升 PrimeVul 召回）
            sinks_by_cwe = self._identify_sinks_by_keywords(lines)
        
        if not sinks_by_cwe:
            # 兜底2：语义类宽松入口（代码片段足够长时，避免整条链路被切片阶段短路）
            sinks_by_cwe = self._build_semantic_fallback_sinks(lines)

        if not sinks_by_cwe:
            print(f"  [EnhancedSliceConstructor] No sinks identified")
            return self._empty_result()
        
        print(f"  [EnhancedSliceConstructor] Identified sinks: { {cwe: len(sinks) for cwe, sinks in sinks_by_cwe.items()} }")
        
        # Step 2: For each sink, backtrack data flow to find attacker-controllable sources
        data_flow_paths_by_cwe = self._backtrack_data_flow(lines, sinks_by_cwe, static_info)
        
        # Step 3: Construct enhanced slices with full data flow paths
        slices_by_cwe = self._construct_enhanced_slices(lines, sinks_by_cwe, data_flow_paths_by_cwe, static_info)
        
        # Step 4: Extract suspicious lines for evidence scoring
        suspicious_lines = self._extract_suspicious_lines(lines, sinks_by_cwe, data_flow_paths_by_cwe)
        
        return {
            "suspicious_count": sum(len(sinks) for sinks in sinks_by_cwe.values()),
            "slices_by_cwe": slices_by_cwe,
            "code_slice": list(slices_by_cwe.values())[0] if slices_by_cwe else "",
            "suspicious_lines": suspicious_lines,
            "data_flow_paths": data_flow_paths_by_cwe,
            "sinks_by_cwe": sinks_by_cwe,
            "heuristic_fallback": bool(sinks_by_cwe) and all(
                sink.get("fallback", False) for sinks in sinks_by_cwe.values() for sink in sinks
            ),
            "enhanced_analysis": True
        }

    def _identify_sinks_by_keywords(self, lines: List[str]) -> Dict[str, List[Dict]]:
        """当严格 sink 未命中时，按 CWE 关键词做兜底。"""
        sinks_by_cwe = defaultdict(list)
        if not self.keyword_patterns:
            return {}

        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith(('//', '/*', '#include')):
                continue

            for cwe, pattern in self.keyword_patterns.items():
                if pattern.search(line):
                    # 控制每个 CWE 的兜底点数量，避免切片过长导致误报和成本上升
                    if len(sinks_by_cwe[cwe]) >= self.max_fallback_hits_per_cwe:
                        continue
                    sinks_by_cwe[cwe].append({
                        "line": line_num,
                        "code": line_stripped[:200],
                        "function": self._extract_function_name(line),
                        "variables": self._extract_variable_info(line),
                        "context": self._get_context(lines, line_num, 2),
                        "fallback": True,
                    })
        # 过滤高噪声 CWE 的低命中结果
        filtered = {}
        for cwe, items in sinks_by_cwe.items():
            min_hits = self.min_hits_for_fallback.get(cwe, 1)
            if len(items) >= min_hits:
                filtered[cwe] = items

        if filtered:
            print(
                f"  [EnhancedSliceConstructor] Keyword fallback sinks: "
                f"{ {cwe: len(v) for cwe, v in filtered.items()} }"
            )
        return dict(filtered)

    def _build_semantic_fallback_sinks(self, lines: List[str]) -> Dict[str, List[Dict]]:
        """
        语义类 CWE 的最终兜底入口：只要代码片段有一定长度，就给出最小切片，
        防止切片阶段把样本直接判定为“无可疑点”。
        """
        if len(lines) < 10:
            return {}
        code = "\n".join(lines).lower()
        # 语义兜底要有最小信号，避免“任何函数片段”都被打成可疑
        semantic_signals = [
            "while", "for", "loop", "assert", "bug_on",
            "malloc", "free", "open(", "close(", "printf", "printk",
            "if", "return", "error", "fail",
        ]
        if not any(sig in code for sig in semantic_signals):
            return {}

        semantic_cwes = ["CWE-20", "CWE-399", "CWE-209", "CWE-264"]
        first_line = (lines[0].strip() if lines else "")[:200]
        sinks_by_cwe = {
            cwe: [{
                "line": 1,
                "code": first_line,
                "function": "semantic_fallback",
                "variables": [],
                "context": self._get_context(lines, 1, 2),
                "fallback": True,
            }]
            for cwe in semantic_cwes
        }
        print(f"  [EnhancedSliceConstructor] Semantic fallback sinks: {len(semantic_cwes)} CWEs")
        return sinks_by_cwe
    
    def _identify_sinks(self, lines: List[str]) -> Dict[str, List[Dict]]:
        """Identify sink functions in the code"""
        sinks_by_cwe = defaultdict(list)
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # 过滤掉大块注释/预处理行
            # 但注意：很多空指针解引用形态在代码里会出现为行首 `*ptr = ...`，
            # 如果简单地把所有行首 `*` 都当做注释，会导致 CWE-476 永远漏掉。
            if line_stripped.startswith(('//', '/*', '#include')):
                continue
            if line_stripped.startswith('*'):
                # 只有在它更像“注释续行”时才跳过；若它符合 `*var =` 解引用赋值形态，则保留参与 sink 命中
                if not self.sink_patterns.get("CWE-476") or not self.sink_patterns["CWE-476"].search(line_stripped):
                    continue
            
            # Check for sink patterns for each CWE
            for cwe, pattern in self.sink_patterns.items():
                if pattern.search(line):
                    # Extract variable/argument information
                    var_info = self._extract_variable_info(line)
                    
                    sinks_by_cwe[cwe].append({
                        "line": line_num,
                        "code": line_stripped[:200],
                        "function": self._extract_function_name(line),
                        "variables": var_info,
                        "context": self._get_context(lines, line_num, 2)
                    })
        
        return dict(sinks_by_cwe)
    
    def _backtrack_data_flow(self, lines: List[str], sinks_by_cwe: Dict[str, List[Dict]], 
                           static_info: Dict) -> Dict[str, List[List[Dict]]]:
        """Backtrack data flow from sinks to find attacker-controllable sources"""
        data_flow_paths_by_cwe = defaultdict(list)
        
        # Use static analysis data flows if available
        static_data_flows = static_info.get("data_flows", [])
        
        for cwe, sinks in sinks_by_cwe.items():
            for sink in sinks:
                sink_line = sink["line"]
                sink_vars = sink.get("variables", [])
                
                # Try to find data flow paths using static analysis
                static_paths = self._find_static_data_flow_paths(static_data_flows, sink_vars, cwe)
                
                if static_paths:
                    data_flow_paths_by_cwe[cwe].extend(static_paths)
                else:
                    # Fallback to simple line-based backtracking
                    simple_path = self._simple_backtrack(lines, sink_line, sink_vars, cwe)
                    if simple_path:
                        data_flow_paths_by_cwe[cwe].append(simple_path)

        # Merge workspace-level Joern reachableByFlows (for vulnscan cross-file mode).
        # Expected shape: static_info["reachable_flows_by_cwe"][cwe] = [{sink,source,nodes,evidence,origin}, ...]
        reachable_by_cwe = static_info.get("reachable_flows_by_cwe", {}) or {}
        for cwe, flows in reachable_by_cwe.items():
            if not isinstance(flows, list):
                continue
            min_nodes = 2 if cwe == "CWE-78" else 3
            for f in flows:
                if not isinstance(f, dict):
                    continue
                sink_s = str(f.get("sink", "")).strip()
                src_s = str(f.get("source", "")).strip()
                if not sink_s or not src_s or sink_s == src_s:
                    continue
                evidence = f.get("evidence", f.get("nodes", []))
                chain_codes = []
                if isinstance(evidence, list):
                    for n in evidence:
                        if isinstance(n, dict):
                            c = str(n.get("code", "")).strip()
                            if c:
                                chain_codes.append(c)
                uniq = []
                for c in chain_codes:
                    if c not in uniq:
                        uniq.append(c)
                if len(uniq) < min_nodes:
                    continue
                data_flow_paths_by_cwe[cwe].append({
                    "sink": sink_s,
                    "source": src_s,
                    "path": uniq[:80] if uniq else [sink_s, src_s],
                    "path_length": len(uniq) if uniq else 2,
                    "is_attacker_controllable": True,
                    "origin": str(f.get("origin", "joern_reachableByFlows")),
                    "evidence": evidence if isinstance(evidence, list) else [],
                })

        # Pure CPG mode for core C sink CWEs: keep only Joern-reachable flows.
        pure_cpg = str(os.getenv("C_PURE_CPG_TAINT", "0")).strip().lower() in {"1", "true", "yes", "on"}
        if pure_cpg:
            core_cwes = {"CWE-78", "CWE-22", "CWE-119", "CWE-190"}
            for cwe in list(data_flow_paths_by_cwe.keys()):
                if cwe not in core_cwes:
                    continue
                only_joern = []
                for p in data_flow_paths_by_cwe.get(cwe, []):
                    if isinstance(p, dict) and str(p.get("origin", "")).strip() == "joern_reachableByFlows":
                        only_joern.append(p)
                data_flow_paths_by_cwe[cwe] = only_joern
        
        return dict(data_flow_paths_by_cwe)
    
    def _find_static_data_flow_paths(self, static_data_flows: List[Dict], sink_vars: List[str], 
                                    cwe: str) -> List[List[Dict]]:
        """Find data flow paths using static analysis results"""
        paths = []
        
        if not static_data_flows or not sink_vars:
            return paths
        
        # Build a simple graph from static data flows
        graph = defaultdict(list)
        for flow in static_data_flows:
            src = flow.get("source", "")
            tgt = flow.get("target", "")
            if src and tgt:
                graph[tgt].append(src)
        
        # For each sink variable, try to find paths to sources
        for sink_var in sink_vars[:3]:  # Limit to first 3 variables
            if sink_var in graph:
                # Simple BFS to find paths
                queue = deque([(sink_var, [sink_var])])
                visited = set([sink_var])
                
                while queue:
                    current_var, path = queue.popleft()
                    
                    # Check if this is a source (attacker-controllable)
                    if self._is_source_variable(current_var):
                        paths.append({
                            "sink": sink_var,
                            "source": current_var,
                            "path": path,
                            "path_length": len(path),
                            "is_attacker_controllable": True
                        })
                    
                    # Continue backtracking
                    for prev_var in graph.get(current_var, []):
                        if prev_var not in visited:
                            visited.add(prev_var)
                            queue.append((prev_var, path + [prev_var]))
        
        return paths
    
    def _simple_backtrack(self, lines: List[str], sink_line: int, sink_vars: List[str], 
                         cwe: str) -> List[Dict]:
        """Simple line-based backtracking for data flow"""
        if not sink_vars:
            return []
        
        # Look for assignments of sink variables in previous lines
        path = []
        for line_num in range(sink_line - 1, max(0, sink_line - 50), -1):
            line = lines[line_num - 1]
            
            # Check for assignments to sink variables
            for var in sink_vars:
                if f"{var} =" in line or f"{var}=" in line:
                    # Found an assignment
                    source_info = self._extract_assignment_source(line, var)
                    if source_info:
                        path.append({
                            "line": line_num,
                            "variable": var,
                            "code": line.strip()[:150],
                            "source": source_info,
                            "is_source": self._is_source_line(line)
                        })
                        
                        # Check if source is attacker-controllable
                        if self._is_source_line(line):
                            return [{
                                "sink": sink_vars[0],
                                "source": source_info.get("variable", "unknown"),
                                "path": [var, source_info.get("variable", "unknown")],
                                "path_length": 2,
                                "is_attacker_controllable": True,
                                "lines": [line_num, sink_line]
                            }]
        
        return []
    
    def _construct_enhanced_slices(self, lines: List[str], sinks_by_cwe: Dict[str, List[Dict]],
                                 data_flow_paths_by_cwe: Dict[str, List[List[Dict]]],
                                 static_info: Dict) -> Dict[str, str]:
        """Construct enhanced slices with data flow paths"""
        slices_by_cwe = {}
        is_large = len(lines) >= self.large_file_lines
        max_sinks_show = self.max_sinks_per_cwe_large if is_large else self.max_sinks_per_cwe
        
        for cwe, sinks in sinks_by_cwe.items():
            slice_lines = []
            
            # Add header
            slice_lines.append(f"=== {cwe} ENHANCED ANALYSIS ===")
            slice_lines.append(f"Total sinks identified: {len(sinks)}")
            slice_lines.append("")
            
            # Add data flow paths if available
            data_flow_paths = data_flow_paths_by_cwe.get(cwe, [])
            if data_flow_paths:
                slice_lines.append("DATA FLOW PATHS (Sink → Source):")
                for i, path in enumerate(data_flow_paths[:3]):  # Show first 3 paths
                    slice_lines.append(f"  Path {i+1}:")
                    slice_lines.append(f"    Sink: {path.get('sink', 'unknown')}")
                    slice_lines.append(f"    Source: {path.get('source', 'unknown')}")
                    slice_lines.append(f"    Path: {' → '.join(path.get('path', []))}")
                    slice_lines.append(f"    Attacker controllable: {path.get('is_attacker_controllable', False)}")
                    slice_lines.append("")
            
            # Add sink details with context
            slice_lines.append("SINK LOCATIONS:")
            for i, sink in enumerate(sinks[:max_sinks_show]):  # Show configurable number of sinks
                line_num = sink["line"]
                slice_lines.append(f"  Sink {i+1} at line {line_num}:")
                slice_lines.append(f"    Function: {sink.get('function', 'unknown')}")
                slice_lines.append(f"    Variables: {', '.join(sink.get('variables', []))}")
                slice_lines.append("")
                
                # Add context around sink
                start = max(0, line_num - self.min_context_lines - 1)
                end = min(len(lines), line_num + self.min_context_lines)
                
                for j in range(start, end):
                    prefix = "→ " if j + 1 == line_num else "  "
                    slice_lines.append(f"{prefix}{j+1}: {lines[j]}")
                slice_lines.append("")
            
            # Add static analysis information if available
            if static_info.get("data_flows"):
                slice_lines.append("STATIC ANALYSIS SUMMARY:")
                slice_lines.append(f"  Data flows: {len(static_info.get('data_flows', []))}")
                slice_lines.append(f"  Call graph functions: {len(static_info.get('call_graph', {}).get('functions', []))}")
                slice_lines.append("")
            
            if slice_lines:
                slices_by_cwe[cwe] = "\n".join(slice_lines)
        
        return slices_by_cwe
    
    def _extract_suspicious_lines(self, lines: List[str], sinks_by_cwe: Dict[str, List[Dict]],
                                data_flow_paths_by_cwe: Dict[str, List[List[Dict]]]) -> Dict[str, List[Tuple[int, str]]]:
        """Extract suspicious lines for evidence scoring"""
        suspicious_lines = {}
        
        for cwe, sinks in sinks_by_cwe.items():
            suspicious_lines[cwe] = []
            for sink in sinks:
                line_num = sink["line"]
                suspicious_lines[cwe].append((line_num, lines[line_num - 1].strip()[:200]))
            
            # Also add source lines from data flow paths
            paths = data_flow_paths_by_cwe.get(cwe, [])
            for path in paths:
                if path.get("lines"):
                    for line_num in path["lines"]:
                        if 1 <= line_num <= len(lines):
                            suspicious_lines[cwe].append((line_num, lines[line_num - 1].strip()[:200]))
        
        return suspicious_lines
    
    def _extract_variable_info(self, line: str) -> List[str]:
        """Extract variable names from a line of code"""
        variables = []
        
        # Look for variable assignments
        assignments = self.assignment_pattern.findall(line)
        for var, _ in assignments:
            if var not in variables:
                variables.append(var)
        
        # Look for pointer dereferences
        pointers = self.pointer_deref_pattern.findall(line)
        for ptr in pointers:
            if ptr not in variables:
                variables.append(ptr)
        
        # Look for array accesses
        arrays = self.array_access_pattern.findall(line)
        for arr, _ in arrays:
            if arr not in variables:
                variables.append(arr)
        
        # Look for function arguments (simplified)
        if '(' in line and ')' in line:
            func_part = line.split('(', 1)[1].rsplit(')', 1)[0]
            # Simple tokenization
            tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', func_part)
            for token in tokens:
                if token not in variables and len(token) > 1:  # Skip very short tokens
                    variables.append(token)
        
        return variables[:10]  # Limit to 10 variables
    
    def _extract_function_name(self, line: str) -> str:
        """Extract function name from a line"""
        # Simple extraction: look for word before '('
        match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
        return match.group(1) if match else "unknown"
    
    def _get_context(self, lines: List[str], line_num: int, context_lines: int) -> List[str]:
        """Get context around a line"""
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return [f"{i+1}: {lines[i]}" for i in range(start, end)]
    
    def _extract_assignment_source(self, line: str, target_var: str) -> Dict[str, Any]:
        """Extract source information from an assignment"""
        # Simple pattern matching for now
        if '=' in line:
            parts = line.split('=', 1)
            if len(parts) == 2:
                source_expr = parts[1].strip().rstrip(';')
                # Extract variables from source expression
                source_vars = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', source_expr)
                return {
                    "expression": source_expr[:100],
                    "variables": source_vars[:5],
                    "variable": source_vars[0] if source_vars else "unknown"
                }
        return {}
    
    def _is_source_variable(self, variable: str) -> bool:
        """Check if a variable is likely to be attacker-controllable"""
        source_keywords = ['user', 'input', 'argv', 'buffer', 'msg', 'request', 'data', 'param']
        return any(keyword in variable.lower() for keyword in source_keywords)
    
    def _is_source_line(self, line: str) -> bool:
        """Check if a line contains source (attacker-controllable input)"""
        return bool(self.source_patterns.search(line))
    
    def _empty_result(self) -> Dict:
        """Return empty result structure"""
        return {
            "suspicious_count": 0,
            "slices_by_cwe": {},
            "code_slice": "",
            "suspicious_lines": {},
            "data_flow_paths": {},
            "sinks_by_cwe": {},
            "enhanced_analysis": True
        }
