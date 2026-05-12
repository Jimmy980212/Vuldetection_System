# joern_utils.py
import json
import os
import re
import subprocess
import uuid
from typing import Any, Dict, List

from config import JOERN_BAT, JOERN_EXPORT, JOERN_PARSE, TEMP_DIR


def _find_first_dot(export_out: str) -> str:
    dot_file = ""
    if os.path.exists(export_out):
        for fn in os.listdir(export_out):
            if fn.endswith(".dot"):
                dot_file = os.path.join(export_out, fn)
                break
    return dot_file


def _parse_and_export_c(code_file: str) -> Dict[str, Any]:
    """C/C++：joern-parse 目录输出 + joern-export。"""
    file_id = str(uuid.uuid4())[:8]
    parse_out = os.path.join(TEMP_DIR, f"cpg_{file_id}")
    export_out = os.path.join(TEMP_DIR, f"export_{file_id}")
    cpg_bin = os.path.join(TEMP_DIR, f"cpg_{file_id}.bin")

    print(f"   执行Joern解析: {os.path.basename(code_file)}")

    try:
        parse_cmd = [JOERN_PARSE, code_file, "--output", parse_out]
        subprocess.run(
            parse_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            shell=True,
        )
    except Exception as e:
        print(f"   Joern解析失败: {e}")

    try:
        export_cmd = [JOERN_EXPORT, "--repr=all", "--format=dot", parse_out, "--out", export_out]
        subprocess.run(
            export_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            shell=True,
        )
    except Exception as e:
        print(f"   Joern导出失败: {e}")

    dot_file = _find_first_dot(export_out)
    return {
        "parse_dir": parse_out,
        "export_dir": export_out,
        "dot_file": dot_file,
        "cpg_bin": cpg_bin if os.path.exists(cpg_bin) else "",
    }


def parse_c_workspace(c_source_root: str) -> Dict[str, Any]:
    """
    对整棵 C/C++ 源码目录执行 joern-parse + joern-export（便于多文件共享同一 CPG/DOT）。
    """
    c_root = os.path.abspath(c_source_root)
    if not os.path.isdir(c_root):
        print(f"C 工作区目录不存在: {c_root}")
        return {"parse_dir": "", "export_dir": "", "dot_file": "", "cpg_bin": ""}

    file_id = str(uuid.uuid4())[:8]
    parse_out = os.path.join(TEMP_DIR, f"cpg_cworkspace_{file_id}")
    export_out = os.path.join(TEMP_DIR, f"export_cworkspace_{file_id}")
    cpg_bin = os.path.join(TEMP_DIR, f"cpg_cworkspace_{file_id}.bin")

    print(f"   执行joern-parse(工作区目录): {c_root}")

    try:
        parse_cmd = [JOERN_PARSE, c_root, "--output", parse_out]
        subprocess.run(
            parse_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            shell=True,
        )
    except Exception as e:
        print(f"   joern-parse(工作区)失败: {e}")

    try:
        export_cmd = [JOERN_EXPORT, "--repr=all", "--format=dot", parse_out, "--out", export_out]
        subprocess.run(
            export_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            shell=True,
        )
    except Exception as e:
        print(f"   Joern导出(C 工作区)失败: {e}")

    dot_file = _find_first_dot(export_out)
    return {
        "parse_dir": parse_out,
        "export_dir": export_out,
        "dot_file": dot_file,
        "cpg_bin": cpg_bin if os.path.exists(cpg_bin) else "",
    }


def parse_and_export_unified(code_file: str) -> Dict[str, Any]:
    if not os.path.exists(code_file):
        print(f"文件不存在: {code_file}")
        return {"parse_dir": "", "export_dir": "", "dot_file": "", "cpg_bin": ""}
    return _parse_and_export_c(code_file)


class JoernHandler:
    """Joern静态分析工具封装 - 增强版"""

    def __init__(self):
        self.joern_parse = JOERN_PARSE
        self.joern_export = JOERN_EXPORT

    @staticmethod
    def run_joern_script(
        *,
        cpg_bin: str,
        script_path: str,
        params: Dict[str, str] | None = None,
        env: Dict[str, str] | None = None,
        timeout_s: int = 180,
    ) -> subprocess.CompletedProcess:
        exe = JOERN_BAT
        args = [exe, "--script", script_path]
        for k, v in (params or {}).items():
            args.extend(["--param", f"{k}={v}"])
        merged_env = os.environ.copy()
        merged_env.setdefault("PYTHONIOENCODING", "utf-8")
        if env:
            merged_env.update({str(k): str(v) for k, v in env.items()})
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=int(timeout_s),
            env=merged_env,
            shell=False,
        )

    def parse_and_export(self, code_file):
        return parse_and_export_unified(code_file)

    def extract_slices(self, dot_file):
        if not dot_file or not os.path.exists(dot_file):
            return []

        slices = []
        try:
            with open(dot_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            functions = re.findall(r'METHOD_FULL_NAME="([^"]+)"\s+NAME="([^"]+)"', content)
            calls = re.findall(r'label="CALL"[^]]*NAME="([^"]+)"', content)

            control_keywords = ['IF', 'ELSE', 'WHILE', 'FOR', 'SWITCH', 'RETURN']
            controls = []
            for keyword in control_keywords:
                keyword_matches = re.findall(rf'label="{keyword}[^"]*"[^]]*CODE="([^"]+)"', content)
                controls.extend([(keyword, match) for match in keyword_matches])

            for method_full_name, func_name in functions[:10]:
                slices.append({
                    "type": "function",
                    "name": func_name,
                    "content": f"{method_full_name} ({func_name})"
                })

            for call in calls[:15]:
                slices.append({
                    "type": "call",
                    "name": call,
                    "content": call
                })

            for ctrl_keyword, ctrl_code in controls[:10]:
                slices.append({
                    "type": "control",
                    "name": ctrl_keyword,
                    "content": ctrl_code[:100]
                })

        except Exception as e:
            print(f"   提取切片失败: {e}")

        return slices[:30]

    def extract_data_flow(self, dot_file):
        if not dot_file or not os.path.exists(dot_file):
            return []

        data_flows = []
        try:
            with open(dot_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            edges = re.findall(r'"(\d+)"\s*->\s*"(\d+)"', content)
            nodes = {}
            node_pattern = r'"(\d+)"\s*\[([^\]]+)\]'
            for match in re.finditer(node_pattern, content):
                node_id = match.group(1)
                node_attrs = match.group(2)

                name_match = re.search(r'NAME="([^"]+)"', node_attrs)
                if name_match:
                    nodes[node_id] = name_match.group(1)
                else:
                    label_match = re.search(r'label="([^"]+)"', node_attrs)
                    if label_match:
                        nodes[node_id] = label_match.group(1)[:50]
                    else:
                        code_match = re.search(r'CODE="([^"]+)"', node_attrs)
                        if code_match:
                            nodes[node_id] = f"CODE: {code_match.group(1)[:30]}"
                        else:
                            nodes[node_id] = f"node_{node_id}"

            for src, dst in edges[:50]:
                if src in nodes and dst in nodes:
                    data_flows.append({
                        "source": nodes[src][:50],
                        "target": nodes[dst][:50],
                        "source_id": src,
                        "target_id": dst
                    })
        except Exception as e:
            print(f"   提取数据流失败: {e}")

        return data_flows[:30]

    def extract_call_graph(self, dot_file):
        if not dot_file or not os.path.exists(dot_file):
            return {"functions": [], "calls": []}

        call_graph = {"functions": [], "calls": []}
        try:
            with open(dot_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            functions = re.findall(r'METHOD_FULL_NAME="([^"]+)"\s+NAME="([^"]+)"', content)
            unique_functions = set()
            for method_full_name, func_name in functions:
                unique_functions.add(func_name)
            call_graph["functions"] = list(unique_functions)[:20]

            call_edges = re.findall(r'"(\d+)"\s*->\s*"(\d+)"\s*\[[^\]]*label="[^"]*CALL[^"]*"[^\]]*\]', content)
            nodes = {}
            node_pattern = r'"(\d+)"\s*\[([^\]]+)\]'
            for match in re.finditer(node_pattern, content):
                node_id = match.group(1)
                node_attrs = match.group(2)

                name_match = re.search(r'NAME="([^"]+)"', node_attrs)
                if name_match:
                    nodes[node_id] = name_match.group(1)
                else:
                    label_match = re.search(r'label="([^"]+)"', node_attrs)
                    if label_match:
                        nodes[node_id] = label_match.group(1)[:50]
                    else:
                        nodes[node_id] = f"node_{node_id}"

            for src, dst in call_edges[:30]:
                if src in nodes and dst in nodes:
                    call_graph["calls"].append({
                        "caller": nodes[src][:50],
                        "callee": nodes[dst][:50],
                        "type": "CALL"
                    })
        except Exception as e:
            print(f"   提取调用图失败: {e}")

        return call_graph

    def extract_c_reachable_flows(
        self,
        *,
        cpg_bin: str,
        cwe: str,
        script_path: str,
        max_flows: int = 40,
        timeout_s: int = 300,
    ) -> List[Dict[str, Any]]:
        if not cpg_bin or not os.path.exists(cpg_bin):
            return []
        if not script_path or not os.path.exists(script_path):
            return []

        env = {
            "JOERN_CWE": str(cwe or ""),
            "JOERN_MAXFLOWS": str(int(max_flows)),
            "JOERN_DEBUG": "0",
            "PYTHONIOENCODING": "utf-8",
        }
        cp = self.run_joern_script(
            cpg_bin=cpg_bin,
            script_path=script_path,
            params={"cpgFile": cpg_bin},
            env=env,
            timeout_s=int(timeout_s),
        )
        out: List[Dict[str, Any]] = []
        for ln in (cp.stdout or "").splitlines():
            s = (ln or "").strip()
            if not s or not s.startswith("{"):
                continue
            try:
                out.append(json.loads(s))
            except Exception:
                continue
        return out

    def extract_cfg(self, dot_file: str) -> Dict[str, Any]:
        if not dot_file or not os.path.exists(dot_file):
            return {"nodes": [], "edges": [], "functions": []}

        nodes = []
        edges = []
        functions = set()

        try:
            with open(dot_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            node_pattern = r'"(\d+)"\s*\[([^\]]+)\]'
            for match in re.finditer(node_pattern, content):
                node_id = match.group(1)
                attrs = match.group(2)

                line = None
                code = ""
                code_match = re.search(r'CODE="([^"]+)"', attrs)
                if code_match:
                    code = code_match.group(1)[:200]
                    line_match = re.search(r'line\s*(\d+)', code, re.IGNORECASE)
                    if line_match:
                        line = int(line_match.group(1))

                func_match = re.search(r'METHOD_FULL_NAME="([^"]+)"', attrs)
                if func_match:
                    full_name = func_match.group(1)
                    func_name = full_name.split('.')[-1].split('(')[0]
                    functions.add(func_name)

                nodes.append({
                    "id": node_id,
                    "code": code,
                    "line": line
                })

            edge_pattern = r'"(\d+)"\s*->\s*"(\d+)"(?:\s*\[([^\]]*)\])?'
            for match in re.finditer(edge_pattern, content):
                src = match.group(1)
                dst = match.group(2)
                attrs = match.group(3) or ""
                if "CFG" in attrs or not attrs:
                    edges.append({"from": src, "to": dst})

            functions = list(functions)

            return {
                "nodes": nodes,
                "edges": edges,
                "functions": functions
            }
        except Exception as e:
            print(f"   提取CFG失败: {e}")
            return {"nodes": [], "edges": [], "functions": []}
