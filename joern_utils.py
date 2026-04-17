import json
import os
import re
import subprocess
import uuid
from typing import Any, Dict, List

from config import JOERN_BAT, JOERN_EXPORT, JOERN_PARSE, TEMP_DIR


def _find_first_dot(export_out: str) -> str:
    if not os.path.exists(export_out):
        return ""
    for fn in os.listdir(export_out):
        if fn.endswith(".dot"):
            return os.path.join(export_out, fn)
    return ""


def _parse_and_export_c(code_file: str) -> Dict[str, Any]:
    file_id = str(uuid.uuid4())[:8]
    parse_out = os.path.join(TEMP_DIR, f"cpg_{file_id}")
    export_out = os.path.join(TEMP_DIR, f"export_{file_id}")
    cpg_bin = os.path.join(TEMP_DIR, f"cpg_{file_id}.bin")

    print(f"   执行Joern解析: {os.path.basename(code_file)}")

    try:
        subprocess.run(
            [JOERN_PARSE, code_file, "--output", parse_out],
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
        subprocess.run(
            [JOERN_EXPORT, "--repr=all", "--format=dot", parse_out, "--out", export_out],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            shell=True,
        )
    except Exception as e:
        print(f"   Joern导出失败: {e}")

    return {
        "parse_dir": parse_out,
        "export_dir": export_out,
        "dot_file": _find_first_dot(export_out),
        "cpg_bin": cpg_bin if os.path.exists(cpg_bin) else "",
    }


def parse_c_workspace(c_source_root: str) -> Dict[str, Any]:
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
        subprocess.run(
            [JOERN_PARSE, c_root, "--output", parse_out],
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
        subprocess.run(
            [JOERN_EXPORT, "--repr=all", "--format=dot", parse_out, "--out", export_out],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            shell=True,
        )
    except Exception as e:
        print(f"   Joern导出(C 工作区)失败: {e}")

    return {
        "parse_dir": parse_out,
        "export_dir": export_out,
        "dot_file": _find_first_dot(export_out),
        "cpg_bin": cpg_bin if os.path.exists(cpg_bin) else "",
    }


class JoernHandler:
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
        args = [JOERN_BAT, "--script", script_path]
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
        if not os.path.exists(code_file):
            print(f"文件不存在: {code_file}")
            return {"parse_dir": "", "export_dir": "", "dot_file": "", "cpg_bin": ""}
        return _parse_and_export_c(code_file)

    def extract_slices(self, dot_file):
        if not dot_file or not os.path.exists(dot_file):
            return []
        slices = []
        try:
            with open(dot_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            functions = re.findall(r'METHOD_FULL_NAME="([^"]+)"\s+NAME="([^"]+)"', content)
            calls = re.findall(r'label="CALL"[^]]*NAME="([^"]+)"', content)
            controls = []
            for kw in ["IF", "ELSE", "WHILE", "FOR", "SWITCH", "RETURN"]:
                controls.extend([(kw, m) for m in re.findall(rf'label="{kw}[^"]*"[^]]*CODE="([^"]+)"', content)])
            for method_full_name, func_name in functions[:10]:
                slices.append({"type": "function", "name": func_name, "content": f"{method_full_name} ({func_name})"})
            for call in calls[:15]:
                slices.append({"type": "call", "name": call, "content": call})
            for kw, code in controls[:10]:
                slices.append({"type": "control", "name": kw, "content": code[:100]})
        except Exception as e:
            print(f"   提取切片失败: {e}")
        return slices[:30]

    def extract_data_flow(self, dot_file):
        if not dot_file or not os.path.exists(dot_file):
            return []
        data_flows = []
        try:
            with open(dot_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            edges = re.findall(r'"(\d+)"\s*->\s*"(\d+)"', content)
            nodes = {}
            for match in re.finditer(r'"(\d+)"\s*\[([^\]]+)\]', content):
                node_id = match.group(1)
                attrs = match.group(2)
                name = re.search(r'NAME="([^"]+)"', attrs)
                if name:
                    nodes[node_id] = name.group(1)
                else:
                    label = re.search(r'label="([^"]+)"', attrs)
                    nodes[node_id] = (label.group(1) if label else f"node_{node_id}")[:50]
            for src, dst in edges[:50]:
                if src in nodes and dst in nodes:
                    data_flows.append({"source": nodes[src][:50], "target": nodes[dst][:50], "source_id": src, "target_id": dst})
        except Exception as e:
            print(f"   提取数据流失败: {e}")
        return data_flows[:30]

    def extract_call_graph(self, dot_file):
        if not dot_file or not os.path.exists(dot_file):
            return {"functions": [], "calls": []}
        call_graph = {"functions": [], "calls": []}
        try:
            with open(dot_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            functions = re.findall(r'METHOD_FULL_NAME="([^"]+)"\s+NAME="([^"]+)"', content)
            call_graph["functions"] = list({func_name for _, func_name in functions})[:20]
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
            if s.startswith("{"):
                try:
                    out.append(json.loads(s))
                except Exception:
                    pass
        return out
