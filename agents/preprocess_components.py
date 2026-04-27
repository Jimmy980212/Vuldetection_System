import json
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class CppcheckScanner:
    """Run cppcheck and parse xml via injected callback."""

    DEFAULT_MACROS = [
        "FUNC",
        "NELEMS",
        "FF_API_CODEC_PROPS",
        "FF_API_AVCODEC_RESAMPLE",
        "FF_ENABLE_DEPRECATION_WARNINGS",
        "FF_DISABLE_DEPRECATION_WARNINGS",
        "av_unused",
        "av_always_inline",
        "av_const",
        "FF_API_UNSIGNED_CHARS",
        "FF_API_LOPT",
        "FF_API_CARDINAL_ERRORS",
    ]

    def __init__(
        self,
        cppcheck_path: str,
        parse_xml_callback: Callable[[str], List[Any]],
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        extra_defines: Optional[List[str]] = None,
    ):
        self.cppcheck_path = cppcheck_path
        self.parse_xml_callback = parse_xml_callback
        self.runner = runner
        self.extra_defines = extra_defines or []

    def scan(self, project_path: str, enable_all: bool = True) -> Tuple[List[Any], int]:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".xml",
            prefix="cppcheck_result_",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            xml_output = tmp.name

        cmd = [
            self.cppcheck_path,
            "--xml",
            f"--output-file={xml_output}",
            "--force",
            "--inconclusive",
            "--quiet",
            project_path,
        ]

        all_defines = self.DEFAULT_MACROS + self.extra_defines
        for macro in all_defines:
            cmd.extend(["-D", macro])

        if enable_all:
            cmd.insert(-2, "--enable=all")

        print(f"[PreprocessAgent] Running command: {' '.join(cmd)}")
        result = self.runner(cmd, capture_output=True, text=True)
        alerts = self.parse_xml_callback(xml_output)

        if os.path.exists(xml_output):
            os.remove(xml_output)
        return alerts, int(getattr(result, "returncode", 0) or 0)


class CppcheckXmlParser:
    """Parse cppcheck XML and build RawAlert objects by factory."""

    def __init__(self, alert_factory: Callable[..., Any]):
        self.alert_factory = alert_factory

    def parse(self, xml_path: str) -> List[Any]:
        alerts: List[Any] = []
        if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
            return alerts

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for error in root.findall(".//error"):
                msg = error.get("msg", "No message")
                severity = error.get("severity", "unknown")
                for location in error.findall("location"):
                    file_path = location.get("file", "unknown")
                    line = int(location.get("line", 0) or 0)
                    func = location.get("function", "unknown")
                    alerts.append(
                        self.alert_factory(
                            file=file_path,
                            line=line,
                            func=func,
                            msg=msg,
                            severity=severity,
                            tool="cppcheck",
                        )
                    )
        except ET.ParseError as exc:
            print(f"[PreprocessAgent] XML parse failed: {exc}")

        return alerts


class AlertDeduplicator:
    @staticmethod
    def _severity_rank(level: str) -> int:
        mapping = {
            "error": 4,
            "warning": 3,
            "style": 2,
            "information": 1,
            "unknown": 0,
        }
        return mapping.get((level or "").lower(), 0)

    @staticmethod
    def _merge_tool_names(left: str, right: str) -> str:
        left_items = {item.strip() for item in (left or "").split("+") if item.strip()}
        right_items = {item.strip() for item in (right or "").split("+") if item.strip()}
        merged = sorted(left_items.union(right_items))
        return "+".join(merged) if merged else "unknown"

    @staticmethod
    def _infer_family_from_msg(msg: str) -> str:
        text = (msg or "").lower()
        families = {
            "buffer_overflow": ["overflow", "strcpy", "strcat", "sprintf", "gets", "memcpy"],
            "command_injection": ["command-injection", "command injection", "system(", "exec", "popen"],
            "tainted_input": ["tainted", "scanf", "recv", "gets", "fgets"],
            "use_after_free": ["use-after-free", "use after free", "uaf", "dangling", "deallocated", "released"],
            "double_free": ["double-free", "double free", "freed twice", "freed again"],
            "out_of_bounds": [
                "out-of-bounds",
                "out of bounds",
                "oob",
                "overread",
                "overwrite",
                "bounds guard",
                "array index",
            ],
            "format_string": ["format-string", "format string", "printf("],
            "null_pointer": ["null pointer", "null-pointer", "nullptr", "null dereference", "null-deref"],
            "memory_leak": ["memory leak", "leak"],
        }
        for family, keywords in families.items():
            if any(keyword in text for keyword in keywords):
                return family
        return "generic"

    def _alert_fingerprint(self, alert: Any) -> Tuple[str, int, str]:
        return (
            os.path.normcase(os.path.normpath(str(getattr(alert, "file", "")))),
            int(getattr(alert, "line", 0) or 0),
            self._infer_family_from_msg(str(getattr(alert, "msg", ""))),
        )

    def deduplicate(self, alerts: List[Any]) -> List[Any]:
        merged: Dict[Tuple[str, int, str], Any] = {}
        for alert in alerts:
            fp = self._alert_fingerprint(alert)
            existing = merged.get(fp)
            if existing is None:
                merged[fp] = alert
                continue

            existing.tool = self._merge_tool_names(getattr(existing, "tool", ""), getattr(alert, "tool", ""))
            if self._severity_rank(getattr(alert, "severity", "")) > self._severity_rank(
                getattr(existing, "severity", "")
            ):
                existing.severity = getattr(alert, "severity", "unknown")

            if getattr(alert, "msg", "") and getattr(alert, "msg", "") not in getattr(existing, "msg", ""):
                existing.msg = f"{getattr(existing, 'msg', '')} | {getattr(alert, 'msg', '')}"
            if getattr(existing, "func", "unknown") in ("unknown", "") and getattr(alert, "func", "") not in (
                "unknown",
                "",
            ):
                existing.func = getattr(alert, "func", "unknown")

        return list(merged.values())


class AlertNormalizer:
    @staticmethod
    def resolve_alert_file(file_path: str, project_path: str, project_files: List[str]) -> str:
        if not file_path:
            return file_path
        if "<" in file_path and ">" in file_path:
            return file_path

        if file_path and os.path.exists(file_path):
            return os.path.abspath(file_path)

        base = project_path if os.path.isdir(project_path) else os.path.dirname(project_path)
        candidate = os.path.abspath(os.path.join(base, file_path))
        if os.path.exists(candidate):
            return candidate

        filename = os.path.basename(file_path or "")
        if filename:
            matches = [path for path in project_files if os.path.basename(path) == filename]
            if len(matches) == 1:
                return matches[0]

        return os.path.abspath(file_path) if file_path else file_path

    @staticmethod
    def list_source_files(path: str) -> List[str]:
        src_ext = (".c", ".cpp", ".cxx", ".cc", ".h", ".hpp")
        files: List[str] = []

        if os.path.isfile(path):
            if path.endswith(src_ext):
                files.append(os.path.abspath(path))
            return files

        for root, _, filenames in os.walk(path):
            for filename in filenames:
                if filename.endswith(src_ext):
                    files.append(os.path.abspath(os.path.join(root, filename)))
        return files


class ProgramSliceBuilder:
    DEFAULT_MAX_PROMPT_TOKENS = 3600
    MIN_PROMPT_TOKENS = 2000
    MAX_PROMPT_TOKENS = 4000
    MAX_PROMPT_CONTEXT_TOKENS = 900
    MAX_CODE_TOKENS = 1800

    def __init__(self):
        self._file_cache: Dict[str, List[str]] = {}

    @staticmethod
    def empty_program_slice(line_num: int = 0) -> Dict[str, Any]:
        line = int(line_num or 0)
        return {
            "source_lines": [],
            "sink_lines": [line] if line else [],
            "slice_lines": [line] if line else [],
            "sliced_code": "",
            "control_flow": {},
            "slice_quality": "low",
            "evidence_package": {
                "version": "source_sink_evidence.v1",
                "source_sink_paths": [],
                "key_variables": [],
                "control_conditions": [],
                "sanitizers": [],
                "memory_events": [],
                "dangerous_calls": [],
                "notes": ["No source-sink evidence available."],
            },
            "prompt_context": "",
            "token_budget": {
                "max_prompt_tokens": ProgramSliceBuilder.DEFAULT_MAX_PROMPT_TOKENS,
                "estimated_context_tokens": 0,
                "estimated_code_tokens": 0,
            },
        }

    def read_file_lines(self, file_path: str) -> List[str]:
        abs_path = os.path.abspath(file_path)
        if abs_path in self._file_cache:
            return self._file_cache[abs_path]
        if not os.path.exists(abs_path):
            return []
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            self._file_cache[abs_path] = lines
            return lines
        except Exception as exc:
            print(f"[PreprocessAgent] Failed to read file: {abs_path}, {exc}")
            return []

    def find_function_bounds(self, lines: List[str], line_num: int, window: int = 120) -> Tuple[int, int]:
        if not lines:
            return 0, -1
        idx = min(max(line_num - 1, 0), len(lines) - 1)

        func_start = None
        func_decl = re.compile(r"^\s*[\w\*\s]+?\s+[\w:~]+\s*\([^;]*\)\s*(\{|$)")
        excluded_prefix = ("if", "for", "while", "switch", "catch")
        for i in range(idx, -1, -1):
            stripped = lines[i].strip()
            if not stripped:
                continue
            if stripped.startswith(excluded_prefix):
                continue
            if func_decl.match(stripped) and ";" not in stripped:
                func_start = i
                break
            if stripped.endswith("{") and i >= idx - window:
                func_start = i
                break

        if func_start is None:
            return max(0, idx - window), min(len(lines) - 1, idx + window)

        brace_balance = 0
        entered = False
        func_end = len(lines) - 1
        for j in range(func_start, len(lines)):
            line = lines[j]
            if "{" in line:
                entered = True
            brace_balance += line.count("{")
            brace_balance -= line.count("}")
            if entered and brace_balance <= 0:
                func_end = j
                break

        if idx > func_end:
            return max(0, idx - window), min(len(lines) - 1, idx + window)
        return func_start, func_end

    def identify_source_sink_paths(
        self,
        lines: List[str],
        line_num: int,
        start: int,
        end: int,
    ) -> Tuple[Set[int], Set[int]]:
        source_lines: Set[int] = set()
        sink_lines: Set[int] = set()

        sink_patterns = [
            r"\bstrcpy\s*\(",
            r"\bstrcat\s*\(",
            r"\bsprintf\s*\(",
            r"\bmemcpy\s*\(",
            r"\bgets\s*\(",
            r"\bscanf\s*\(",
            r"\bsystem\s*\(",
            r"\bexec\w*\s*\(",
            r"\bprintf\s*\([^,\)]*\)",
        ]
        source_patterns = [
            r"\bgets\s*\(",
            r"\bscanf\s*\(",
            r"\bfgets\s*\(",
            r"\bread\s*\(",
            r"\brecv\s*\(",
            r"\bgetenv\s*\(",
            r"\bargv\s*\[",
        ]

        sink_lines.add(line_num)
        for i in range(start, min(end + 1, len(lines))):
            text = lines[i]
            stripped = text.strip()
            if not stripped or stripped.startswith("//"):
                continue
            for pattern in source_patterns:
                if re.search(pattern, text):
                    source_lines.add(i + 1)
                    break
            for pattern in sink_patterns:
                if re.search(pattern, text):
                    sink_lines.add(i + 1)
                    break
        return source_lines, sink_lines

    def build_control_flow(self, lines: List[str], start: int, end: int) -> Dict[int, Set[int]]:
        control_flow: Dict[int, Set[int]] = {}
        if not lines or end < start:
            return control_flow

        for i in range(start, end + 1):
            current = i + 1
            control_flow[current] = set()
            stripped = lines[i].strip()

            if re.match(r"^(return|throw)\b", stripped):
                continue

            if i < end:
                control_flow[current].add(current + 1)

            if re.search(r"\b(if|for|while|switch)\s*\(", stripped):
                fallthrough = self.find_block_fallthrough(lines, i, end)
                if fallthrough is not None:
                    control_flow[current].add(fallthrough)
        return control_flow

    @staticmethod
    def find_block_fallthrough(lines: List[str], current_idx: int, end_idx: int) -> Optional[int]:
        line = lines[current_idx]
        if "{" not in line:
            target = current_idx + 2
            if target <= end_idx + 1:
                return target
            return None

        brace_balance = 0
        for j in range(current_idx, end_idx + 1):
            brace_balance += lines[j].count("{")
            brace_balance -= lines[j].count("}")
            if j > current_idx and brace_balance <= 0:
                target = j + 2
                if target <= end_idx + 1:
                    return target
                return None
        return None

    @staticmethod
    def build_predecessor_map(control_flow: Dict[int, Set[int]]) -> Dict[int, Set[int]]:
        predecessor: Dict[int, Set[int]] = {line: set() for line in control_flow.keys()}
        for src, dsts in control_flow.items():
            for dst in dsts:
                predecessor.setdefault(dst, set()).add(src)
        return predecessor

    def backward_slice(
        self,
        control_flow: Dict[int, Set[int]],
        sink_line: int,
        source_lines: Set[int],
        max_nodes: int = 180,
    ) -> Set[int]:
        if not control_flow:
            return {sink_line}

        predecessor = self.build_predecessor_map(control_flow)
        worklist = [sink_line]
        slice_lines: Set[int] = set()

        while worklist and len(slice_lines) < max_nodes:
            current = worklist.pop()
            if current in slice_lines:
                continue
            slice_lines.add(current)
            for prev in predecessor.get(current, set()):
                if prev not in slice_lines:
                    worklist.append(prev)

        for src in sorted(source_lines):
            if src <= sink_line and sink_line - src <= 220:
                slice_lines.add(src)

        for offset in range(-2, 3):
            ln = sink_line + offset
            if ln in control_flow:
                slice_lines.add(ln)
        return slice_lines

    @staticmethod
    def extract_slice_code(lines: List[str], slice_lines: Set[int]) -> str:
        if not lines or not slice_lines:
            return ""
        content = []
        for line_num in sorted(slice_lines):
            if 1 <= line_num <= len(lines):
                content.append(f"=> {line_num}: {lines[line_num - 1].rstrip()}")
        return "\n".join(content)

    @staticmethod
    def estimate_tokens(text: str) -> int:
        return max(1, (len(str(text or "")) + 3) // 4)

    @staticmethod
    def _token_budget_from_env() -> int:
        try:
            raw_value = int(os.getenv("VULDET_MAX_PROMPT_TOKENS", str(ProgramSliceBuilder.DEFAULT_MAX_PROMPT_TOKENS)))
        except (TypeError, ValueError):
            raw_value = ProgramSliceBuilder.DEFAULT_MAX_PROMPT_TOKENS
        return max(ProgramSliceBuilder.MIN_PROMPT_TOKENS, min(ProgramSliceBuilder.MAX_PROMPT_TOKENS, raw_value))

    @staticmethod
    def _line_entry(lines: List[str], line_num: int) -> Dict[str, Any]:
        code = ""
        if 1 <= line_num <= len(lines):
            code = lines[line_num - 1].strip()
        return {"line": int(line_num), "code": code}

    @staticmethod
    def _sanitize_code(code: str) -> str:
        return re.sub(r"\s+", " ", str(code or "").strip())[:240]

    @staticmethod
    def _extract_identifiers(text: str, limit: int = 12) -> List[str]:
        keywords = {
            "if",
            "for",
            "while",
            "return",
            "sizeof",
            "NULL",
            "nullptr",
            "int",
            "char",
            "void",
            "const",
            "struct",
            "free",
            "malloc",
            "memcpy",
            "strcpy",
            "sprintf",
            "use",
            "after",
            "before",
            "freed",
            "free",
            "used",
            "line",
            "source",
            "sink",
            "at",
            "and",
        }
        identifiers: List[str] = []
        for item in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text or ""):
            if item in keywords or item.lower() in keywords or item.upper() in keywords:
                continue
            if len(item) == 1 and item.isupper():
                continue
            if item not in identifiers:
                identifiers.append(item)
            if len(identifiers) >= limit:
                break
        return identifiers

    @staticmethod
    def _infer_function_name(lines: List[str], start: int) -> str:
        if not lines or start < 0 or start >= len(lines):
            return "unknown"
        for idx in range(start, max(-1, start - 6), -1):
            text = lines[idx].strip()
            match = re.search(r"([A-Za-z_][A-Za-z0-9_:~]*)\s*\([^;]*\)\s*(?:\{|$)", text)
            if match and not text.startswith(("if", "for", "while", "switch", "catch")):
                return match.group(1)
        return "unknown"

    @staticmethod
    def _collect_matching_lines(
        lines: List[str],
        start: int,
        end: int,
        patterns: List[str],
        identifiers: Optional[List[str]] = None,
        limit: int = 14,
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        identifiers = identifiers or []
        for idx in range(start, min(end + 1, len(lines))):
            text = lines[idx]
            lowered = text.lower()
            if not text.strip():
                continue
            pattern_hit = any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)
            identifier_hit = bool(identifiers) and any(re.search(rf"\b{re.escape(name)}\b", text) for name in identifiers)
            if pattern_hit and (not identifiers or identifier_hit or len(items) < 4):
                items.append({"line": idx + 1, "code": ProgramSliceBuilder._sanitize_code(text)})
            if len(items) >= limit:
                break
        return items

    @staticmethod
    def _render_budgeted_code(lines: List[str], important_lines: Set[int], max_tokens: int) -> str:
        if not lines or not important_lines:
            return ""

        expanded: Set[int] = set()
        for line_num in important_lines:
            for offset in range(-1, 2):
                candidate = int(line_num) + offset
                if 1 <= candidate <= len(lines):
                    expanded.add(candidate)

        content: List[str] = []
        previous = None
        for line_num in sorted(expanded):
            if previous is not None and line_num > previous + 1:
                content.append("...")
            content.append(f"=> {line_num}: {lines[line_num - 1].rstrip()}")
            previous = line_num
            if ProgramSliceBuilder.estimate_tokens("\n".join(content)) >= max_tokens:
                content.append("... [code truncated by token budget]")
                break
        return "\n".join(content)

    def _build_evidence_package(
        self,
        lines: List[str],
        start: int,
        end: int,
        line_num: int,
        alert_msg: str,
        source_lines: Set[int],
        sink_lines: Set[int],
        slice_lines: Set[int],
    ) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        max_prompt_tokens = self._token_budget_from_env()
        function_name = self._infer_function_name(lines, start)
        sink_text = lines[line_num - 1] if 1 <= line_num <= len(lines) else ""
        identifier_text = "\n".join([alert_msg or "", sink_text] + [lines[i - 1] for i in sorted(source_lines) if 1 <= i <= len(lines)])
        identifiers = self._extract_identifiers(identifier_text)

        control_conditions = self._collect_matching_lines(
            lines,
            start,
            end,
            [r"\bif\s*\(", r"\bfor\s*\(", r"\bwhile\s*\(", r"\bswitch\s*\(", r"\breturn\b"],
            identifiers=identifiers,
            limit=14,
        )
        sanitizers = self._collect_matching_lines(
            lines,
            start,
            end,
            [
                r"\bassert\s*\(",
                r"\bav_assert",
                r"\bsizeof\b",
                r"\bARRAY_SIZE\b",
                r"\bFF_ARRAY_ELEMS\b",
                r"\bstrn",
                r"\bsnprintf\s*\(",
                r"\bchecked",
                r"\bclamp",
                r"!=\s*NULL",
                r"!=\s*nullptr",
            ],
            identifiers=identifiers,
            limit=12,
        )
        memory_events = self._collect_matching_lines(
            lines,
            start,
            end,
            [r"\bmalloc\s*\(", r"\bcalloc\s*\(", r"\brealloc\s*\(", r"\bfree\s*\(", r"\bdelete\b", r"\bNULL\b", r"\bnullptr\b"],
            identifiers=identifiers,
            limit=12,
        )
        dangerous_calls = self._collect_matching_lines(
            lines,
            start,
            end,
            [
                r"\bstrcpy\s*\(",
                r"\bstrcat\s*\(",
                r"\bsprintf\s*\(",
                r"\bgets\s*\(",
                r"\bmemcpy\s*\(",
                r"\bmemmove\s*\(",
                r"\brecv\s*\(",
                r"\bread\s*\(",
                r"\bsystem\s*\(",
                r"->",
                r"\[[^\]]+\]",
            ],
            identifiers=identifiers,
            limit=16,
        )

        important_lines: Set[int] = set(slice_lines)
        important_lines.update(source_lines)
        important_lines.update(sink_lines)
        for item in control_conditions + sanitizers + memory_events + dangerous_calls:
            important_lines.add(int(item.get("line", 0) or 0))

        source_sink_paths: List[Dict[str, Any]] = []
        sinks = sorted(sink_lines or {line_num})
        sources = sorted(source_lines)
        if not sources:
            sources = [max(start + 1, min(line_num, end + 1))]
        for sink in sinks[:4]:
            nearest_source = max([src for src in sources if src <= sink] or [sources[0]])
            path_lines = sorted(ln for ln in important_lines if min(nearest_source, sink) <= ln <= max(nearest_source, sink))[:80]
            source_sink_paths.append(
                {
                    "source_line": int(nearest_source),
                    "sink_line": int(sink),
                    "path_lines": path_lines,
                    "variables": identifiers[:8],
                    "source": self._line_entry(lines, nearest_source),
                    "sink": self._line_entry(lines, sink),
                }
            )

        code_excerpt = self._render_budgeted_code(lines, important_lines, max_tokens=self.MAX_CODE_TOKENS)
        evidence_package = {
            "version": "source_sink_evidence.v1",
            "function": {
                "name": function_name,
                "start_line": start + 1,
                "end_line": end + 1,
            },
            "alert_line": int(line_num),
            "key_variables": identifiers[:12],
            "source_lines": sorted(source_lines),
            "sink_lines": sorted(sink_lines),
            "source_sink_paths": source_sink_paths,
            "control_conditions": control_conditions,
            "sanitizers": sanitizers,
            "memory_events": memory_events,
            "dangerous_calls": dangerous_calls,
            "notes": [
                "Evidence is intraprocedural unless call-chain data is present.",
                "Absence of sanitizer entries is evidence to review, not proof by itself.",
            ],
        }

        prompt_context_raw = {
            "source_sink_evidence": evidence_package,
            "code_excerpt": code_excerpt,
        }
        prompt_context = json.dumps(prompt_context_raw, ensure_ascii=False, indent=2)
        if self.estimate_tokens(prompt_context) > self.MAX_PROMPT_CONTEXT_TOKENS:
            compact = dict(prompt_context_raw)
            compact["code_excerpt"] = self._render_budgeted_code(lines, important_lines, max_tokens=520)
            evidence_compact = dict(evidence_package)
            evidence_compact["control_conditions"] = control_conditions[:8]
            evidence_compact["sanitizers"] = sanitizers[:8]
            evidence_compact["memory_events"] = memory_events[:8]
            evidence_compact["dangerous_calls"] = dangerous_calls[:10]
            compact["source_sink_evidence"] = evidence_compact
            prompt_context = json.dumps(compact, ensure_ascii=False, indent=2)

        token_budget = {
            "max_prompt_tokens": max_prompt_tokens,
            "target_prompt_tokens": min(3400, max_prompt_tokens),
            "estimated_context_tokens": self.estimate_tokens(prompt_context),
            "estimated_code_tokens": self.estimate_tokens(code_excerpt),
            "code_excerpt_token_cap": self.MAX_CODE_TOKENS,
        }
        return evidence_package, prompt_context, token_budget

    def compute_program_slice(self, file_path: str, line_num: int, alert_msg: str) -> Dict[str, Any]:
        lines = self.read_file_lines(file_path)
        if not lines:
            return self.empty_program_slice(line_num)

        start, end = self.find_function_bounds(lines, line_num)
        source_lines, sink_lines = self.identify_source_sink_paths(lines, line_num, start, end)
        control_flow = self.build_control_flow(lines, start, end)
        slice_lines = self.backward_slice(control_flow, line_num, source_lines)
        evidence_package, prompt_context, token_budget = self._build_evidence_package(
            lines=lines,
            start=start,
            end=end,
            line_num=line_num,
            alert_msg=alert_msg,
            source_lines=source_lines,
            sink_lines=sink_lines,
            slice_lines=slice_lines,
        )
        context_payload = json.loads(prompt_context)
        sliced_code = context_payload.get("code_excerpt") or self.extract_slice_code(lines, slice_lines)

        quality = "low"
        if len(slice_lines) <= 8:
            quality = "high"
        elif len(slice_lines) <= 28:
            quality = "medium"

        serializable_control_flow = {line: sorted(list(next_lines)) for line, next_lines in control_flow.items()}
        return {
            "source_lines": sorted(list(source_lines)),
            "sink_lines": sorted(list(sink_lines)),
            "slice_lines": sorted(list(slice_lines)),
            "sliced_code": sliced_code,
            "control_flow": serializable_control_flow,
            "slice_quality": quality,
            "evidence_package": evidence_package,
            "prompt_context": prompt_context,
            "token_budget": token_budget,
        }
