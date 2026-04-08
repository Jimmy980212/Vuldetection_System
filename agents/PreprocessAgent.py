# agents/PreprocessAgent.py
import json
import locale
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from agents.preprocess_components import (
    AlertDeduplicator,
    AlertNormalizer,
    CppcheckScanner,
    CppcheckXmlParser,
    ProgramSliceBuilder,
)
from core.base import BaseAgent
from utils.structured_logging import get_logger, log_event


LOGGER = get_logger("vuldetection.preprocess")


@dataclass
class RawAlert:
    alert_id: str
    file: str
    line: int
    func: str
    msg: str
    severity: str
    tool: str = "cppcheck"


class JoernAnalyzer:
    """Execute Joern over WSL and extract candidate security alerts."""

    def __init__(self, wsl_distro: str = None):
        self.wsl_distro = wsl_distro or ""
        self.cpg_output_dir: Optional[str] = None
        self.default_rules_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "joern_rules.json"
        )
        self.last_status: Dict[str, Any] = {
            "available": False,
            "executed": False,
            "status": "unknown",
            "error": "",
            "alerts": 0,
        }

    @staticmethod
    def _windows_to_wsl_path(windows_path: str) -> str:
        abs_path = os.path.abspath(windows_path)
        if len(abs_path) > 1 and abs_path[1] == ":":
            drive = abs_path[0].lower()
            rest = abs_path[2:].replace("\\", "/")
            return f"/mnt/{drive}{rest}"
        return abs_path.replace("\\", "/")

    @staticmethod
    def _wsl_to_windows_path(path: str) -> str:
        text = (path or "").strip()
        if text.startswith("/mnt/") and len(text) > 7:
            drive = text[5]
            rest = text[6:].replace("/", "\\")
            return f"{drive.upper()}:{rest}"
        return text

    @staticmethod
    def _decode_process_output(data: bytes | str | None) -> str:
        if data is None:
            return ""
        if isinstance(data, str):
            return data
        for enc in ("utf-8", "utf-16le", "utf-16", locale.getpreferredencoding(False) or "utf-8", "gbk", "cp936"):
            try:
                return data.decode(enc)
            except Exception:
                continue
        return data.decode("utf-8", errors="replace")

    @classmethod
    def _run_process(cls, cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
        raw = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout)
        return subprocess.CompletedProcess(
            args=raw.args,
            returncode=raw.returncode,
            stdout=cls._decode_process_output(raw.stdout),
            stderr=cls._decode_process_output(raw.stderr),
        )

    @staticmethod
    def _looks_like_wsl_access_issue(result: subprocess.CompletedProcess) -> bool:
        code = int(getattr(result, "returncode", 0) or 0)
        text = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}".lower()
        if code in {-1, 4294967295}:
            return True
        markers = ("e_accessdenied", "createinstance", "access denied", "拒绝访问")
        return any(marker in text for marker in markers)

    @staticmethod
    def _extract_command_error(result: subprocess.CompletedProcess) -> str:
        stdout = str(getattr(result, "stdout", "") or "").strip()
        stderr = str(getattr(result, "stderr", "") or "").strip()
        if stderr:
            return stderr
        if stdout:
            return stdout
        code = int(getattr(result, "returncode", 0) or 0)
        return f"command_failed(returncode={code})"

    def _run_wsl_command(self, cmd: List[str], timeout: int = 3600) -> subprocess.CompletedProcess:
        full_cmd = ["wsl"]
        if self.wsl_distro:
            full_cmd.extend(["-d", self.wsl_distro])
        full_cmd.extend(cmd)

        candidates: List[List[str]] = [full_cmd]
        system_wsl = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32", "wsl.exe")
        if os.path.exists(system_wsl):
            alt = [system_wsl] + full_cmd[1:]
            if alt not in candidates:
                candidates.append(alt)

        last_result: Optional[subprocess.CompletedProcess] = None
        for candidate in candidates:
            print(f"[JoernAnalyzer] Running: {' '.join(candidate)}")
            result = self._run_process(candidate, timeout=timeout)
            if int(result.returncode or 0) == 0:
                return result
            last_result = result
            if not self._looks_like_wsl_access_issue(result):
                return result

        if last_result is not None:
            return last_result
        return subprocess.CompletedProcess(args=full_cmd, returncode=1, stdout="", stderr="Failed to run WSL command.")

    def check_joern_available(self) -> bool:
        self.last_status = {
            "available": False,
            "executed": False,
            "status": "checking",
            "error": "",
            "alerts": 0,
        }
        try:
            check = self._run_wsl_command(
                [
                    "bash",
                    "-lc",
                    "command -v joern-parse >/dev/null 2>&1 && command -v joern >/dev/null 2>&1",
                ],
                timeout=60,
            )
            available = int(check.returncode or 0) == 0
            self.last_status["available"] = available
            self.last_status["status"] = "available" if available else "not_available"
            if not available:
                self.last_status["error"] = self._extract_command_error(check)
            return available
        except Exception as exc:
            self.last_status["status"] = "check_failed"
            self.last_status["error"] = str(exc)
            return False

    def parse_project(self, project_path: str, output_dir: Optional[str] = None) -> Optional[str]:
        wsl_path = self._windows_to_wsl_path(project_path)
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="joern_cpg_")
        self.cpg_output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        cpg_path = os.path.join(output_dir, "cpg.bin.zip")
        wsl_cpg_path = self._windows_to_wsl_path(cpg_path)
        cmd = ["joern-parse", wsl_path, "--output", wsl_cpg_path]

        try:
            result = self._run_wsl_command(cmd, timeout=7200)
            if int(result.returncode or 0) != 0:
                self.last_status["status"] = "parse_failed"
                self.last_status["error"] = self._extract_command_error(result)
                print(f"[JoernAnalyzer] joern-parse failed: {self.last_status['error']}")
                return None
            if not os.path.exists(cpg_path) or os.path.getsize(cpg_path) == 0:
                self.last_status["status"] = "parse_failed"
                self.last_status["error"] = "CPG file not generated or empty."
                return None
            print(f"[JoernAnalyzer] CPG generated: {cpg_path}")
            return cpg_path
        except subprocess.TimeoutExpired:
            self.last_status["status"] = "parse_timeout"
            self.last_status["error"] = "joern-parse timed out."
            print("[JoernAnalyzer] joern-parse timeout")
            return None
        except Exception as exc:
            self.last_status["status"] = "parse_exception"
            self.last_status["error"] = str(exc)
            print(f"[JoernAnalyzer] joern-parse exception: {exc}")
            return None

    @staticmethod
    def _fallback_rules() -> List[Dict[str, str]]:
        return [
            {
                "name": "buffer-overflow",
                "severity": "high",
                "query": """
importCpg("%s")
cpg.method.call.name(".*cpy|.*cat|.*sprintf|gets").foreach { c =>
  val code = c.code.replace("\\t", " ").replace("\\n", " ")
  println(s"BNF\\t${c.file}\\t${c.lineNumber.getOrElse(0)}\\t${code}\\tbuffer-overflow")
}
""",
            },
            {
                "name": "command-injection",
                "severity": "high",
                "query": """
importCpg("%s")
cpg.method.call.name("system|popen|execl|execve|execvp").foreach { c =>
  val code = c.code.replace("\\t", " ").replace("\\n", " ")
  println(s"BNF\\t${c.file}\\t${c.lineNumber.getOrElse(0)}\\t${code}\\tcommand-injection")
}
""",
            },
            {
                "name": "tainted-buffer-access",
                "severity": "medium",
                "query": """
importCpg("%s")
cpg.method.call.name("gets|scanf|recv").foreach { c =>
  val code = c.code.replace("\\t", " ").replace("\\n", " ")
  println(s"BNF\\t${c.file}\\t${c.lineNumber.getOrElse(0)}\\t${code}\\ttainted-buffer-access")
}
""",
            },
            {
                "name": "format-string-risk",
                "severity": "medium",
                "query": """
importCpg("%s")
cpg.method.call.name("sprintf|snprintf").foreach { c =>
  val code = c.code.replace("\\t", " ").replace("\\n", " ")
  println(s"BNF\\t${c.file}\\t${c.lineNumber.getOrElse(0)}\\t${code}\\tformat-string-risk")
}
""",
            },
            {
                "name": "memory-leak",
                "severity": "medium",
                "query": """
importCpg("%s")
cpg.method.call.name("malloc|calloc|realloc").foreach { c =>
  val code = c.code.replace("\\t", " ").replace("\\n", " ")
  println(s"BNF\\t${c.file}\\t${c.lineNumber.getOrElse(0)}\\t${code}\\tmemory-leak")
}
""",
            },
        ]

    def _default_rules(self) -> List[Dict[str, str]]:
        # Backward-compatible method name used by legacy callers.
        return self.load_rules()

    @staticmethod
    def _normalize_joern_severity(level: str) -> str:
        value = (level or "").lower()
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "style",
            "info": "information",
            "error": "error",
            "warning": "warning",
            "style": "style",
            "information": "information",
        }
        return mapping.get(value, "warning")

    def _validate_rule(self, rule: Dict[str, Any]) -> bool:
        if not isinstance(rule, dict):
            return False
        if not rule.get("name") or not rule.get("query"):
            return False
        severity = str(rule.get("severity", "")).strip().lower()
        if severity not in {
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "error",
            "warning",
            "style",
            "information",
        }:
            return False
        return True

    def _load_rules_from_file(self, rules_path: str) -> Optional[List[Dict[str, str]]]:
        if not rules_path or not os.path.exists(rules_path):
            return None
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as exc:
            print(f"[JoernAnalyzer] Failed to load rules file: {rules_path}, error={exc}")
            return None

        if not isinstance(payload, list):
            print(f"[JoernAnalyzer] Invalid rules format in {rules_path}: expected list")
            return None

        valid_rules: List[Dict[str, str]] = []
        for item in payload:
            if self._validate_rule(item):
                valid_rules.append(
                    {
                        "name": str(item["name"]),
                        "severity": str(item["severity"]),
                        "query": str(item["query"]),
                    }
                )
        if not valid_rules:
            print(f"[JoernAnalyzer] No valid rules found in {rules_path}")
            return None
        return valid_rules

    def load_rules(self, rules_path: Optional[str] = None) -> List[Dict[str, str]]:
        custom = self._load_rules_from_file(rules_path) if rules_path else None
        if custom:
            return custom

        defaults = self._load_rules_from_file(self.default_rules_path)
        if defaults:
            return defaults

        return self._fallback_rules()

    def _run_joern_query(self, wsl_cpg_path: str, rule: Dict[str, str], project_path: str) -> List[RawAlert]:
        query_template = rule.get("query", "")
        if not query_template:
            return []

        script = query_template % wsl_cpg_path
        temp_script = tempfile.NamedTemporaryFile(mode="w", suffix=".sc", delete=False, encoding="utf-8")
        temp_script.write(script)
        temp_script.close()

        try:
            wsl_script_path = self._windows_to_wsl_path(temp_script.name)
            result = self._run_wsl_command(["joern", "--script", wsl_script_path], timeout=1800)
            if int(result.returncode or 0) != 0:
                print(
                    "[JoernAnalyzer] query failed",
                    f"rule={rule.get('name')}",
                    f"error={self._extract_command_error(result)[:300]}",
                )
                return []
            severity = self._normalize_joern_severity(rule.get("severity", "medium"))
            return self._parse_joern_output(result.stdout, severity, project_path)
        except Exception as exc:
            print(f"[JoernAnalyzer] query exception: {exc}")
            return []
        finally:
            try:
                os.unlink(temp_script.name)
            except Exception:
                pass

    def _resolve_file_path(self, raw_path: str, project_path: str) -> str:
        candidate = self._wsl_to_windows_path(raw_path)
        if os.path.exists(candidate):
            return os.path.abspath(candidate)

        base = project_path if os.path.isdir(project_path) else os.path.dirname(project_path)
        from_base = os.path.abspath(os.path.join(base, candidate))
        if os.path.exists(from_base):
            return from_base

        return candidate

    def _parse_joern_output(self, output: str, severity: str, project_path: str) -> List[RawAlert]:
        alerts: List[RawAlert] = []
        for line in (output or "").splitlines():
            text = line.strip()
            if not text.startswith("BNF\t"):
                continue
            parts = text.split("\t")
            if len(parts) < 5:
                continue

            file_path = self._resolve_file_path(parts[1], project_path)
            try:
                line_num = int(parts[2])
            except ValueError:
                line_num = 0

            func_hint = ""
            if len(parts) >= 6:
                func_hint = parts[3]
                code = parts[4]
                vuln_type = parts[5]
            else:
                code = parts[3]
                vuln_type = parts[4]

            func_match = func_hint or (code.split("(")[0] if "(" in code else code[:20])
            func = func_match.strip() if func_match else "unknown"

            alerts.append(
                RawAlert(
                    alert_id=str(uuid.uuid4()),
                    file=file_path,
                    line=line_num,
                    func=func,
                    msg=f"{vuln_type}: {code}",
                    severity=severity,
                    tool="joern",
                )
            )
        return alerts

    def get_vulnerabilities_from_cpg(
        self,
        cpg_path: str,
        project_path: str,
        rules: Optional[List[Dict[str, str]]] = None,
        rules_path: Optional[str] = None,
    ) -> List[RawAlert]:
        if not os.path.exists(cpg_path):
            print(f"[JoernAnalyzer] CPG file does not exist: {cpg_path}")
            return []

        if rules is None:
            rules = self.load_rules(rules_path)

        alerts: List[RawAlert] = []
        wsl_cpg_path = self._windows_to_wsl_path(cpg_path)
        for rule in rules:
            alerts.extend(self._run_joern_query(wsl_cpg_path, rule, project_path))
        return alerts

    def analyze(
        self,
        project_path: str,
        save_cpg: bool = True,
        output_dir: Optional[str] = None,
        rules: Optional[List[Dict[str, str]]] = None,
        rules_path: Optional[str] = None,
    ) -> Tuple[List[RawAlert], Optional[str]]:
        self.last_status = {
            "available": self.last_status.get("available", False),
            "executed": False,
            "status": "starting",
            "error": "",
            "alerts": 0,
        }
        print(f"[JoernAnalyzer] Start analyze: {project_path}")

        cpg_path = self.parse_project(project_path, output_dir)
        if not cpg_path:
            self.last_status["status"] = "parse_failed"
            return [], None

        try:
            alerts = self.get_vulnerabilities_from_cpg(
                cpg_path,
                project_path,
                rules=rules,
                rules_path=rules_path,
            )
        except TypeError:
            # Backward compatibility for monkeypatched tests using old signature.
            alerts = self.get_vulnerabilities_from_cpg(cpg_path, project_path, rules=rules)

        self.last_status["executed"] = True
        self.last_status["alerts"] = len(alerts)
        self.last_status["status"] = "ok"
        print(f"[JoernAnalyzer] Scan complete, alerts={len(alerts)}")

        if not save_cpg:
            temp_dir = self.cpg_output_dir
            try:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                cpg_path = None
            except Exception as exc:
                print(f"[JoernAnalyzer] Failed to cleanup CPG: {exc}")
            return alerts, cpg_path

        return alerts, cpg_path


class PreprocessAgent(BaseAgent):
    def __init__(self, cppcheck_path: str | None = None, wsl_distro: str = None, enable_joern: bool = True):
        super().__init__()

        candidates = [
            cppcheck_path,
            "cppcheck",
            "D:/cppcheck/cppcheck.exe",
            "D:\\cppcheck\\cppcheck.exe",
            "C:/Program Files/Cppcheck/cppcheck.exe",
        ]

        self.cppcheck_path: Optional[str] = None
        for path in candidates:
            if not path:
                continue
            try:
                subprocess.run([path, "--version"], capture_output=True, check=True)
                self.cppcheck_path = path
                print(f"[PreprocessAgent] Found Cppcheck: {self.cppcheck_path}")
                break
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue

        if not self.cppcheck_path:
            raise EnvironmentError(
                "Cppcheck not found. Install cppcheck or pass cppcheck_path explicitly."
            )

        self.enable_joern = bool(enable_joern)
        self.joern_analyzer: Optional[JoernAnalyzer] = None
        self.joern_available = False

        self.alert_normalizer = AlertNormalizer()
        self.alert_deduplicator = AlertDeduplicator()
        self.slice_builder = ProgramSliceBuilder()
        self.xml_parser = CppcheckXmlParser(alert_factory=self._create_raw_alert)
        self.cppcheck_scanner = CppcheckScanner(
            cppcheck_path=self.cppcheck_path,
            parse_xml_callback=self._parse_xml,
            runner=subprocess.run,
        )

        if self.enable_joern:
            try:
                analyzer = JoernAnalyzer(wsl_distro=wsl_distro)
                self.joern_analyzer = analyzer
                if analyzer.check_joern_available():
                    self.joern_available = True
                    print("[PreprocessAgent] Joern is available")
                else:
                    print(
                        "[PreprocessAgent] Joern check failed; will still attempt Joern when requested. "
                        f"detail={analyzer.last_status.get('error', '')}"
                    )
            except Exception as exc:
                print(f"[PreprocessAgent] Joern init failed: {exc}")

    @staticmethod
    def _create_raw_alert(
        file: str,
        line: int,
        func: str,
        msg: str,
        severity: str,
        tool: str,
    ) -> RawAlert:
        return RawAlert(
            alert_id=str(uuid.uuid4()),
            file=file,
            line=int(line or 0),
            func=func or "unknown",
            msg=msg or "No message",
            severity=severity or "unknown",
            tool=tool or "cppcheck",
        )

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        project_path = input_data.get("project_path")
        enable_all = bool(input_data.get("enable_all", True))
        enable_joern = bool(input_data.get("enable_joern", self.enable_joern))
        save_cpg = bool(input_data.get("save_cpg", True))
        compute_slices = bool(input_data.get("compute_slices", True))
        joern_rules = input_data.get("joern_rules")
        joern_rules_path = input_data.get("joern_rules_path")
        cpg_output_dir = input_data.get("cpg_output_dir")

        if not project_path:
            raise ValueError("Missing project_path in input_data")
        if not os.path.exists(project_path):
            raise FileNotFoundError(f"Project path does not exist: {project_path}")

        log_event(
            LOGGER,
            "preprocess_start",
            project_path=os.path.abspath(project_path),
            enable_joern=enable_joern,
            compute_slices=compute_slices,
        )

        cppcheck_alerts, cppcheck_exit_code = self.cppcheck_scanner.scan(
            project_path=project_path,
            enable_all=enable_all,
        )
        if cppcheck_exit_code not in (0, 1):
            print(f"[PreprocessAgent] Warning: Cppcheck exit code = {cppcheck_exit_code}")

        joern_alerts: List[RawAlert] = []
        cpg_path: Optional[str] = None
        joern_status = "disabled"
        joern_error = ""
        joern_executed = False

        if enable_joern:
            if not self.joern_analyzer:
                joern_status = "not_available"
                joern_error = "Joern analyzer unavailable."
            else:
                joern_status = "requested"
                output_dir = cpg_output_dir
                temp_output_dir = None
                if not output_dir:
                    if save_cpg:
                        run_tag = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
                        output_dir = os.path.join(
                            os.path.dirname(os.path.dirname(__file__)),
                            "outputs",
                            "cpg",
                            run_tag,
                        )
                        os.makedirs(output_dir, exist_ok=True)
                    else:
                        temp_output_dir = tempfile.mkdtemp(prefix="joern_cpg_")
                        output_dir = temp_output_dir

                try:
                    joern_alerts, cpg_path = self.joern_analyzer.analyze(
                        project_path=project_path,
                        save_cpg=save_cpg,
                        output_dir=output_dir,
                        rules=joern_rules,
                        rules_path=joern_rules_path,
                    )
                    joern_executed = bool(self.joern_analyzer.last_status.get("executed", False))
                    joern_status = str(self.joern_analyzer.last_status.get("status", "unknown"))
                    joern_error = str(self.joern_analyzer.last_status.get("error", ""))
                    if joern_executed:
                        self.joern_available = True
                except Exception as exc:
                    joern_status = "exception"
                    joern_error = str(exc)
                    print(f"[PreprocessAgent] Joern analyze failed: {exc}")
                finally:
                    if temp_output_dir and os.path.exists(temp_output_dir):
                        shutil.rmtree(temp_output_dir, ignore_errors=True)

        all_alerts = cppcheck_alerts + joern_alerts
        deduped_alerts = self._deduplicate_alerts(all_alerts)
        files = self._list_source_files(project_path)

        alerts_with_slices: List[Dict[str, Any]] = []
        for alert in deduped_alerts:
            alert.file = self._resolve_alert_file(alert.file, project_path, files)
            if compute_slices:
                program_slice = self._compute_program_slice(alert.file, int(alert.line), alert.msg)
            else:
                program_slice = self._empty_program_slice(int(alert.line))
            alert_dict = asdict(alert)
            alert_dict["program_slice"] = program_slice
            alerts_with_slices.append(alert_dict)

        project_info = {
            "files": files,
            "compile_commands": None,
            "cppcheck_exit_code": cppcheck_exit_code,
            "cppcheck_raw_count": len(cppcheck_alerts),
            "joern_raw_count": len(joern_alerts),
            "total_raw_count": len(all_alerts),
            "deduped_alert_count": len(deduped_alerts),
            "cpg_path": cpg_path,
            "cpg_exists": bool(cpg_path and os.path.exists(cpg_path)),
            "joern_available": self.joern_available,
            "joern_requested": enable_joern,
            "joern_executed": joern_executed,
            "joern_status": joern_status,
            "joern_error": joern_error,
            "slices_computed": compute_slices,
        }

        log_event(
            LOGGER,
            "preprocess_complete",
            project_path=os.path.abspath(project_path),
            alerts_raw=len(all_alerts),
            alerts_deduped=len(deduped_alerts),
            joern_status=joern_status,
            status="ok",
        )

        return {"raw_alerts": alerts_with_slices, "project_info": project_info}

    @staticmethod
    def _severity_rank(level: str) -> int:
        return AlertDeduplicator._severity_rank(level)

    @staticmethod
    def _merge_tool_names(left: str, right: str) -> str:
        return AlertDeduplicator._merge_tool_names(left, right)

    @staticmethod
    def _infer_family_from_msg(msg: str) -> str:
        return AlertDeduplicator._infer_family_from_msg(msg)

    def _alert_fingerprint(self, alert: RawAlert) -> Tuple[str, int, str]:
        return self.alert_deduplicator._alert_fingerprint(alert)

    def _deduplicate_alerts(self, alerts: List[RawAlert]) -> List[RawAlert]:
        return self.alert_deduplicator.deduplicate(alerts)

    def _resolve_alert_file(self, file_path: str, project_path: str, project_files: List[str]) -> str:
        return self.alert_normalizer.resolve_alert_file(file_path, project_path, project_files)

    @staticmethod
    def _empty_program_slice(line_num: int = 0) -> Dict[str, Any]:
        return ProgramSliceBuilder.empty_program_slice(line_num)

    def build_program_slice_for_alert(
        self,
        alert: Dict[str, Any],
        project_path: str,
        project_files: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if not isinstance(alert, dict):
            return {}

        files = project_files if project_files is not None else self._list_source_files(project_path)
        resolved_file = self._resolve_alert_file(str(alert.get("file", "")), project_path, files)
        line = int(alert.get("line", 0) or 0)
        msg = str(alert.get("msg", ""))

        program_slice = self._compute_program_slice(resolved_file, line, msg)

        alert["file"] = resolved_file
        alert["program_slice"] = program_slice
        return program_slice

    def _read_file_lines(self, file_path: str) -> List[str]:
        return self.slice_builder.read_file_lines(file_path)

    def _find_function_bounds(self, lines: List[str], line_num: int, window: int = 120) -> Tuple[int, int]:
        return self.slice_builder.find_function_bounds(lines, line_num, window=window)

    def _identify_source_sink_paths(
        self,
        lines: List[str],
        line_num: int,
        start: int,
        end: int,
    ) -> Tuple[Set[int], Set[int]]:
        return self.slice_builder.identify_source_sink_paths(lines, line_num, start, end)

    def _build_control_flow(self, lines: List[str], start: int, end: int) -> Dict[int, Set[int]]:
        return self.slice_builder.build_control_flow(lines, start, end)

    @staticmethod
    def _find_block_fallthrough(lines: List[str], current_idx: int, end_idx: int) -> Optional[int]:
        return ProgramSliceBuilder.find_block_fallthrough(lines, current_idx, end_idx)

    @staticmethod
    def _build_predecessor_map(control_flow: Dict[int, Set[int]]) -> Dict[int, Set[int]]:
        return ProgramSliceBuilder.build_predecessor_map(control_flow)

    def _backward_slice(
        self,
        control_flow: Dict[int, Set[int]],
        sink_line: int,
        source_lines: Set[int],
        max_nodes: int = 180,
    ) -> Set[int]:
        return self.slice_builder.backward_slice(control_flow, sink_line, source_lines, max_nodes=max_nodes)

    @staticmethod
    def _extract_slice_code(lines: List[str], slice_lines: Set[int]) -> str:
        return ProgramSliceBuilder.extract_slice_code(lines, slice_lines)

    def _compute_program_slice(self, file_path: str, line_num: int, alert_msg: str) -> Dict[str, Any]:
        return self.slice_builder.compute_program_slice(file_path, line_num, alert_msg)

    def _parse_xml(self, xml_path: str) -> List[RawAlert]:
        return self.xml_parser.parse(xml_path)

    def _list_source_files(self, path: str) -> List[str]:
        return self.alert_normalizer.list_source_files(path)
