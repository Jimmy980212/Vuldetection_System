import argparse
import datetime as _dt
import hashlib
import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
RESULT_DIR = BASE_DIR / "result"
DATASET_DIR = BASE_DIR / "dataset"
JOB_DIR = BASE_DIR / "output" / "mvp_jobs"

JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


def now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def read_json(path: Path, fallback: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return fallback


def safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        return path.name


def stable_id(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:12]


def extract_line(location: Any) -> int:
    m = re.search(r"\d+", str(location or ""))
    return int(m.group(0)) if m else 0


def normalize_severity(sev: Any) -> str:
    s = str(sev or "medium").strip().lower()
    aliases = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "mid": "medium",
        "low": "low",
        "info": "info",
        "提示": "info",
        "高危": "high",
        "中危": "medium",
        "低危": "low",
    }
    return aliases.get(s, "medium")


def severity_label(sev: str) -> str:
    return {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "提示",
    }.get(sev, "中危")


def report_index() -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    files = sorted(
        RESULT_DIR.rglob("*.report.json"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    reports: List[Dict[str, Any]] = []
    by_id: Dict[str, Dict[str, Any]] = {}
    for path in files:
        rel = safe_rel(path, RESULT_DIR)
        rid = stable_id(rel)
        raw = read_json(path, {})
        if not isinstance(raw, dict):
            continue
        report = {
            "id": rid,
            "path": rel,
            "abs_path": str(path),
            "file": raw.get("file") or path.name.replace(".report.json", ""),
            "project": raw.get("project") or "default",
            "scan_time": raw.get("scan_time") or "",
            "total_vulnerabilities": int(raw.get("total_vulnerabilities") or 0),
            "severity_summary": raw.get("severity_summary") or {},
            "vulnerabilities_by_cwe": raw.get("vulnerabilities_by_cwe") or {},
            "static_analysis_summary": raw.get("static_analysis_summary") or {},
            "raw": raw,
        }
        reports.append(report)
        by_id[rid] = report
    return reports, by_id


def flatten_findings(reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for report in reports:
        for idx, vuln in enumerate(report.get("raw", {}).get("vulnerabilities") or [], 1):
            if not isinstance(vuln, dict):
                continue
            sev = normalize_severity(vuln.get("severity"))
            cwe = str(vuln.get("cwe") or vuln.get("cwe_id") or "CWE-UNKNOWN")
            location = vuln.get("location") or ""
            line = extract_line(location)
            fid = f"{report['id']}-{idx:03d}"
            findings.append(
                {
                    "id": fid,
                    "report_id": report["id"],
                    "vuln_id": f"VUL-{fid.upper()}",
                    "file": report.get("file"),
                    "project": report.get("project"),
                    "cwe": cwe,
                    "cwe_description": vuln.get("cwe_description") or "",
                    "severity": sev,
                    "severity_label": severity_label(sev),
                    "confidence": vuln.get("confidence", 0),
                    "evidence_score": vuln.get("evidence_score", 0),
                    "location": location,
                    "line": line,
                    "description": vuln.get("description") or "",
                    "suggestion": vuln.get("suggestion") or "",
                    "validation": vuln.get("validation") or {},
                    "evidence_chain": vuln.get("evidence_chain") or {},
                    "source": "真实报告",
                    "status": "已确认" if sev in {"critical", "high", "medium", "low"} else "待确认",
                }
            )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: (order.get(x["severity"], 9), -int(float(x.get("confidence") or 0))))
    return findings


def aggregate_summary() -> Dict[str, Any]:
    summary_file = RESULT_DIR / "scan_summary.json"
    saved_summary = read_json(summary_file, {}) if summary_file.exists() else {}
    reports, _ = report_index()
    findings = flatten_findings(reports)

    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cwe_summary: Dict[str, int] = {}
    for item in findings:
        severity[item["severity"]] = severity.get(item["severity"], 0) + 1
        cwe_summary[item["cwe"]] = cwe_summary.get(item["cwe"], 0) + 1

    if not findings and isinstance(saved_summary, dict):
        for sev, count in (saved_summary.get("severity_summary") or {}).items():
            nsev = normalize_severity(sev)
            severity[nsev] = severity.get(nsev, 0) + int(count or 0)
        cwe_summary.update(saved_summary.get("cwe_summary") or {})

    scans = list_jobs()
    total_vulns = len(findings) if findings else int(saved_summary.get("total_vulnerabilities") or 0)
    return {
        "source": "real" if reports else "empty",
        "message": "" if reports else "result/ 中还没有可用报告。可以先在前端发起一次扫描，或运行 CLI 生成报告。",
        "scan_time": saved_summary.get("scan_time") or (reports[0]["scan_time"] if reports else ""),
        "summary": saved_summary,
        "stats": {
            "total_reports": len(reports),
            "total_files": int(saved_summary.get("total_files") or len(reports)),
            "total_vulnerabilities": total_vulns,
            "severity_summary": severity,
            "cwe_summary": cwe_summary,
            "confirmed": sum(1 for f in findings if f.get("status") == "已确认"),
            "running_jobs": sum(1 for j in scans if j.get("status") == "running"),
            "completed_jobs": sum(1 for j in scans if j.get("status") == "completed"),
            "failed_jobs": sum(1 for j in scans if j.get("status") == "failed"),
        },
        "reports": [
            {k: v for k, v in r.items() if k not in {"raw", "abs_path"}}
            for r in reports
        ],
        "findings": findings,
        "scans": scans,
    }


def list_jobs() -> List[Dict[str, Any]]:
    with JOBS_LOCK:
        jobs = [dict(v) for v in JOBS.values()]
    jobs.sort(key=lambda j: j.get("created_at", ""), reverse=True)
    return jobs


def log_tail(path: Path, max_chars: int = 12000) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
        return data[-max_chars:]
    except Exception:
        return ""


def resolve_workspace_path(value: str, default: Path) -> Path:
    raw = (value or "").strip()
    candidate = Path(raw) if raw else default
    if not candidate.is_absolute():
        candidate = BASE_DIR / candidate
    resolved = candidate.resolve()
    base = BASE_DIR.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError("路径必须位于当前项目目录内") from exc
    return resolved


def build_scan_command(payload: Dict[str, Any]) -> List[str]:
    mode = str(payload.get("mode") or "scan").strip().lower()
    parallel = max(1, min(16, int(payload.get("parallel") or 2)))
    args = [sys.executable, str(BASE_DIR / "main.py"), "--mode", mode, "--parallel", str(parallel)]

    if mode == "scan":
        root = resolve_workspace_path(str(payload.get("root") or "dataset/multi_c_project"), DATASET_DIR)
        args += ["--lang", "c", "--root", str(root)]
        max_files = payload.get("max_files")
        if max_files not in (None, "", 0, "0"):
            args += ["--max-files", str(max(1, int(max_files)))]
        if bool(payload.get("c_workspace_cpg")):
            args.append("--c-workspace-cpg")
        if bool(payload.get("no_cache")):
            args.append("--no-cache")
        return args

    if mode == "detect":
        source = str(payload.get("source") or "local").strip().lower()
        if source not in {"local", "secvul", "primevul"}:
            raise ValueError("detect.source 仅支持 local/secvul/primevul")
        args += ["--source", source]
        if source == "local":
            file_value = str(payload.get("file") or "").strip()
            dir_value = str(payload.get("dir") or "").strip()
            if file_value:
                file_path = resolve_workspace_path(file_value, DATASET_DIR / "sparse_big_less100.c")
                args += ["--file", str(file_path)]
            else:
                dir_path = resolve_workspace_path(dir_value or "dataset", DATASET_DIR)
                args += ["--dir", str(dir_path), "--max-samples", str(max(1, int(payload.get("max_samples") or 10)))]
        else:
            args += [
                "--samples",
                str(max(1, int(payload.get("samples") or 10))),
                "--vuln-ratio",
                str(max(0.0, min(1.0, float(payload.get("vuln_ratio") or 0.5)))),
                "--split",
                str(payload.get("split") or "train"),
            ]
            if bool(payload.get("no_mirror")):
                args.append("--no-mirror")
        if bool(payload.get("no_cache")):
            args.append("--no-cache")
        return args

    raise ValueError("mode 仅支持 scan 或 detect")


def start_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
    command = build_scan_command(payload)
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex[:12]
    log_path = JOB_DIR / f"{job_id}.log"
    job = {
        "id": job_id,
        "status": "queued",
        "created_at": now_iso(),
        "started_at": "",
        "finished_at": "",
        "duration_sec": 0,
        "returncode": None,
        "command": command,
        "command_display": " ".join(command),
        "log_path": str(log_path),
        "pid": None,
    }
    with JOBS_LOCK:
        JOBS[job_id] = job

    def runner() -> None:
        started = time.time()
        env = os.environ.copy()
        env.setdefault("PYTHONUTF8", "1")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "running"
            JOBS[job_id]["started_at"] = now_iso()
        try:
            with log_path.open("w", encoding="utf-8", errors="replace") as log:
                log.write(f"$ {' '.join(command)}\n\n")
                log.flush()
                proc = subprocess.Popen(
                    command,
                    cwd=str(BASE_DIR),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    env=env,
                )
                with JOBS_LOCK:
                    JOBS[job_id]["pid"] = proc.pid
                rc = proc.wait()
            status = "completed" if rc == 0 else "failed"
            with JOBS_LOCK:
                JOBS[job_id].update(
                    {
                        "status": status,
                        "returncode": rc,
                        "finished_at": now_iso(),
                        "duration_sec": round(time.time() - started, 2),
                    }
                )
        except Exception as exc:
            with log_path.open("a", encoding="utf-8", errors="replace") as log:
                log.write(f"\n[web_mvp] failed: {exc}\n")
            with JOBS_LOCK:
                JOBS[job_id].update(
                    {
                        "status": "failed",
                        "error": str(exc),
                        "finished_at": now_iso(),
                        "duration_sec": round(time.time() - started, 2),
                    }
                )

    threading.Thread(target=runner, daemon=True).start()
    return dict(job)


def find_source_file(file_name: str) -> Optional[Path]:
    if not file_name:
        return None
    raw = unquote(file_name).strip()
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = BASE_DIR / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(BASE_DIR.resolve())
        if resolved.exists() and resolved.is_file():
            return resolved
    except Exception:
        pass

    normalized = raw.replace("\\", "/").lstrip("/")
    ignored = {"result", "temp", "output", "__pycache__", ".git"}
    for path in BASE_DIR.rglob(Path(normalized).name):
        if any(part in ignored for part in path.parts):
            continue
        if normalized.endswith(path.name) or str(path).replace("\\", "/").endswith(normalized):
            return path
    return None


def code_context(file_name: str, line: int, radius: int = 8) -> Dict[str, Any]:
    path = find_source_file(file_name)
    if not path:
        return {"found": False, "file": file_name, "lines": []}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if line <= 0:
        line = 1
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return {
        "found": True,
        "file": safe_rel(path, BASE_DIR),
        "line": line,
        "lines": [
            {"number": i, "text": lines[i - 1], "hit": i == line}
            for i in range(start, end + 1)
        ],
    }


class MVPHandler(BaseHTTPRequestHandler):
    server_version = "VulnShieldMVP/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stdout.write("[%s] %s\n" % (now_iso(), fmt % args))

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return json.loads(raw or "{}")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.handle_api_get(parsed.path, parse_qs(parsed.query))
        else:
            self.serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.handle_api_post(parsed.path)
        else:
            self.send_json({"error": "not found"}, 404)

    def handle_api_get(self, path: str, query: Dict[str, List[str]]) -> None:
        try:
            if path == "/api/health":
                self.send_json({"ok": True, "time": now_iso(), "base_dir": str(BASE_DIR)})
                return
            if path == "/api/summary":
                self.send_json(aggregate_summary())
                return
            if path == "/api/reports":
                reports, _ = report_index()
                self.send_json({"reports": [{k: v for k, v in r.items() if k not in {"raw", "abs_path"}} for r in reports]})
                return
            if path == "/api/findings":
                reports, _ = report_index()
                self.send_json({"findings": flatten_findings(reports)})
                return
            if path.startswith("/api/reports/"):
                rid = path.rsplit("/", 1)[-1]
                _, by_id = report_index()
                report = by_id.get(rid)
                if not report:
                    self.send_json({"error": "report not found"}, 404)
                    return
                self.send_json({k: v for k, v in report.items() if k != "abs_path"})
                return
            if path in {"/api/scans", "/api/tasks"}:
                self.send_json({"scans": list_jobs()})
                return
            if path.startswith("/api/scans/") or path.startswith("/api/tasks/"):
                jid = path.rsplit("/", 1)[-1]
                with JOBS_LOCK:
                    job = dict(JOBS.get(jid) or {})
                if not job:
                    self.send_json({"error": "scan job not found"}, 404)
                    return
                job["log_tail"] = log_tail(Path(job.get("log_path", "")))
                self.send_json(job)
                return
            if path == "/api/code-context":
                file_name = (query.get("file") or [""])[0]
                line = int((query.get("line") or ["1"])[0] or 1)
                radius = max(2, min(30, int((query.get("radius") or ["8"])[0] or 8)))
                self.send_json(code_context(file_name, line, radius))
                return
            self.send_json({"error": "not found"}, 404)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 500)

    def handle_api_post(self, path: str) -> None:
        try:
            if path in {"/api/scans", "/api/tasks"}:
                payload = self.read_body_json()
                job = start_scan(payload)
                self.send_json(job, 202)
                return
            self.send_json({"error": "not found"}, 404)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 400)

    def serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            target = FRONTEND_DIR / "index.html"
        else:
            rel = unquote(path).lstrip("/")
            target = FRONTEND_DIR / rel
            if not target.exists():
                target = FRONTEND_DIR / "index.html"
        try:
            resolved = target.resolve()
            resolved.relative_to(FRONTEND_DIR.resolve())
            if not resolved.is_file():
                raise FileNotFoundError(str(resolved))
            data = resolved.read_bytes()
            ctype = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
            if resolved.suffix == ".js":
                ctype = "text/javascript"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self.send_json({"error": "static file not found"}, 404)


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnShield C CLI Web MVP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    FRONTEND_DIR.mkdir(exist_ok=True)
    RESULT_DIR.mkdir(exist_ok=True)
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((args.host, args.port), MVPHandler)
    print(f"Web MVP running at http://{args.host}:{args.port}/")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
