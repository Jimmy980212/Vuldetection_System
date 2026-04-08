import os
import re
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Dict, List, Optional, Tuple


class CVEKnowledgeBase:
    """Load and summarize CVE data from an xlsx file for prompt and rule guidance."""

    NAMESPACES = {
        "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
        "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
    }

    FAMILY_CONFIG = {
        "buffer_overflow": {
            "cwes": {"CWE-120", "CWE-121", "CWE-122", "CWE-119"},
            "aliases": ["buffer overflow", "stack overflow", "heap overflow", "buffer overrun"],
            "hints": [
                "check destination buffer size against attacker-controlled length",
                "prefer bounded copy APIs and explicit length checks",
            ],
        },
        "null_pointer": {
            "cwes": {"CWE-476", "CWE-125"},
            "aliases": ["null pointer", "nullptr", "null dereference"],
            "hints": [
                "guard pointer dereference with null checks",
                "validate allocation and function return paths before dereference",
            ],
        },
        "memory_leak": {
            "cwes": {"CWE-401", "CWE-404"},
            "aliases": ["memory leak", "resource leak", "leak", "refcount"],
            "hints": [
                "pair allocation and release in all success/failure paths",
                "enforce ownership conventions and cleanup routines",
            ],
        },
        "double_free": {
            "cwes": {"CWE-415", "CWE-590"},
            "aliases": ["double free"],
            "hints": [
                "ensure free/delete is executed at most once for each allocation",
                "null out or transfer ownership after free",
            ],
        },
        "use_after_free": {
            "cwes": {"CWE-416", "CWE-825"},
            "aliases": ["use after free", "uaf", "use-after-free"],
            "hints": [
                "do not dereference pointers after free/delete",
                "verify lifetime and ownership across error paths and races",
            ],
        },
        "out_of_bounds": {
            "cwes": {"CWE-787", "CWE-125", "CWE-126", "CWE-193", "CWE-124", "CWE-131"},
            "aliases": ["out-of-bounds", "out of bounds", "oob", "overread", "overwrite", "buffer overread"],
            "hints": [
                "validate index and length before read/write",
                "check integer truncation/overflow before pointer arithmetic",
            ],
        },
        "integer_overflow": {
            "cwes": {"CWE-190", "CWE-680", "CWE-191", "CWE-192"},
            "aliases": ["integer overflow", "signed integer overflow", "overflow", "integer underflow"],
            "hints": [
                "use checked arithmetic before allocation/indexing",
                "validate untrusted numeric inputs and bounds",
            ],
        },
        "format_string": {
            "cwes": {"CWE-134"},
            "aliases": ["format string"],
            "hints": [
                "avoid attacker-controlled format strings",
                "use explicit format specifiers and sanitized inputs",
            ],
        },
        "command_injection": {
            "cwes": {"CWE-78", "CWE-77", "CWE-74"},
            "aliases": ["command injection", "shell injection", "os command injection"],
            "hints": [
                "avoid shell invocation with untrusted input",
                "use allowlists and argumentized APIs",
            ],
        },
        "race_condition": {
            "cwes": {"CWE-362", "CWE-367", "CWE-667", "CWE-820"},
            "aliases": ["race condition", "time-of-check", "toctou", "race", "concurrent"],
            "hints": [
                "use proper locking mechanisms for shared resources",
                "avoid TOCTOU patterns by validating and using resources atomically",
            ],
        },
        "resource_exhaustion": {
            "cwes": {"CWE-400", "CWE-770", "CWE-674", "CWE-1325"},
            "aliases": ["resource exhaustion", "denial of service", "dos", "infinite loop", "uncontrolled resource"],
            "hints": [
                "implement proper resource limits and quotas",
                "validate loop termination conditions",
            ],
        },
        "path_traversal": {
            "cwes": {"CWE-22", "CWE-23", "CWE-24", "CWE-25", "CWE-26", "CWE-27", "CWE-28"},
            "aliases": ["path traversal", "directory traversal", "path injection", "../"],
            "hints": [
                "sanitize and validate all file paths",
                "use canonical paths and realpath to resolve symbolic links",
            ],
        },
        "type_confusion": {
            "cwes": {"CWE-843", "CWE-195", "CWE-197", "CWE-198"},
            "aliases": ["type confusion", "type mismatch", "signed to unsigned"],
            "hints": [
                "ensure proper type casting and validation",
                "avoid implicit type conversions that may lose information",
            ],
        },
        "heap_corruption": {
            "cwes": {"CWE-122", "CWE-415", "CWE-416", "CWE-761"},
            "aliases": ["heap corruption", "heap overflow", "heap spraying"],
            "hints": [
                "use safe memory allocation patterns",
                "implement proper heap management and validation",
            ],
        },
        "pointer_arithmetic": {
            "cwes": {"CWE-468", "CWE-469", "CWE-824"},
            "aliases": ["pointer arithmetic", "invalid pointer", "pointer offset"],
            "hints": [
                "validate pointer calculations before use",
                "ensure pointer arithmetic does not overflow",
            ],
        },
    }

    DEFAULT_STOPWORDS = {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "into",
        "when",
        "which",
        "could",
        "allow",
        "allows",
        "via",
        "has",
        "have",
        "had",
        "was",
        "were",
        "are",
        "been",
        "prior",
        "before",
        "after",
        "due",
        "because",
        "exists",
        "version",
        "versions",
        "kernel",
        "linux",
        "remote",
        "local",
        "attacker",
        "attackers",
        "vulnerability",
        "vulnerable",
        "code",
        "execution",
        "possible",
        "crafted",
        "file",
        "files",
        "function",
        "functions",
        "data",
        "memory",
    }

    def __init__(self, xlsx_path: Optional[str] = None):
        self.xlsx_path = xlsx_path
        self.loaded = False
        self.total_records = 0
        self.known_cwes = set()
        self.cwe_counter = Counter()
        self.family_stats = {
            name: {
                "count": 0,
                "keywords": Counter(),
                "cwes": Counter(),
                "samples": [],
            }
            for name in list(self.FAMILY_CONFIG.keys()) + ["unknown"]
        }

        if xlsx_path:
            self.load(xlsx_path)

    def load(self, xlsx_path: Optional[str] = None) -> bool:
        if xlsx_path:
            self.xlsx_path = xlsx_path

        if not self.xlsx_path or not os.path.exists(self.xlsx_path):
            self.loaded = False
            return False

        # reset state
        self.loaded = False
        self.total_records = 0
        self.known_cwes = set()
        self.cwe_counter = Counter()
        self.family_stats = {
            name: {
                "count": 0,
                "keywords": Counter(),
                "cwes": Counter(),
                "samples": [],
            }
            for name in list(self.FAMILY_CONFIG.keys()) + ["unknown"]
        }

        try:
            workbook = self._read_workbook(self.xlsx_path)
            for sheet_name, rows in workbook.items():
                self._ingest_sheet(sheet_name, rows)
            self.loaded = True
            return True
        except Exception:
            self.loaded = False
            return False

    def _read_workbook(self, xlsx_path: str) -> Dict[str, List[List[str]]]:
        def col_index(cell_ref: str) -> int:
            col = "".join(ch for ch in cell_ref if ch.isalpha())
            idx = 0
            for ch in col:
                idx = idx * 26 + (ord(ch.upper()) - 64)
            return idx

        workbook_rows: Dict[str, List[List[str]]] = {}
        ns = self.NAMESPACES

        with zipfile.ZipFile(xlsx_path, "r") as zf:
            shared_strings = []
            if "xl/sharedStrings.xml" in zf.namelist():
                sst_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for si in sst_root.findall(".//m:si", ns):
                    parts = [t.text or "" for t in si.findall(".//m:t", ns)]
                    shared_strings.append("".join(parts))

            wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
            rels_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
            rid_to_target = {
                rel.get("Id"): rel.get("Target")
                for rel in rels_root.findall(".//pr:Relationship", ns)
            }

            for sheet in wb_root.findall(".//m:sheets/m:sheet", ns):
                sheet_name = sheet.get("name", "unknown")
                rid = sheet.get(
                    "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
                )
                target = rid_to_target.get(rid)
                if not target:
                    continue

                sheet_xml = f"xl/{target}"
                if sheet_xml not in zf.namelist():
                    continue

                sheet_root = ET.fromstring(zf.read(sheet_xml))
                rows: List[List[str]] = []

                for row in sheet_root.findall(".//m:sheetData/m:row", ns):
                    cells = {}
                    for cell in row.findall("m:c", ns):
                        ref = cell.get("r", "")
                        idx = col_index(ref)
                        ctype = cell.get("t")

                        value = ""
                        v = cell.find("m:v", ns)
                        if v is not None and v.text is not None:
                            raw = v.text
                            if ctype == "s":
                                try:
                                    value = shared_strings[int(raw)]
                                except Exception:
                                    value = raw
                            else:
                                value = raw
                        else:
                            inline = cell.find("m:is/m:t", ns)
                            if inline is not None and inline.text is not None:
                                value = inline.text

                        cells[idx] = value.strip()

                    if cells:
                        max_idx = max(cells.keys())
                        rows.append([cells.get(i, "") for i in range(1, max_idx + 1)])

                workbook_rows[sheet_name] = rows

        return workbook_rows

    def _ingest_sheet(self, sheet_name: str, rows: List[List[str]]) -> None:
        if not rows:
            return

        header = [h.strip().lower() for h in rows[0]]

        def find_idx(target: str, default: int) -> int:
            for i, col in enumerate(header):
                if target in col:
                    return i
            return default

        cve_idx = find_idx("cve", 0)
        cwe_idx = find_idx("cwe", 1)
        desc_idx = find_idx("description", 2)
        published_idx = find_idx("published", 4)

        for row in rows[1:]:
            cve_id = self._safe_get(row, cve_idx)
            cwe_text = self._safe_get(row, cwe_idx)
            desc = self._safe_get(row, desc_idx)
            published = self._safe_get(row, published_idx)

            if not cve_id and not desc:
                continue

            cwe_list = self.extract_cwe_list(cwe_text)
            for cwe in cwe_list:
                self.cwe_counter[cwe] += 1
                self.known_cwes.add(cwe)

            family = self._infer_family(cwe_list, desc, sheet_name)
            family_bucket = self.family_stats[family]
            family_bucket["count"] += 1

            for cwe in cwe_list:
                family_bucket["cwes"][cwe] += 1

            for kw in self._extract_keywords(desc):
                family_bucket["keywords"][kw] += 1

            if cve_id and len(family_bucket["samples"]) < 8:
                family_bucket["samples"].append(
                    {"cve": cve_id, "cwe": cwe_text, "published": published}
                )

            self.total_records += 1

    @staticmethod
    def _safe_get(values: List[str], idx: int) -> str:
        if idx < 0 or idx >= len(values):
            return ""
        return (values[idx] or "").strip()

    def _infer_family(self, cwe_list: List[str], desc: str, sheet_name: str) -> str:
        # prioritize exact CWE mapping
        cwe_set = set(cwe_list)
        for family, cfg in self.FAMILY_CONFIG.items():
            if cwe_set.intersection(cfg["cwes"]):
                return family

        haystack = f"{sheet_name} {desc}".lower()
        for family, cfg in self.FAMILY_CONFIG.items():
            for alias in cfg["aliases"]:
                if alias in haystack:
                    return family

        return "unknown"

    def _extract_keywords(self, text: str) -> List[str]:
        tokens = re.findall(r"[a-z][a-z0-9_-]{2,}", (text or "").lower())
        return [t for t in tokens if t not in self.DEFAULT_STOPWORDS]

    @staticmethod
    def extract_cwe_list(text: str) -> List[str]:
        return sorted(set(re.findall(r"CWE-\d+", (text or "").upper())))

    def family_from_cwe(self, cwe_text: str) -> Optional[str]:
        cwe_list = self.extract_cwe_list(cwe_text)
        if not cwe_list:
            return None

        cwe_set = set(cwe_list)
        for family, cfg in self.FAMILY_CONFIG.items():
            if cwe_set.intersection(cfg["cwes"]):
                return family
        return None

    def infer_family_from_text(self, text: str, cwe_hint: str = "") -> Optional[str]:
        family = self.family_from_cwe(cwe_hint)
        if family:
            return family

        t = (text or "").lower()
        for family_name, cfg in self.FAMILY_CONFIG.items():
            for alias in cfg["aliases"]:
                if alias in t:
                    return family_name
        return None

    def is_known_cwe(self, cwe_text: str) -> bool:
        for cwe in self.extract_cwe_list(cwe_text):
            if cwe in self.known_cwes:
                return True
        return False

    def security_relevance_score(self, alert_msg: str, severity: str = "") -> int:
        severity_score = {
            "error": 4,
            "warning": 3,
            "high": 4,
            "medium": 3,
            "low": 2,
            "style": 1,
            "information": 0,
            "": 0,
        }.get((severity or "").lower(), 1)

        msg = (alert_msg or "").lower()
        keyword_bonus = 0
        if "include file" in msg:
            keyword_bonus -= 2
        if self.infer_family_from_text(msg):
            keyword_bonus += 4

        generic_security_terms = [
            "overflow",
            "out of bounds",
            "out-of-bounds",
            "use after free",
            "double free",
            "null pointer",
            "race",
            "heap",
            "stack",
            "dangling",
            "memory leak",
        ]
        if any(term in msg for term in generic_security_terms):
            keyword_bonus += 2

        return severity_score + keyword_bonus

    def build_prompt_context(self, alert_msg: str, cwe_hint: str = "") -> str:
        if not self.loaded or self.total_records == 0:
            return "No CVE knowledge available."

        family = self.infer_family_from_text(alert_msg, cwe_hint)
        if family and family in self.family_stats:
            bucket = self.family_stats[family]
            top_cwes = [f"{k}({v})" for k, v in bucket["cwes"].most_common(3)]
            top_keywords = [k for k, _ in bucket["keywords"].most_common(8)]
            hints = self.FAMILY_CONFIG.get(family, {}).get("hints", [])
            return (
                f"CVE family hint: {family}\n"
                f"Similar CVE samples in knowledge base: {bucket['count']}\n"
                f"Top CWE in this family: {', '.join(top_cwes) if top_cwes else 'N/A'}\n"
                f"Frequent description keywords: {', '.join(top_keywords) if top_keywords else 'N/A'}\n"
                f"Reasoning hints: {'; '.join(hints) if hints else 'N/A'}"
            )

        top_global = [f"{k}({v})" for k, v in self.cwe_counter.most_common(6)]
        return (
            f"Global CVE records loaded: {self.total_records}\n"
            f"Most frequent CWE: {', '.join(top_global) if top_global else 'N/A'}\n"
            "No direct family match for this alert. Use strict code evidence."
        )

    def get_family_default(self, family: str) -> Tuple[str, str]:
        defaults = {
            "buffer_overflow": ("CWE-120", "Buffer Overflow"),
            "null_pointer": ("CWE-476", "Null Pointer Dereference"),
            "memory_leak": ("CWE-401", "Memory Leak"),
            "double_free": ("CWE-415", "Double Free"),
            "use_after_free": ("CWE-416", "Use After Free"),
            "out_of_bounds": ("CWE-787", "Out-of-Bounds Access"),
            "integer_overflow": ("CWE-190", "Integer Overflow"),
            "format_string": ("CWE-134", "Format String Vulnerability"),
            "command_injection": ("CWE-78", "Command Injection"),
            "race_condition": ("CWE-362", "Race Condition"),
            "resource_exhaustion": ("CWE-400", "Resource Exhaustion"),
            "path_traversal": ("CWE-22", "Path Traversal"),
            "type_confusion": ("CWE-843", "Type Confusion"),
            "heap_corruption": ("CWE-122", "Heap Corruption"),
            "pointer_arithmetic": ("CWE-468", "Pointer Arithmetic Error"),
        }
        return defaults.get(family, ("CWE-000", "Unknown"))
