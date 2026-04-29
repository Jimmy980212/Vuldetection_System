"""
C/C++ only HuggingFace dataset adapter.
Only keeps PrimeVul / SecVulEval loading required by CLI detect mode.
"""

import logging
import os
import random
from typing import Any, Dict, List

from config import PRIMEVUL_HF_CONFIG, PRIMEVUL_HF_DATASET, apply_hf_mirror
from dataset import CodeSample

logger = logging.getLogger(__name__)


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _normalize_cwe_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v] if v.strip() else []
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v).strip()] if str(v).strip() else []


class System4DatasetAdapter:
    """C/C++ dataset adapter for PrimeVul and SecVulEval only."""

    def __init__(self, use_huggingface: bool = True):
        self.use_huggingface = bool(use_huggingface)

    def _load_hf_split(self, dataset_name: str, split: str, config_name: str = ""):
        if not self.use_huggingface:
            return []
        apply_hf_mirror(True)
        logger.info("HF dataset endpoint: %s", os.environ.get("HF_ENDPOINT", ""))
        from datasets import load_dataset

        if config_name:
            return load_dataset(dataset_name, config_name, split=split)
        return load_dataset(dataset_name, split=split)

    @staticmethod
    def _to_codesample(
        code: str,
        file_name: str,
        project: str,
        idx: int,
        is_vulnerable: bool,
        cwe_list: List[str],
    ) -> CodeSample:
        sample = CodeSample(file_name, code)
        sample.file_name = file_name
        sample.file_path = file_name
        sample.project = project or "default"
        sample.idx = idx
        sample.is_vulnerable = bool(is_vulnerable)
        sample.cwe_list = list(cwe_list or [])
        return sample

    def load_primevul_balanced(
        self,
        total_samples: int,
        vuln_ratio: float = 0.5,
        split: str = "train",
        seed: int = 42,
    ) -> List[CodeSample]:
        random.seed(seed)
        total = max(1, int(total_samples))
        need_v = max(0, int(round(total * float(vuln_ratio))))
        need_s = max(0, total - need_v)

        ds = self._load_hf_split(PRIMEVUL_HF_DATASET, split, PRIMEVUL_HF_CONFIG)
        vuln_rows: List[Dict[str, Any]] = []
        safe_rows: List[Dict[str, Any]] = []
        for row in ds:
            r = dict(row)
            code = str(r.get("func") or "").strip()
            if len(code) < 10:
                continue
            if _to_int(r.get("target"), 0) == 1:
                vuln_rows.append(r)
            else:
                safe_rows.append(r)

        random.shuffle(vuln_rows)
        random.shuffle(safe_rows)
        picked = vuln_rows[:need_v] + safe_rows[:need_s]
        random.shuffle(picked)

        out: List[CodeSample] = []
        for i, r in enumerate(picked):
            idx = _to_int(r.get("idx"), i)
            project = str(r.get("project") or "primevul").replace("/", "_").replace("\\", "_")
            file_name = f"pv_{idx}_{project}.c"
            out.append(
                self._to_codesample(
                    code=str(r.get("func") or ""),
                    file_name=file_name,
                    project=project,
                    idx=idx,
                    is_vulnerable=(_to_int(r.get("target"), 0) == 1),
                    cwe_list=_normalize_cwe_list(r.get("cwe")),
                )
            )
        logger.info("PrimeVul 采样完成: %s 条", len(out))
        return out

    def load_secvul_balanced(
        self,
        total_samples: int,
        vuln_ratio: float = 0.5,
        split: str = "train",
        seed: int = 42,
    ) -> List[CodeSample]:
        random.seed(seed)
        total = max(1, int(total_samples))
        need_v = max(0, int(round(total * float(vuln_ratio))))
        need_s = max(0, total - need_v)

        ds = self._load_hf_split("SecVulEval", split)
        vuln_rows: List[Dict[str, Any]] = []
        safe_rows: List[Dict[str, Any]] = []
        for row in ds:
            r = dict(row)
            code = str(r.get("func") or r.get("code") or r.get("func_body") or "").strip()
            if len(code) < 10:
                continue
            target_v = r.get("target", r.get("is_vulnerable", 0))
            if _to_int(target_v, 0) == 1:
                vuln_rows.append(r)
            else:
                safe_rows.append(r)

        random.shuffle(vuln_rows)
        random.shuffle(safe_rows)
        picked = vuln_rows[:need_v] + safe_rows[:need_s]
        random.shuffle(picked)

        out: List[CodeSample] = []
        for i, r in enumerate(picked):
            idx = _to_int(r.get("idx"), i)
            project = str(r.get("project") or "secvul").replace("/", "_").replace("\\", "_")
            file_name = f"sv_{idx}_{project}.c"
            code = str(r.get("func") or r.get("code") or r.get("func_body") or "")
            out.append(
                self._to_codesample(
                    code=code,
                    file_name=file_name,
                    project=project,
                    idx=idx,
                    is_vulnerable=(_to_int(r.get("target", r.get("is_vulnerable", 0)), 0) == 1),
                    cwe_list=_normalize_cwe_list(r.get("cwe")),
                )
            )
        logger.info("SecVulEval 采样完成: %s 条", len(out))
        return out

