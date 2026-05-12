import os
from typing import Any, Dict, Optional

from .utils import save_json, now_iso


class CheckpointStore:
    """
    断点续扫：记录每个文件的签名（mtime + size）与对应的落盘报告路径。
    """

    def __init__(self, checkpoint_path: str):
        self.checkpoint_path = checkpoint_path
        self._data: Dict[str, Any] = {"version": 1, "items": {}}

    def load(self) -> None:
        if os.path.exists(self.checkpoint_path):
            try:
                import json

                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception:
                # 损坏时从头开始（不影响检测准确性，只影响是否能续扫）
                self._data = {"version": 1, "items": {}}

    def should_skip(self, rel_id: str, signature: Dict[str, Any]) -> bool:
        item = self._data.get("items", {}).get(rel_id)
        if not item:
            return False
        return item.get("signature") == signature and item.get("status") == "done"

    def mark_done(
        self,
        rel_id: str,
        signature: Dict[str, Any],
        report_path: str,
        total_vulnerabilities: int = 0,
    ) -> None:
        self._data.setdefault("items", {})
        self._data["items"][rel_id] = {
            "signature": signature,
            "status": "done",
            "report_path": report_path,
            "total_vulnerabilities": int(total_vulnerabilities),
            "done_at": now_iso(),
        }
        self.flush()

    def flush(self) -> None:
        tmp_path = self.checkpoint_path + ".tmp"
        save_json(self._data, tmp_path)
        os.replace(tmp_path, self.checkpoint_path)

