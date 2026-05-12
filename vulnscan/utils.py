import os
import json
import hashlib
import datetime
from typing import Any, Dict


def add_line_numbers(code: str) -> str:
    """为源码每行前置行号（仅用于展示/调试；Joern 解析请使用原始源码，见 main.py / vulnscan.project_scanner）"""
    lines = code.split("\n")
    return "\n".join([f"{i+1}: {line}" for i, line in enumerate(lines)])


def save_json(data: Any, filepath: str) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def md5_text(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


def file_signature(path: str) -> Dict[str, Any]:
    """用于断点续扫的轻量签名：mtime + size"""
    st = os.stat(path)
    # float/整数均可，跨平台统一用 int
    return {"mtime": int(st.st_mtime), "size": int(st.st_size)}


def safe_relpath_id(root_dir: str, file_path: str, max_len: int = 200) -> str:
    """
    将相对路径转为可作为文件名的稳定 id（避免目录分隔符冲突）。
    """
    rel = os.path.relpath(file_path, root_dir)
    rel = rel.replace("\\", "/")
    rel_id = rel.replace("/", "__")
    # 过长时用 hash 截断
    if len(rel_id) > max_len:
        h = hashlib.md5(rel.encode("utf-8", errors="ignore")).hexdigest()[:12]
        rel_id = rel_id[: max_len - 13] + "_" + h
    return rel_id


def now_iso() -> str:
    return datetime.datetime.now().isoformat()

