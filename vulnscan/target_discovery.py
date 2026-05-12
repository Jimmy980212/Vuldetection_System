import os
from typing import Iterable, Iterator, List, Optional, Set


DEFAULT_IGNORE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "result",
    "temp",
    "venv",
    ".venv",
}


def iter_code_files(
    root_dir: str,
    extensions: Iterable[str],
    ignore_dirs: Optional[Set[str]] = None,
    max_files: Optional[int] = None,
) -> Iterator[str]:
    """
    流式遍历代码文件，避免一次性把全项目加载到内存。
    """
    ignore = set(DEFAULT_IGNORE_DIRS)
    if ignore_dirs:
        ignore |= set(ignore_dirs)

    exts = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions}

    count = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 原地修改 dirnames，控制 os.walk 继续深挖哪些目录
        dirnames[:] = [d for d in dirnames if d not in ignore and not d.startswith(".")]

        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in exts:
                yield os.path.join(dirpath, fn)
                count += 1
                if max_files is not None and count >= max_files:
                    return

