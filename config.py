# config.py (C/C++ only)
import os
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).parent.absolute()
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
RESULT_DIR = os.path.join(BASE_DIR, "result")
TEMP_DIR = os.path.join(BASE_DIR, "temp")

HF_MIRROR_ENDPOINT = os.environ.get("HF_MIRROR_ENDPOINT", "https://hf-mirror.com").rstrip("/")


def apply_hf_mirror(enabled: bool = True, endpoint: Optional[str] = None) -> None:
    if not enabled:
        os.environ["HF_ENDPOINT"] = "https://huggingface.co"
        os.environ.pop("HUGGINGFACE_HUB_ENDPOINT", None)
        return
    ep = (endpoint or HF_MIRROR_ENDPOINT).rstrip("/")
    os.environ["HF_ENDPOINT"] = ep
    os.environ["HUGGINGFACE_HUB_ENDPOINT"] = ep
    os.environ.setdefault("HF_HUB_DISABLE_HF_TRANSFER", "1")


def _env_hf_mirror_default_on() -> bool:
    v = os.environ.get("HF_USE_MIRROR", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


if _env_hf_mirror_default_on():
    apply_hf_mirror(True)

PRIMEVUL_HF_DATASET = os.environ.get("PRIMEVUL_HF_DATASET", "colin/PrimeVul")
PRIMEVUL_HF_CONFIG = os.environ.get("PRIMEVUL_HF_CONFIG", "default")


def _joern_base_dir() -> str:
    explicit = os.environ.get("JOERN_PATH", "").strip()
    if explicit:
        return explicit
    if os.name == "nt":
        return r"D:\zhuomian\Cao\joern-cli"
    return "/opt/joern-cli"


def _joern_executable(root: str, name: str) -> str:
    if not root:
        root = "."
    if os.name == "nt":
        candidates = [
            os.path.join(root, f"{name}.bat"),
            os.path.join(root, "bin", f"{name}.bat"),
            os.path.join(root, "bin", name),
        ]
    else:
        candidates = [os.path.join(root, "bin", name), os.path.join(root, name)]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[0]


JOERN_PATH = _joern_base_dir()
JOERN_PARSE = _joern_executable(JOERN_PATH, "joern-parse")
JOERN_EXPORT = _joern_executable(JOERN_PATH, "joern-export")
JOERN_BAT = _joern_executable(JOERN_PATH, "joern")

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
DEEPSEEK_API_URL = os.environ.get("DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions").strip()
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat").strip()

ALLOWED_LLM_PROVIDERS = frozenset({"deepseek", "qwen", "wenxin", "doubao", "kimi", "zhipu", "hunyuan"})
LLM_PROVIDER_ALIASES = {
    "moonshot": "kimi",
    "tongyi": "qwen",
    "dashscope": "qwen",
    "ernie": "wenxin",
    "qianfan": "wenxin",
    "baidu": "wenxin",
    "volcengine": "doubao",
    "ark": "doubao",
    "bytedance": "doubao",
    "glm": "zhipu",
    "bigmodel": "zhipu",
    "tencent": "hunyuan",
}


def normalize_llm_provider(name: Optional[str]) -> str:
    p = (name or "deepseek").strip().lower()
    p = LLM_PROVIDER_ALIASES.get(p, p)
    if p not in ALLOWED_LLM_PROVIDERS:
        return "deepseek"
    return p


LLM_PROVIDER = normalize_llm_provider(os.environ.get("LLM_PROVIDER", "deepseek"))
LLM_API_KEY = os.environ.get("LLM_API_KEY", DEEPSEEK_API_KEY).strip()
_llm_base_raw = os.environ.get("LLM_API_BASE", "").strip()
LLM_API_BASE = _llm_base_raw.rstrip("/") if _llm_base_raw else ""
LLM_API_PATH = os.environ.get("LLM_API_PATH", "/chat/completions")
LLM_MODEL = os.environ.get("LLM_MODEL", "").strip()

VULNERABILITY_CATEGORIES = {
    "buffer_overflow": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-126"],
    "memory_leak": ["CWE-401", "CWE-404", "CWE-415", "CWE-416", "CWE-590", "CWE-761"],
    "null_pointer": ["CWE-476", "CWE-690", "CWE-252"],
    "integer_issues": ["CWE-190", "CWE-191", "CWE-194", "CWE-195", "CWE-197", "CWE-681"],
    "command_injection": ["CWE-77", "CWE-78", "CWE-88", "CWE-89"],
    "path_traversal": ["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-73"],
    "format_string": ["CWE-134"],
    "array_index": ["CWE-129"],
    "division_by_zero": ["CWE-369"],
    "uninitialized_var": ["CWE-456", "CWE-457", "CWE-665"],
}

VULN_KEYWORDS = {
    "CWE-119": ["strcpy\\(", "strcat\\(", "sprintf\\(", "vsprintf\\(", "gets\\(", "memcpy\\(", "memmove\\("],
    "CWE-120": ["strcpy\\(", "strcat\\(", "sprintf\\(", "gets\\("],
    "CWE-121": ["strcpy\\(", "strcat\\("],
    "CWE-124": ["strncpy\\(", "snprintf\\(", "memcpy\\("],
    "CWE-126": ["strlen\\(", "memchr\\(", "strchr\\("],
    "CWE-190": ["kzalloc\\([^\\n]*\\*[^\\n]*sizeof\\(", "kmalloc\\([^\\n]*\\*[^\\n]*sizeof\\("],
    "CWE-194": ["atoi\\(", "atol\\(", "strtol\\(", "sscanf\\("],
    "CWE-195": ["memcpy\\(", "strncpy\\(", "malloc\\("],
    "CWE-401": [],
    "CWE-404": [],
    "CWE-415": [],
    "CWE-416": [],
    "CWE-476": [],
    "CWE-690": [],
    "CWE-252": [],
    "CWE-77": ["system\\(", "exec\\(", "popen\\("],
    "CWE-78": ["system\\(", "exec\\(", "popen\\("],
    "CWE-89": ["mysql_query\\(", "sqlite3_exec\\("],
    "CWE-22": ["fopen\\(", "open\\(", "access\\(", "stat\\(", "chdir\\(", "chmod\\(", "rename\\(", "remove\\("],
    "CWE-23": ["fopen\\(", "open\\("],
    "CWE-35": ["fopen\\(", "open\\(", "access\\("],
    "CWE-59": ["fopen\\(", "open\\(", "access\\(", "stat\\("],
    "CWE-73": ["fopen\\(", "open\\(", "access\\("],
    "CWE-134": ["printf\\(", "fprintf\\(", "sprintf\\(", "snprintf\\(", "syslog\\("],
    "CWE-200": ["printf\\(", "fprintf\\(", "sprintf\\(", "strcpy\\(", "memcpy\\("],
    "CWE-250": ["setuid\\(", "setgid\\(", "seteuid\\(", "setegid\\("],
    "CWE-259": ["password", "passwd", "pwd", "secret", "key", "cred"],
    "CWE-321": ["key", "aes", "des", "rsa", "encrypt", "decrypt"],
    "CWE-561": ["if\\(0\\)", "if\\(false\\)", "if\\(FALSE\\)", "while\\(0\\)"],
    "CWE-704": ["reinterpret_cast"],
    "CWE-843": ["union", "reinterpret_cast"],
    "CWE-129": ["\\[.*\\]\\s*=", "array\\[", "\\[index", "\\[i\\]", "\\[j\\]", "\\[k\\]"],
    "CWE-369": ["/\\s*0", "divide by zero", "division by zero"],
    "CWE-456": ["uninitialized", "not initialized", "without initialization"],
    "CWE-457": ["use of uninitialized", "uninitialized variable"],
    "CWE-665": ["improper initialization", "incorrect initialization"],
    "CWE-590": ["free\\(.*\\)\\s*;\\s*free\\(", "free\\(.*\\)\\s*;.*free\\("],
    "CWE-762": ["malloc.*free", "calloc.*free", "realloc.*free", "memory.*mismatch"],
    "CWE-125": ["\\[.*\\]\\s*=", "array\\[", "out of bounds", "boundary check", "index check"],
    "CWE-20": ["input.*validation", "validate.*input", "sanitize.*input", "check.*input", "verify.*input"],
    "CWE-189": ["overflow", "underflow", "INT_MAX", "INT_MIN", "UINT_MAX"],
    "CWE-399": ["resource.*management", "resource.*leak", "malloc\\(", "free\\(", "open\\(", "close\\("],
    "CWE-835": ["while\\(1\\)", "for\\(;;\\)", "infinite.*loop"],
    "CWE-264": ["privilege", "permission", "access.*control", "authorization", "authentication"],
    "CWE-209": ["information.*leak", "data.*leak", "sensitive.*information", "debug", "trace"],
}

os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)
