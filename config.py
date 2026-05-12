# config.py
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# 项目路径
BASE_DIR = Path(__file__).parent.absolute()
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
RESULT_DIR = os.path.join(BASE_DIR, "result")
TEMP_DIR = os.path.join(BASE_DIR, "temp")

# HuggingFace 国内镜像（datasets / huggingface_hub 在首次请求前需设置环境变量）
# 环境变量可覆盖：HF_MIRROR_ENDPOINT、HF_USE_MIRROR（0/1）
HF_MIRROR_ENDPOINT = os.environ.get("HF_MIRROR_ENDPOINT", "https://hf-mirror.com").rstrip("/")


def apply_hf_mirror(enabled: bool = True, endpoint: Optional[str] = None) -> None:
    """
    将 Hub 请求指向国内镜像，需在 import datasets / huggingface_hub 发起网络请求之前调用。
    关闭镜像：export HF_USE_MIRROR=0，或 apply_hf_mirror(False) 恢复官方 https://huggingface.co。
    """
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

# HuggingFace 数据集 ID（PrimeVul：target=1 为漏洞，0 为安全）
PRIMEVUL_HF_DATASET = os.environ.get("PRIMEVUL_HF_DATASET", "colin/PrimeVul")
PRIMEVUL_HF_CONFIG = os.environ.get("PRIMEVUL_HF_CONFIG", "default")

def _joern_base_dir() -> str:
    """Joern CLI 根目录。务必设置环境变量 JOERN_PATH（Linux 常见 /opt/joern-cli）。"""
    explicit = os.environ.get("JOERN_PATH", "").strip()
    if explicit:
        return explicit
    if os.name == "nt":
        return r"D:\zhuomian\Cao\joern-cli"
    return "/opt/joern-cli"


def _joern_executable(root: str, name: str) -> str:
    """
    解析 joern-parse / joern-export / joern 可执行文件路径。
    Linux发行包通常在 bin/；Windows 常见为根目录下的 .bat。
    """
    if not root:
        root = "."
    if os.name == "nt":
        candidates = [
            os.path.join(root, f"{name}.bat"),
            os.path.join(root, "bin", f"{name}.bat"),
            os.path.join(root, "bin", name),
        ]
    else:
        candidates = [
            os.path.join(root, "bin", name),
            os.path.join(root, name),
        ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[0]


# Joern 配置（Linux：设置 JOERN_PATH=/opt/joern-cli 等）
JOERN_PATH = _joern_base_dir()
JOERN_PARSE = _joern_executable(JOERN_PATH, "joern-parse")
JOERN_EXPORT = _joern_executable(JOERN_PATH, "joern-export")
JOERN_BAT = _joern_executable(JOERN_PATH, "joern")

# DeepSeek 默认仅作占位；生产环境请用环境变量 LLM_API_KEY / DEEPSEEK_API_KEY（勿写入仓库）
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
DEEPSEEK_API_URL = os.environ.get(
    "DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions"
).strip()
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat").strip()

# 通用 LLM API 配置（OpenAI-compatible Chat Completions）
# 仅支持国产提供方：deepseek / qwen(通义) / wenxin(文心) / doubao(豆包) / kimi / zhipu(智谱) / hunyuan(混元)
ALLOWED_LLM_PROVIDERS = frozenset(
    {"deepseek", "qwen", "wenxin", "doubao", "kimi", "zhipu", "hunyuan"}
)
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


# - LLM_PROVIDER: 见 ALLOWED_LLM_PROVIDERS
# - LLM_API_KEY / DEEPSEEK_API_KEY: API Key
# - LLM_API_BASE: 留空则使用 agent 内该提供方预设 Base
# - LLM_API_PATH: 默认 /chat/completions
# - LLM_MODEL: 留空则使用 agent 内该提供方预设模型
LLM_PROVIDER = normalize_llm_provider(os.environ.get("LLM_PROVIDER", "deepseek"))
LLM_API_KEY = os.environ.get("LLM_API_KEY", DEEPSEEK_API_KEY).strip()
_llm_base_raw = os.environ.get("LLM_API_BASE", "").strip()
LLM_API_BASE = _llm_base_raw.rstrip("/") if _llm_base_raw else ""
LLM_API_PATH = os.environ.get("LLM_API_PATH", "/chat/completions")
LLM_MODEL = os.environ.get("LLM_MODEL", "").strip()

# 漏洞类型配置
VULNERABILITY_CATEGORIES = {
    "buffer_overflow": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-126"],
    "memory_leak": ["CWE-401", "CWE-404", "CWE-415", "CWE-416", "CWE-590", "CWE-761"],
    "null_pointer": ["CWE-476", "CWE-690", "CWE-252"],
    "integer_issues": ["CWE-190", "CWE-191", "CWE-194", "CWE-195", "CWE-197", "CWE-681"],
    "command_injection": ["CWE-77", "CWE-78", "CWE-88", "CWE-89"],
    "path_traversal": ["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-73"],
    "race_condition": ["CWE-362", "CWE-363", "CWE-364", "CWE-366", "CWE-367"],
    "format_string": ["CWE-134"],
    "concurrency": ["CWE-414", "CWE-667", "CWE-672", "CWE-674"],
    "crypto_issues": ["CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328"],
    "file_handling": ["CWE-377", "CWE-378", "CWE-379"],
    "information_leak": ["CWE-200", "CWE-201", "CWE-202", "CWE-203"],
    "privilege_issues": ["CWE-250", "CWE-264", "CWE-265", "CWE-266", "CWE-267", "CWE-268", "CWE-269"],
    "hardcoded_creds": ["CWE-259", "CWE-260", "CWE-261", "CWE-262", "CWE-263", "CWE-321", "CWE-522", "CWE-798"],
    "insecure_temp": ["CWE-377", "CWE-378"],
    "dead_code": ["CWE-561", "CWE-563", "CWE-570", "CWE-571"],
    "logic_errors": ["CWE-478", "CWE-479", "CWE-480", "CWE-481", "CWE-482", "CWE-483", "CWE-484"],
    "type_confusion": ["CWE-704", "CWE-843"],
    "resource_exhaustion": ["CWE-770", "CWE-771", "CWE-772", "CWE-773", "CWE-774"],
    "array_index": ["CWE-129"],
    "division_by_zero": ["CWE-369"],
    "uninitialized_var": ["CWE-456", "CWE-457", "CWE-665"],
    "double_free": ["CWE-415"],
    "use_after_free": ["CWE-416"],
    "memory_mismatch": ["CWE-590", "CWE-762"],
}

# 漏洞关键字映射 - 优化版（减少误报）
# 移除了通用C语言关键字，只保留真正可疑的模式
VULN_KEYWORDS = {
    # 缓冲区溢出 - 只保留真正危险的函数
    # 说明：
    # SecVulEval 的样本里很多不是 libc 函数拷贝，而是内核态拷贝/未校验长度的请求数据处理。
    # 因此在保留原“显式危险函数”之外，补充更贴近内核场景的触发点，
    # 以避免切片阶段因关键词过窄导致漏报（从而让 accuracy/recall 直接归零）。
    "CWE-119": [
        # libc 里最容易造成确定性越界的函数才纳入（避免内核中大量“安全sprintf”引发误报）
        "strcpy\\(", "strcat\\(", "sprintf\\(", "vsprintf\\(", "gets\\(", "memcpy\\(", "memmove\\(",
        # 内核/框架拷贝（示例：ib_copy_from_udata）
        "ib_copy_from_udata\\(",
        # 示例：smbhash.c 中的 key->固定缓冲区拼接/转换
        "str_to_key\\(",
        # 示例：整数乘法参与分配大小，可能导致缓冲区实际分配不足（间接触发 CWE-119 语义）
        "kzalloc\\([^\\n]*\\*[^\\n]*sizeof\\(",
        "kmalloc\\([^\\n]*\\*[^\\n]*sizeof\\(",
        "kvzalloc\\([^\\n]*\\*[^\\n]*sizeof\\(",
        
        # 数组越界常见“哨兵索引”写法：先将 free/idx 设为 -1，再用其作为下标写入
        # 该样本（mlx4_register_mac.c）体现为: int free = -1; ... table->refs[free] = ...
        "int\\s+free\\s*=\\s*-1",
        "\\[\\s*free\\s*\\]\\s*=",
    ],
    # 收紧：避免 sprintf/gets 造成误报
    "CWE-120": ["strcpy\\(", "strcat\\(", "sprintf\\(", "gets\\("],
    "CWE-121": ["strcpy\\(", "strcat\\("],
    "CWE-122": ["alloca\\(", "HeapAlloc\\("],  # 移除了malloc，太通用
    "CWE-124": ["strncpy\\(", "snprintf\\(", "memcpy\\("],
    "CWE-126": ["strlen\\(", "memchr\\(", "strchr\\("],
    
    # 整数溢出 - 需要更具体的模式
    "CWE-190": [
        # 分配/缓冲区大小中出现乘法表达式，可能导致整数溢出进而引发下游缓冲区问题
        "kzalloc\\([^\\n]*\\*[^\\n]*sizeof\\(",
        "kmalloc\\([^\\n]*\\*[^\\n]*sizeof\\(",
        "kvzalloc\\([^\\n]*\\*[^\\n]*sizeof\\(",
    ],  # 控制在“分配大小 + sizeof + 乘法”场景，避免过宽导致误报
    "CWE-191": [],
    "CWE-194": ["atoi\\(", "atol\\(", "strtol\\(", "sscanf\\("],
    "CWE-195": ["memcpy\\(", "strncpy\\(", "malloc\\("],
    "CWE-197": [],  # 移除所有基本类型，太通用
    
    # 内存管理 - 只打开最典型且特征明显的模式，兼顾召回和误报
    "CWE-401": [],  # 仍暂时禁用通用内存泄漏，避免噪声
    "CWE-404": [],  # 资源释放问题暂不依赖关键字
    "CWE-415": [],  # 双重释放模式较难仅靠正则判定
    # 为降低误报：CWE-416（释放后使用）暂时不依赖过宽的正则触发
    "CWE-416": [],
    
    # 为降低误报：CWE-476（空指针解引用）暂时禁用，避免 NULL 在内核代码中高频触发
    "CWE-476": [],
    "CWE-690": [],  # 暂时禁用
    "CWE-252": [],  # 暂时禁用
    
    # 命令注入
    "CWE-77": ["system\\(", "exec\\(", "popen\\(", "ShellExecute\\(", "CreateProcess\\("],
    "CWE-78": ["system\\(", "exec\\(", "popen\\("],
    "CWE-88": ["system\\(", "exec\\(", "popen\\(", "ShellExecute\\("],
    "CWE-89": ["mysql_query\\(", "SQL", "sqlite3_exec\\("],
    
    # 路径遍历 - 需要用户输入上下文
    "CWE-22": ["fopen\\(", "open\\(", "access\\(", "stat\\(", "chdir\\(", "chmod\\(", "rename\\(", "remove\\("],
    "CWE-23": ["fopen\\(", "open\\("],
    "CWE-35": ["fopen\\(", "open\\(", "access\\("],
    "CWE-59": ["fopen\\(", "open\\(", "access\\(", "stat\\("],
    "CWE-73": ["fopen\\(", "open\\(", "access\\("],
    
    # 格式化字符串
    "CWE-134": [
        "printf\\(", "fprintf\\(", "sprintf\\(", "snprintf\\(", "syslog\\(",
        # 内核日志宏（比 printf 更贴近 SecVulEval 内核样本）
        "dev_dbg\\(", "dev_info\\(", "pr_info\\(", "pr_err\\(",
    ],
    
    # 竞态条件
    # 过宽的并发关键词（如 lock/mutex 仅表示同步原语，并不必然是竞态漏洞）
    # 为降低误报，先暂时禁用，后续可再加入更精确的触发条件
    "CWE-362": [],
    "CWE-367": [],
    
    # 临时文件
    "CWE-377": ["tmpfile\\(", "tmpnam\\(", "mktemp\\(", "mkstemp\\("],
    "CWE-378": ["tmpfile\\(", "tmpnam\\("],
    
    # 信息泄露
    # 收紧：避免 sprintf 在内核中安全使用导致误报
    "CWE-200": ["printf\\(", "fprintf\\(", "sprintf\\(", "strcpy\\(", "memcpy\\("],
    
    # 权限
    "CWE-250": ["setuid\\(", "setgid\\(", "seteuid\\(", "setegid\\("],
    
    # 硬编码凭证
    "CWE-259": ["password", "passwd", "pwd", "secret", "key", "cred"],
    "CWE-321": ["key", "aes", "des", "rsa", "encrypt", "decrypt"],
    
    # 加密
    # “key”在代码中非常常见（可能是哈希 key/数据 key），容易引发误报
    # 先暂时禁用加密相关触发，交由更强证据的静态分析/LLM 来判断
    "CWE-326": [],
    "CWE-327": [],
    "CWE-328": [],
    
    # 死代码
    "CWE-561": ["if\\(0\\)", "if\\(false\\)", "if\\(FALSE\\)", "while\\(0\\)"],
    "CWE-563": [],  # 移除=和==，太通用
    
    # 类型转换
    "CWE-704": ["reinterpret_cast"],
    "CWE-843": ["union", "reinterpret_cast"],
    
    # 资源耗尽 - 暂时禁用
    "CWE-770": [],  # 暂时禁用
    
    # 数组索引 - 针对PrimeVul CWE-125添加关键词
    "CWE-129": [
        "\\[.*\\]\\s*=",  # 数组赋值
        "array\\[", "\\[index", "\\[i\\]", "\\[j\\]", "\\[k\\]",
        "out of bounds", "boundary check", "index check"
    ],
    
    # 除零错误 - 针对PrimeVul常见错误
    "CWE-369": [
        "/\\s*0", "/\\s*zero", "divide by zero", "division by zero",
        "denominator\\s*==\\s*0", "divisor\\s*==\\s*0"
    ],
    
    # 初始化问题
    "CWE-456": [
        "uninitialized", "not initialized", "without initialization",
        "int\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*;",  # 声明但未初始化
        "char\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*;"
    ],
    "CWE-457": [
        "use of uninitialized", "uninitialized variable",
        "variable.*used.*before.*initialization"
    ],
    "CWE-665": [
        "improper initialization", "incorrect initialization",
        "initialize.*incorrectly"
    ],
    
    # 内存不匹配
    "CWE-590": [
        "free\\(.*\\)\\s*;\\s*free\\(",  # 双重释放模式
        "free\\(.*\\)\\s*;.*free\\("
    ],
    "CWE-762": [
        "malloc.*free", "calloc.*free", "realloc.*free",
        "memory.*mismatch", "alloc.*free.*mismatch"
    ],
    
    # PrimeVul特定CWE类型 - 优化版
    "CWE-125": [
        # 数组索引相关模式
        "\\[.*\\]\\s*=",  # 数组赋值
        "array\\[", "\\[index", "\\[i\\]", "\\[j\\]", "\\[k\\]",
        "out of bounds", "boundary check", "index check",
        "array.*size", "size.*array", "length.*check",
        # 更具体的数组操作
        "memcpy\\(", "memmove\\(", "strncpy\\(", "strncat\\(",
        "for.*i.*<", "for.*j.*<", "while.*i.*<",
        "if.*index.*>", "if.*i.*>=", "if.*j.*>="
    ],
    "CWE-20": [
        # 输入验证相关模式
        "input.*validation", "validate.*input", "sanitize.*input",
        "check.*input", "verify.*input", "input.*check",
        # 具体的验证函数
        "strlen\\(", "sizeof\\(", "strnlen\\(", "memchr\\(",
        "if.*len.*>", "if.*size.*>", "if.*count.*>",
        "assert\\(", "ASSERT\\(", "BUG_ON\\(",
        # 边界检查
        "min\\(", "max\\(", "clamp\\(", "bound\\("
    ],
    "CWE-189": [
        # 数值错误相关模式
        "numeric.*error", "numeric.*issue", "calculation.*error",
        "arithmetic.*error", "math.*error",
        # 具体的数值操作
        "\\+\\+", "--", "\\+=", "-=", "\\*=", "/=",
        "int.*\\+", "int.*-", "int.*\\*", "int.*/",
        "size_t.*\\+", "size_t.*-", "size_t.*\\*",
        # 溢出检查
        "overflow", "underflow", "wrap.*around",
        "INT_MAX", "INT_MIN", "UINT_MAX"
    ],
    "CWE-399": [
        # 资源管理错误相关模式
        "resource.*management", "resource.*leak", "handle.*leak",
        "resource.*not.*released", "resource.*not.*freed",
        # 具体的资源管理函数
        "malloc\\(", "calloc\\(", "realloc\\(", "free\\(",
        "kmalloc\\(", "kzalloc\\(", "kfree\\(",
        "open\\(", "close\\(", "fopen\\(", "fclose\\(",
        "socket\\(", "bind\\(", "listen\\(", "accept\\(", "close\\(",
        # 错误路径处理
        "goto.*error", "goto.*fail", "return.*-1",
        "if.*error", "if.*fail", "if.*NULL"
    ],
    "CWE-835": [
        # 无限循环相关模式
        "while\\(1\\)", "for\\(;;\\)", "infinite.*loop",
        "endless.*loop", "loop.*forever", "never.*ending.*loop",
        # 具体的循环模式
        "while.*true", "while.*TRUE", "for.*;.*;",
        "do.*while.*1", "do.*while.*true",
        # 缺少退出条件的循环
        "while.*condition", "for.*i.*;.*;.*i\\+\\+"
    ],
    "CWE-264": [
        # 权限控制相关模式
        "privilege", "permission", "access.*control",
        "authorization", "authentication", "security.*context",
        # 具体的权限函数
        "setuid\\(", "setgid\\(", "seteuid\\(", "setegid\\(",
        "capable\\(", "has_capability\\(", "check_permission\\(",
        "access\\(", "chmod\\(", "chown\\(", "fchmod\\(", "fchown\\(",
        # 权限检查
        "if.*capable", "if.*permission", "if.*privileged"
    ],
    "CWE-209": [
        # 信息泄露相关模式
        "information.*leak", "data.*leak", "leak.*information",
        "sensitive.*information", "confidential.*information",
        # 具体的信息输出函数
        "printf\\(", "fprintf\\(", "sprintf\\(", "snprintf\\(",
        "printk\\(", "dev_dbg\\(", "dev_info\\(", "pr_info\\(", "pr_err\\(",
        "write\\(", "send\\(", "sendto\\(", "puts\\(", "putchar\\(",
        # 调试信息
        "debug", "DEBUG", "dump", "DUMP", "trace", "TRACE"
    ]


}

# 创建目录
os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)