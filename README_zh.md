# VulDetection

基于多智能体的自动化漏洞检测系统，专为 C/C++ 代码库设计，结合静态分析工具（Cppcheck、Joern）和大语言模型，实现智能化的漏洞分类与验证。

## 功能特性

- **多智能体架构**：五个专业智能体协同工作
  - `PreprocessAgent`：协调 Cppcheck 和 Joern 静态分析
  - `FeatureAgent`：从代码上下文中提取语义特征
  - `InferenceAgent`：基于大语言模型的漏洞推理与分类
  - `ValidationAgent`：与 CVE 知识库交叉验证发现
  - `ReportAgent`：生成全面的漏洞报告

- **双静态分析引擎**：结合 Cppcheck 和 Joern 实现全面覆盖
  - Cppcheck：快速、基于规则的分析，检测常见漏洞模式
  - Joern：深度代码属性图分析，处理复杂漏洞

- **大语言模型增强分析**：支持多种大语言模型：
  - DeepSeek v4 Pro（默认）
  - OpenAI GPT-4/4o
  - Ollama（本地模型，如 CodeLlama、Qwen2.5-Coder）
  - Azure OpenAI
  - 上下文感知的漏洞分类
  - 减少误报
  - 结合 CWE 的严重程度评估
  - 主 Provider 失败时自动回退

- **多种输出格式**：支持 JSON、Markdown 和 CSV 格式的报告

## 支持的漏洞类型

| 类别 | CWE 覆盖 |
|----------|--------------|
| 缓冲区溢出 | CWE-120, CWE-121, CWE-122, CWE-119 |
| 空指针 | CWE-476, CWE-125 |
| 内存泄漏 | CWE-401, CWE-404 |
| 双重释放 | CWE-415, CWE-590 |
| 释放后使用 | CWE-416, CWE-825 |
| 越界访问 | CWE-787, CWE-125, CWE-126, CWE-193 |
| 整数溢出 | CWE-190, CWE-680, CWE-191 |
| 格式化字符串 | CWE-134 |
| 命令注入 | CWE-78, CWE-77, CWE-74 |
| 竞态条件 | CWE-362, CWE-367, CWE-667 |
| 路径遍历 | CWE-22, CWE-23, CWE-24 |
| 以及更多... | |

## 环境要求

- **Python**：3.10 或更高版本
- **操作系统**：Windows、Linux、macOS
- **依赖项**：详见 `requirements.txt`
- **外部工具**（可选）：
  - [Cppcheck](http://cppcheck.sourceforge.net/) - 静态代码分析
  - [Joern](https://joern.io/) - 代码属性图分析（Windows 上需要 WSL）

## 安装步骤

1. 克隆仓库：
```bash
git clone <仓库地址>
cd vuldetection
```

2. 安装 Python 依赖：
```bash
pip install -r requirements.txt
```

3. （可选）安装 Cppcheck：
   - **Windows**：从 [cppcheck.sourceforge.net](http://cppcheck.sourceforge.net/) 下载
   - **Linux**：`sudo apt install cppcheck` 或 `brew install cppcheck`
   - **WSL（用于在 Windows 上运行 Joern）**：安装 WSL 发行版和 Joern

4. （可选）安装 Joern：
   - 访问 [joern.io 网站](https://joern.io/) 获取详细安装说明
   - 在 Windows 上，确保已配置 WSL 以运行 Joern

5. 配置 API 凭证：

   在项目根目录创建 `config.json` 文件，配置你的大语言模型 Provider：
```json
{
    "llm_providers": {
        "providers": [
            {
                "name": "deepseek",
                "provider_type": "openai_compatible",
                "model_name": "deepseek-v4-pro",
                "base_url": "https://api.deepseek.com",
                "api_key": "YOUR_API_KEY_HERE",
                "enabled": true,
                "is_local": false
            },
            {
                "name": "ollama",
                "provider_type": "ollama",
                "model_name": "codellama",
                "base_url": "http://localhost:11434",
                "api_key": "",
                "enabled": false,
                "is_local": true
            }
        ],
        "default_provider": "deepseek",
        "fallback_providers": ["ollama"]
    }
}
```

   **关键配置说明：**
   - `default_provider`：主用的 LLM Provider
   - `fallback_providers`：主 Provider 失败时的备用 Provider 列表
   - `enabled`：设为 `true` 启用该 Provider
   - `is_local`：本地模型（如 Ollama）设为 `true`，云服务设为 `false`

   **Ollama 本地模型安装：**
   ```bash
   # 从 https://ollama.ai 安装 Ollama
   ollama serve
   ollama pull codellama  # 或 qwen2.5-coder
   ```

## 使用方法

### 基本用法

```python
from main import run_vulnerability_detection

result = run_vulnerability_detection(
    target_path="/path/to/your/source/code",
    cppcheck_path="/path/to/cppcheck.exe",  # 可选
    enable_joern=True,                       # 如果 Joern 不可用则设为 False
    max_alerts=30,
    analysis_workers=4
)

# 获取结果
reports = result["reports"]
scan_id = result["scan_id"]
```

### 命令行用法

```bash
python main.py
```

系统将扫描默认测试文件。修改 `main.py` 可以扫描你自己的目标代码。

### 运行测试

```bash
pytest test_scripts/ -v
```

## 项目结构

```
vuldetection/
├── agents/                  # 多智能体组件
│   ├── FeatureAgent.py      # 特征提取智能体
│   ├── InferenceAgent.py    # 大语言模型推理智能体
│   ├── PreprocessAgent.py    # 静态分析协调智能体
│   ├── ValidationAgent.py    # CVE 验证智能体
│   └── report_agent.py       # 报告生成智能体
├── core/                    # 核心系统组件
│   ├── base.py              # 基础类和接口
│   ├── contracts.py         # 数据契约和模式
│   ├── models.py            # 数据模型
│   ├── orchestrator.py      # 智能体协调器
│   ├── pipeline.py          # 分析管道
│   └── schema.py            # 模式定义
├── utils/                   # 工具模块
│   ├── cve_knowledge.py     # CVE 知识库
│   ├── llm_client.py        # LLM API 客户端（旧版）
│   ├── llm_gateway.py        # LLM 网关（旧版）
│   ├── llm_provider.py      # LLM Provider 基类
│   ├── llm_manager.py        # 多LLM管理器
│   ├── llm_providers/       # LLM Provider 实现
│   │   ├── openai_provider.py # OpenAI/Azure OpenAI Provider
│   │   └── ollama_provider.py # Ollama 本地 Provider
│   └── structured_logging.py # 日志工具
├── tools/                   # 工具和实用程序
│   └── llm_provider_manager.py # LLM Provider 管理CLI
├── data/                    # 数据文件
│   ├── CVE_collection.xlsx   # CVE 知识数据库
│   ├── joern_rules.json      # Joern 分析规则
│   └── test_codes/          # 测试代码样例
├── outputs/                 # 分析输出
│   ├── cpg/                 # 代码属性图
│   └── reports/             # 漏洞报告
├── .github/workflows/       # CI/CD 流水线
├── main.py                  # 入口文件
├── requirements.txt         # Python 依赖
└── pytest.ini              # 测试配置
```

## 输出格式

系统生成全面的漏洞报告：

### JSON 报告格式
```json
{
  "scan_id": "20260408_120000_abc123",
  "target_path": "/path/to/code",
  "findings": [
    {
      "file": "vulnerable.c",
      "line": 42,
      "vulnerability_type": "buffer_overflow",
      "cwe": "CWE-120",
      "severity": "high",
      "confidence": 0.85,
      "description": "..."
    }
  ]
}
```

### 风险等级
- **高危（High）**：需要立即处理的严重漏洞
- **中危（Medium）**：需要审查的重要漏洞
- **低危（Low）**：轻微问题或信息性发现
- **需要审核（Needs Review）**：需要人工验证的发现

## 配置选项

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `target_path` | string | 必填 | 源代码路径 |
| `cppcheck_path` | string | 自动 | Cppcheck 可执行文件路径 |
| `enable_joern` | bool | True | 启用 Joern 分析 |
| `max_alerts` | int | 30 | 最大处理的告警数量 |
| `analysis_workers` | int | 4 | 并行分析工作线程数 |
| `wsl_distro` | string | None | WSL 发行版（Windows 上运行 Joern） |

### LLM Provider 管理

使用 CLI 工具管理你的大语言模型 Provider：

```bash
# 列出所有已配置的 Provider
python tools/llm_provider_manager.py list

# 检查 Provider 健康状态
python tools/llm_provider_manager.py status

# 显示当前活动的 Provider
python tools/llm_provider_manager.py current

# 切换默认 Provider
python tools/llm_provider_manager.py set-default ollama

# 启用/禁用 Provider
python tools/llm_provider_manager.py enable ollama
python tools/llm_provider_manager.py disable ollama

# 添加/移除备用 Provider
python tools/llm_provider_manager.py add-fallback ollama
python tools/llm_provider_manager.py remove-fallback ollama
```

### 支持的 LLM Provider

| Provider | 类型 | 需要API | 说明 |
|----------|------|---------|------|
| DeepSeek | 云端 | 是 | 默认，`deepseek-v4-pro` 模型 |
| OpenAI | 云端 | 是 | GPT-4、GPT-4o |
| Ollama | 本地 | 否 | 通过 `ollama serve` 本地运行模型 |
| Azure OpenAI | 云端 | 是 | 企业用户 |

## CI/CD 集成

项目包含 GitHub Actions 工作流用于质量门禁：

```bash
# 本地运行所有质量门禁测试
pytest -q -k "schema_gate or performance_gate or precision_gate"
```

## 性能说明

- **CPG 生成**：Joern 生成的代码属性图可以保存复用
- **并行处理**：使用 `analysis_workers` 控制并发数
- **告警限制**：使用 `max_alerts` 防止大型代码库的分析失控

## 许可证

本项目仅供教育和研究目的使用。

## 致谢

- [Cppcheck](http://cppcheck.sourceforge.net/)
- [Joern](https://joern.io/)
- [DeepSeek](https://deepseek.com/) 提供的大语言模型能力
