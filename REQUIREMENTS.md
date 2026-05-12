# Requirements

本项目是 **纯 C/C++ CLI 漏洞检测版本**，依赖分为四部分：
- Python 运行环境
- Joern 静态分析工具链
- LLM（可选但推荐）
- HuggingFace 数据集依赖（可选）

---

## 1) Python

- 版本：Python 3.10+
- 安装依赖：

```bash
pip install -r requirements.txt
```

`requirements.txt` 主要覆盖：
- `requests`：LLM API 调用
- `pandas`：数据集统计/处理
- `datasets`：PrimeVul / SecVulEval 加载

---

## 2) Joern（必需）

### 2.1 必需文件

在 `config.py` 中配置以下路径：
- `JOERN_PATH`
- `JOERN_PARSE`
- `JOERN_EXPORT`
- `JOERN_BAT`

Windows 常见检查项：
- `joern-parse.bat`
- `joern-export.bat`
- `joern.bat`

### 2.2 作用范围

Joern 用于：
- 单文件静态分析切片
- 工程级 `scan` 模式
- `--c-workspace-cpg` 共享工作区 CPG
- reachable flows 提取

---

## 3) LLM（推荐）

项目仅支持国产 OpenAI-compatible Chat Completions 提供方，合法 `LLM_PROVIDER` 取值见 `config.ALLOWED_LLM_PROVIDERS`：
- `deepseek`
- `qwen`
- `wenxin`
- `doubao`
- `kimi`
- `zhipu`
- `hunyuan`

推荐通过环境变量设置：

```powershell
$env:LLM_PROVIDER="deepseek"
$env:LLM_API_KEY="你的密钥"
$env:LLM_API_BASE="https://api.deepseek.com/v1"
$env:LLM_MODEL="deepseek-chat"
```

---

## 4) HuggingFace 数据集（可选）

当使用以下数据源时需要：
- `primevul`
- `secvul`

所需依赖：
- `datasets`
- 可访问 HuggingFace Hub 或镜像

镜像相关：
- 默认会在加载前调用 `config.apply_hf_mirror(...)`
- 可通过 `HF_USE_MIRROR=0` 或 `--no-mirror` 关闭镜像

---

## 5) Windows 常见问题

- 路径包含空格时请加双引号
- 若终端乱码，优先使用 UTF-8 终端
- 若 Joern 报错，优先检查 `JOERN_PATH` 和 bat 文件是否存在
- 若 HuggingFace 加载失败，先检查镜像连通性或切换 `--no-mirror`
