# Requirements

本项目分为 **Python 运行环境**、**Joern 静态分析工具链**、**LLM（可选但强烈建议）**、以及 **HuggingFace 数据集依赖（可选）** 四部分。

---

## 1) Python

- **版本**：Python 3.10+（推荐 3.12）
- **安装依赖**：

```bash
pip install -r requirements.txt
```

`requirements.txt` 覆盖：
- `requests`：LLM API 调用
- `pandas`：HuggingFace 数据集处理/统计
- `datasets`：HuggingFace 数据集加载（仅在使用 `primevul/secvul` 时需要）

---

## 2) Joern（必需，用于 C/C++ 静态分析）

### 2.1 必需文件
在 `config.py` 中配置以下路径（Windows 常见为 `*.bat`）：
- `JOERN_PATH`：joern-cli 解压目录
- `JOERN_PARSE / JOERN_EXPORT / JOERN_BAT`

### 2.2 快速自检
确保下列文件存在：
- `JOERN_PARSE(.bat)`
- `JOERN_EXPORT(.bat)`
- `joern(.bat)`

---

## 3) LLM（推荐）

项目仅支持 **国产大模型**（OpenAI **兼容**的 Chat Completions 协议）。合法 `LLM_PROVIDER` 取值见 `config.ALLOWED_LLM_PROVIDERS`：

`deepseek` · `qwen`（阿里通义）· `wenxin`（百度文心/千帆）· `doubao`（豆包/火山方舟）· `kimi`（月之暗面）· `zhipu`（智谱）· `hunyuan`（腾讯混元）。  
旧标识如 `moonshot` 会映射为 `kimi`；非列表内标识会回退为 `deepseek`。

推荐用环境变量配置（Windows PowerShell 示例）：

```powershell
$env:LLM_PROVIDER="deepseek"
$env:LLM_API_KEY="你的密钥"
# LLM_API_BASE / LLM_MODEL 可留空，使用各厂商内置默认（见 agent.py provider_presets）
```

说明：

- UI 模式下也可在前端填写供应商 / Base URL / Model / API Key，后端会按请求覆盖进程内配置。

---

## 4) HuggingFace 数据集（可选）

当使用 `primevul / secvul` 数据源时，需要：
- `datasets`（Python 包）
- 可访问 HuggingFace Hub（或镜像）

镜像配置：
- 数据集加载已强制走 `HF_MIRROR_ENDPOINT`（默认 `https://hf-mirror.com`），并在加载前设置 `HF_ENDPOINT` 等变量
- UI 数据集扫描中可勾选 “Use HF mirror”

---

## 5) Windows 常见问题

- **路径包含空格**：命令行/配置中尽量使用双引号包裹路径
- **端口被占用**：更换 `--port`（如 8001），并确保前端 `Backend URL` 同步修改
- **编码/乱码**：建议 PowerShell/终端使用 UTF-8；本项目已尽量在输出与文件读写中使用 `utf-8, errors=replace`

