# vulnshield-c-cli

面向 **C/C++** 的命令行漏洞检测工具，保留原项目中的 C/C++ 全检测链路：
- 本地文件/目录检测
- SecVulEval / PrimeVul 数据集检测
- 工程级 `vulnscan` 扫描
- `--c-workspace-cpg` 共享 workspace CPG / 跨文件 reachable flows
- Web 前端界面（`frontend/web_mvp.py`）

本版本已移除：Java 检测、Python 检测。

---

## 1. 环境要求

- **WSL2（推荐）**：Joern 在 Linux 环境下运行效果最佳，推荐在 WSL2 中运行本项目
- Python 3.12+
- Joern CLI（Linux 版，见下方配置）
- 可选：国产 LLM API Key（deepseek / qwen / kimi 等）
- 可选：HuggingFace 网络访问（PrimeVul / SecVulEval 数据集评估）

更完整说明见 [REQUIREMENTS.md](REQUIREMENTS.md)。

---

## 2. 安装

### WSL2（推荐）

```bash
cd /mnt/c/Users/lenovo/Desktop/vulnshield-c-cli
python3 -m venv .venv-linux
source .venv-linux/bin/activate
pip install -r requirements.txt python-dotenv
```

### Windows

```bash
cd C:\Users\lenovo\Desktop\vulnshield-c-cli
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt python-dotenv
```

---

## 3. 配置

所有配置通过项目根目录的 `.env` 文件管理（首次使用可参考 `deploy/env.example`）。

### 3.1 .env 文件

```bash
# Joern CLI 根目录
JOERN_PATH=/opt/joern/joern-cli

# LLM
LLM_PROVIDER=deepseek
LLM_API_KEY=sk-xxxxxxxx

# 以下为可选配置，留空即用各提供方默认值
# LLM_API_BASE=https://api.deepseek.com/v1
# LLM_MODEL=deepseek-v4-pro
# 也可用 deepseek-v4-flash（更快/更低成本）

# HuggingFace 镜像（国内用户保持默认即可）
# HF_USE_MIRROR=1
```

`config.py` 启动时会通过 `python-dotenv` 自动加载 `.env`，无需手动设系统环境变量。

### 3.2 Joern

在 `.env` 中设置 `JOERN_PATH` 指向 joern-cli 目录。确保目录包含：
- `bin/joern-parse`
- `bin/joern-export`
- `bin/joern`

WSL 示例：`JOERN_PATH=/opt/joern/joern-cli`

### 3.3 LLM

在 `.env` 中填写 `LLM_PROVIDER` 和 `LLM_API_KEY`。支持提供方见 `config.py` 中 `ALLOWED_LLM_PROVIDERS`（deepseek / qwen / kimi / zhipu / hunyuan 等）。

### 3.4 HuggingFace 镜像

默认启用 `https://hf-mirror.com` 国内镜像。关闭方式：

```bash
HF_USE_MIRROR=0
```

或命令行追加 `--no-mirror`。

---

## 4. CLI 用法

### 4.1 查看帮助

```bash
python main.py --help
```

### 4.2 单文件检测

```bash
python main.py --mode detect --source local --file dataset/sparse_big_less100.c --parallel 2
```

### 4.3 目录批量检测

```bash
python main.py --mode detect --source local --dir dataset --max-samples 12 --parallel 2
```

### 4.4 PrimeVul 数据集检测

```bash
python main.py --mode detect --source primevul --samples 10 --vuln-ratio 0.5 --split test --parallel 4 --seed 42
```

### 4.5 SecVulEval 数据集检测

```bash
python main.py --mode detect --source secvul --samples 10 --vuln-ratio 0.5 --split train --parallel 4 --seed 42
```

### 4.6 工程级扫描

```bash
python main.py --mode scan --lang c --root dataset/multi_c_project --parallel 2
```

### 4.7 共享 workspace CPG 扫描

```bash
python main.py --mode scan --lang c --root dataset/multi_c_project --parallel 2 --c-workspace-cpg
```

### 4.8 生成大测试文件

```bash
python main.py --mode generate-big-file --out dataset/big_test.c --blocks 200
```

---

## 5. Web 前端

项目提供了 Web 管理界面，可查看检测报告、发起扫描任务、监控 Agent 状态。

### 5.1 启动

```bash
python frontend/web_mvp.py
```

默认监听 `http://127.0.0.1:8765`，可通过 `--host` / `--port` 自定义。

### 5.2 功能页面

| 页面 | 说明 |
|------|------|
| 概览仪表盘 | 漏洞总数、严重等级分布、扫描任务状态 |
| 漏洞结果 | 查看、筛选、排序所有检测出的漏洞 |
| 检测任务 | 发起新的扫描/检测任务，查看运行日志 |
| 报告管理 | 浏览历史检测报告 |
| Agent监控 | 查看多Agent链路状态 |

前端是纯静态页面 + API 后端，在 WSL 中启动后，Windows 浏览器可直接访问 `http://127.0.0.1:8765`。

---

## 6. 输出结果

通常输出到 `result/`：
- `scan_summary.json`：汇总结果
- `*.report.json`：单文件报告
- `evaluation_reports/*.json`：数据集评估报告

数据集检测会额外输出：
- TP / FP / TN / FN
- Accuracy / Precision / Recall / F1 / MCC
- CWE 命中率

---

## 7. 保留能力说明

当前 CLI 版仍保留这些 C/C++ 能力：
- `EnhancedMetaAgent` 单文件检测主链路
- `ProjectScanner` 工程扫描
- `parse_c_workspace()` 工作区级 Joern 解析
- `extract_c_reachable_flows()` 跨文件 reachable flows 提取
- `enhanced_slice_constructor.py` 对 `reachable_flows_by_cwe` 的消费

---

## 8. 免责声明

本项目仅用于合法授权范围内的安全研究、教学和工程质量提升。请勿用于未授权目标。
