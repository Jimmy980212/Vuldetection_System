# Vuldetection System (C/C++ Standalone)

`ccpp_standalone` 是一个面向 C/C++ 场景的命令行漏洞检测项目，支持单文件、目录与工程级扫描，并可结合大模型进行漏洞分析与报告生成。

## 功能特性

- 单文件检测（快速验证某个源文件）
- 多文件/目录扫描（递归处理项目代码）
- 工程级跨文件分析（`--c-workspace-cpg`）
- 数据集模式检测（`primevul` / `secvul`）
- 检测结果落盘到 `result/`，便于复查与自动化集成

## 检测架构

项目已统一为单一检测主链路：`EnhancedMetaAgent`。

- 静态分析：`StaticAnalyzerAgent`
- 切片构造：`EnhancedSliceConstructor`
- 漏洞推理：`SpecializedLLMAgent`（按 CWE 并行）
- 结果验证：`HypothesisValidatorAgent`
- 报告生成：`ReportAgent`

## 运行环境

- Python 3.10+（推荐 3.12）
- Joern 工具链（必需，用于程序分析）
- 可选：LLM API（用于增强分析能力）

安装依赖：

```bash
pip install -r requirements.txt
```

更多环境配置细节请参考：`REQUIREMENTS.md`

## 快速开始

在项目根目录执行以下示例命令：

```bash
# 1) 检测单个 C 文件
python main.py --mode detect --file dataset/multi_c_project/main.c

# 2) 从数据集抽样检测
python main.py --mode detect --source primevul --samples 10 --parallel 6

# 3) 扫描整个 C 工程（启用 workspace 级 CPG）
python main.py --mode scan --root dataset/multi_c_project --c-workspace-cpg --parallel 4
```

## 目录说明

- `main.py`：CLI 入口
- `vulnscan/`：扫描与分析核心逻辑
- `dataset/`：示例数据与测试项目
- `result/`：检测报告输出目录
- `temp/`：分析过程临时文件

## 常见问题

- 若 Joern 路径或脚本未配置，扫描会失败；请先按 `REQUIREMENTS.md` 检查 `config.py`。
- 若需要检测数据集（`primevul/secvul`），请确认网络环境与可选依赖已安装。

