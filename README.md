# C/C++ Standalone CLI

独立运行的 C/C++ 漏洞检测项目，仅保留命令行检测能力。

## 保留能力

- 单文件检测
- 多文件/目录检测
- 跨文件工程扫描（`--c-workspace-cpg`）
- 数据集加载检测（`primevul` / `secvul`）

## 已移除

- 前端页面与 UI 相关代码
- Java/Python 数据集与检测入口

## 快速使用

在 `ccpp_standalone/` 目录下：

```bash
pip install -r requirements.txt
python main.py --mode detect --file dataset/multi_c_project/main.c
python main.py --mode detect --source primevul --samples 10 --parallel 6
python main.py --mode scan --root dataset/multi_c_project --c-workspace-cpg --parallel 4
```

## 输出目录

- `result/`：检测报告
- `temp/`：临时文件

