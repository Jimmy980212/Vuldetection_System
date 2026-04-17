"""
vulnscan - 面向大规模代码库的漏洞检测扫描架构（不改变核心检测逻辑）。

核心检测仍由顶层 `agent.MetaAgent` 完成：
  StaticAnalyzer -> SliceConstructor -> LLMReasoning -> HypothesisValidator -> ReportAgent
"""

