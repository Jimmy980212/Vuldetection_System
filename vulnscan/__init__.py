"""
vulnscan - 面向大规模代码库的漏洞检测扫描架构（不改变核心检测逻辑）。

核心检测统一由 `enhanced_meta_agent.EnhancedMetaAgent` 完成：
  StaticAnalyzer -> EnhancedSliceConstructor -> SpecializedLLMAgent -> HypothesisValidator -> ReportAgent
"""

