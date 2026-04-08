from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScanRequest:
    target_path: str
    max_alerts: int = 30
    analysis_workers: int = 4
    enable_joern: bool = True
    save_cpg: bool = True
    enable_all: bool = True
    cpg_output_dir: Optional[str] = None
    schema_failure_policy: str = "fail_close"


@dataclass
class CandidateStageResult:
    project_info: Dict[str, Any] = field(default_factory=dict)
    raw_alerts: List[Dict[str, Any]] = field(default_factory=list)
    deduped_alerts: List[Dict[str, Any]] = field(default_factory=list)
    dedup_stats: Dict[str, int] = field(default_factory=dict)
    ranked_alerts: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeepAnalysisResult:
    reports: List[Dict[str, Any]] = field(default_factory=list)
    processed_alerts: int = 0
    skipped_alerts: int = 0
    unresolved_path_skips: int = 0
    degraded_alerts: int = 0
    schema_warnings: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
