import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.benchmark import evaluate_reports, load_json, save_metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate vulnerability reports against the phase-1 benchmark labels.")
    parser.add_argument(
        "--labels",
        default=str(ROOT / "data" / "benchmarks" / "phase1_labels.json"),
        help="Path to benchmark labels JSON.",
    )
    parser.add_argument(
        "--report",
        default=str(ROOT / "outputs" / "reports" / "latest" / "vulnerability_report.json"),
        help="Path to vulnerability_report.json.",
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "outputs" / "benchmarks" / "phase1_metrics.json"),
        help="Where to write metrics JSON.",
    )
    parser.add_argument("--line-tolerance", type=int, default=2)
    parser.add_argument("--min-confidence", type=float, default=0.0)
    parser.add_argument("--require-cwe", action="store_true")
    args = parser.parse_args()

    report_payload = load_json(args.report)
    label_payload = load_json(args.labels)
    metrics = evaluate_reports(
        report_payload=report_payload,
        label_payload=label_payload,
        line_tolerance=args.line_tolerance,
        require_cwe=args.require_cwe,
        min_confidence=args.min_confidence,
    )
    save_metrics(metrics, args.output)
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
