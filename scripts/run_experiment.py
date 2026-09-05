from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))

    from soc_validation_experiment.pipeline import run_pipeline

    parser = argparse.ArgumentParser(description="Run the SOC alert validation experiment pipeline.")
    parser.add_argument("--config", default="config/experiment.toml", help="Path to the experiment TOML config.")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic CICIDS-like data for pipeline QA.")
    parser.add_argument("--enricher", choices=["mock", "openai"], help="Override enrichment provider.")
    parser.add_argument("--max-alerts", type=int, help="Maximum baseline alerts to enrich and validate.")
    args = parser.parse_args()

    context = run_pipeline(
        root=root,
        config_path=root / args.config,
        synthetic=args.synthetic,
        enricher=args.enricher,
        max_alerts=args.max_alerts,
    )
    print(f"Run complete: {context.run_dir}")
    print(f"Metrics: {context.run_dir / 'metrics.json'}")
    print(f"Chapter 4 summary: {context.run_dir / 'chapter4_run_summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
