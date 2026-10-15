"""Focused portable October replay on regenerated frozen September predictions.

Preserves the four selected correction policies from the October 2 replay.
The broader Web and missing-fact sensitivities and June analysis are not run.
See OCTOBER_CODE_PROVENANCE.json for the exact source/adaptation inventory.
"""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import json
import numpy as np
import pandas as pd

from october_frozen_common import (ROOT, POLICY, ce, corrected, legacy, load_frozen,
                                   read, require, web_brute, write_manifest)

POLICIES = ["existing_rules", "web_brute_out_of_coverage", "scan_dead_branch_retired", POLICY]


def evaluate(record, enrichment, original):
    # Exact decision expressions from replay_advisor_validation_20261002.py.
    current = original["disposition"]
    narrow = "inconclusive" if web_brute(record["baseline_predicted_label"]) else current
    scan = ("supported" if legacy.get_float(record, "baseline_probability") >= .80
            and legacy.get_float(record, "Flow Packets/s") > 1000 else "unsupported") if original["rule_id"] == "RULE_SCAN_SYN_ACTIVITY" else current
    combined = "inconclusive" if web_brute(record["baseline_predicted_label"]) else scan
    result = dict(zip(POLICIES, [current, narrow, scan, combined]))
    require(corrected.validate_hypothesis(record, enrichment, check_smt=False)["disposition"] == combined, "Corrected adapter differs from frozen replay expression")
    return result


def replay_frame(frame, expected, selection, draws=1000):
    rows = []
    for record in frame.loc[frame.baseline_probability >= ce.REFERENCE].to_dict("records"):
        saved = expected[int(record["row_index"])]
        enrichment = legacy.mock_enrich(record)
        old = {"disposition": saved["existing_rules"], "rule_id": saved["original_rule_id"]}
        rows.append({**saved, **evaluate(record, enrichment, old)})
    base = frame.baseline_probability.to_numpy() >= ce.REFERENCE
    index = {int(identity): i for i, identity in enumerate(frame.row_index)}
    reports, cache = {}, {}
    for policy in POLICIES:
        removed = np.zeros(len(frame), dtype=bool)
        for row in rows:
            removed[index[row["identity"]]] = row[policy] == "unsupported"
        report = ce.metrics(frame, base, base & ~removed)
        report["dispositions"] = dict(Counter(r[policy] for r in rows))
        report["changed_dispositions"] = sum(r[policy] != r["existing_rules"] for r in rows)
        key = removed.tobytes()
        if key not in cache:
            cache[key] = ce.group_bootstrap(frame, base, removed, draws=draws)
        report["feature_group_bootstrap"] = cache[key]
        lower, upper = cache[key]["recall_delta_ci95"]
        report["recall_loss_percentage_points_ci95"] = [-100 * upper, -100 * lower] if lower is not None else [None, None]
        report["h2_interval_within_five_percentage_points"] = lower >= -.05 if lower is not None else None
        reports[policy] = report
    cutoff = selection["score_only_cutoff"]
    if cutoff is not None:
        retained = frame.baseline_probability.to_numpy() >= cutoff
        reports["development_score_filter"] = {**ce.metrics(frame, base, retained), "locked_cutoff": cutoff}
    return rows, reports


def run(frozen_run, data_root, output):
    started = ce.utc()
    entry_hash = ce.sha(__file__)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    state = load_frozen(frozen_run, data_root)
    entry_label = "code/" + Path(__file__).relative_to(ROOT).as_posix()
    state["files"][entry_label] = Path(__file__)
    state["hashes"][entry_label] = entry_hash
    rows, reports = replay_frame(state["frame"], state["expected"], state["selection"])
    prior = state["prior"]["policies"]["symbolic"]
    for key in ["test_rows", "baseline_fp", "baseline_tp", "fp_removed", "tp_removed", "retained_fp", "retained_tp", "malicious"]:
        require(reports["existing_rules"][key] == prior[key], f"Original metric mismatch: {key}")
    if not state["synthetic"]:
        require(reports["existing_rules"]["feature_group_bootstrap"] == prior["feature_group_bootstrap"], "Original group bootstrap did not reproduce")
    pd.DataFrame(rows).to_csv(output / "alert_dispositions.csv", index=False)
    saved = pd.read_csv(output / "alert_dispositions.csv").to_dict("records")
    for policy in POLICIES:
        removed = Counter(int(r["y_true"]) for r in saved if r[policy] == "unsupported")
        require((removed[0], removed[1]) == (reports[policy]["fp_removed"], reports[policy]["tp_removed"]), f"Saved-row recount failed: {policy}")
    result = {"condition": "duplicate_group_split", "selected_policy": POLICY, "policies": reports,
              "classification": "synthetic_QA" if state["synthetic"] else "retrospective_validation_only_policy_replay",
              "reproduction_mismatches": 0, "independent_saved_csv_recount_passed": True,
              "scope": "Four correction policies and the frozen development-selected score filter; excludes June and auxiliary sensitivity analyses.",
              "latency": "No H3 timing is measured by this analytical replay."}
    ce.write_json(output / "results.json", result)
    pd.DataFrame([{"policy": p, **{k: m[k] for k in ["test_rows", "baseline_fp", "baseline_tp", "fp_removed", "tp_removed", "fp_reduction", "baseline_recall", "validated_recall", "recall_delta"]}} for p, m in reports.items()]).to_csv(output / "policy_comparison.csv", index=False)
    write_manifest(output, state, __file__, started, {"bootstrap_draws": 1000})
    print(json.dumps({"output": str(output), "classification": result["classification"], "corrected": reports[POLICY]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-run", type=Path, required=True, help="Completed September run directory containing manifest.json and duplicate_group_split/")
    parser.add_argument("--data-root", type=Path, default=ROOT, help="Base directory for frozen config.data.csv_paths; no downloads")
    parser.add_argument("--output", type=Path, required=True, help="New output directory; existing paths are refused")
    args = parser.parse_args()
    run(args.frozen_run, args.data_root, args.output)


if __name__ == "__main__":
    main()
