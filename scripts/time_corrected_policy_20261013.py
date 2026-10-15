"""Portable corrected local timing; no fitting, hosted calls, or downloads.

self_test, summarize and timed_pass are copied without behavioral changes from
October 13's retained timing entry point. The driver replaces private paths and
receipts with the supplied frozen run and public replay. Timing is machine-local.
"""
from __future__ import annotations

import argparse
from collections import Counter
import inspect
import json
from pathlib import Path
import time
import numpy as np
import pandas as pd
from october_frozen_common import (ROOT, POLICY, SEED, ce, legacy, corrected, read,
                                   require, load_frozen, write_manifest, environment)

def self_test():
    tests = []
    base = {'Destination Port': 80, 'Flow Packets/s': 0., 'Flow Bytes/s': 0.,
            'SYN Flag Count': 0, 'Total Fwd Packets': 4, 'Total Backward Packets': 4,
            'Total Length of Bwd Packets': 0, 'baseline_probability': 1.,
            'baseline_predicted_label': 'Web Attack - Brute Force'}
    original_smt = corrected.smt_rule_check
    def forbid_solver(*args):
        raise AssertionError('Out-of-coverage guard executed solver work')
    corrected.smt_rule_check = forbid_solver
    try:
        result = corrected.validate_hypothesis(base, legacy.mock_enrich(base))
    finally:
        corrected.smt_rule_check = original_smt
    assert result['disposition'] == 'inconclusive' and not result['rule_coverage']
    assert result['smt_result'] == 'not_applicable'
    tests.append('Predicted web brute force exits as inconclusive without SMT')
    for score, rate, syn, expected in [(.8, 1000, 1, 'unsupported'),
                                     (.8, 1001, 1, 'supported'),
                                     (.79, 1001, 1, 'unsupported'),
                                     (.2, 0, 3, 'unsupported')]:
        rec = dict(base, baseline_probability=score, baseline_predicted_label='PortScan')
        rec.update({'Flow Packets/s': rate, 'SYN Flag Count': syn})
        enrichment = legacy.mock_enrich(rec)
        result = corrected.validate_hypothesis(rec, enrichment)
        assert result['disposition'] == expected
        assert result['smt_result'] == ('sat' if expected == 'supported' else 'unsat')
        if syn == 3:
            assert legacy.validate_hypothesis(rec, enrichment)['disposition'] == 'supported'
        tests.append(f'Scan Python and SMT boundary score={score}, rate={rate}, SYN={syn}')
    for label, port, score, rate in [('FTP-Patator', 21, .9, 0.),
                                    ('DoS Hulk', 80, .9, float('nan')),
                                    ('Web Attack - XSS', 80, .9, 0.),
                                    ('unclassified', 0, .2, 0.)]:
        rec = dict(base, baseline_predicted_label=label, baseline_probability=score)
        rec.update({'Destination Port': port, 'Flow Packets/s': rate})
        enrichment = legacy.mock_enrich(rec)
        assert corrected.validate_hypothesis(rec, enrichment) == legacy.validate_hypothesis(rec, enrichment)
        tests.append(f'Unchanged rule and SMT behavior for {label}')
    src = inspect.getsource(corrected.smt_rule_check)
    assert src.count('solver.add(') == inspect.getsource(legacy.smt_rule_check).count('solver.add(')
    for name in ['packets_per_second', 'total_packets', 'syn_count', 'dst_port',
                 'bytes_per_second', 'total_bwd_bytes', 'baseline_probability']:
        assert f'solver.add({name} ==' in src
    return {'status': 'passed', 'tests': tests, 'count': len(tests),
            'all_seven_solver_fact_bindings_preserved': True}


def summarize(rows):
    a = np.asarray([r['total_ns'] for r in rows], dtype=np.float64) / 1e9
    return {'alerts': len(rows), 'mean_seconds': float(a.mean()),
            'median_seconds': float(np.median(a)),
            'p95_seconds': float(np.quantile(a, .95, method='linear')),
            'maximum_seconds': float(a.max()),
            'mean_enrichment_seconds': float(np.mean([r['enrichment_ns'] for r in rows]) / 1e9),
            'mean_validation_seconds': float(np.mean([r['validation_ns'] for r in rows]) / 1e9),
            'at_or_above_one_second': int(np.count_nonzero(a >= 1.)),
            'dispositions': dict(Counter(r['disposition'] for r in rows)),
            'smt_results': dict(Counter(r['smt_result'] for r in rows))}


def timed_pass(records, validator, policy, phase, repeat, expected, original):
    rows = []
    started_utc = ce.utc()
    for n, record in enumerate(records, 1):
        a = time.perf_counter_ns()
        enrichment = legacy.mock_enrich(record)
        b = time.perf_counter_ns()
        result = validator(record, enrichment)
        c = time.perf_counter_ns()
        # All comparisons and record assembly occur after the measured span.
        identity = int(record['row_index'])
        saved = expected[identity]
        wanted = saved[POLICY] if policy == 'corrected' else saved['existing_rules']
        assert result['disposition'] == wanted, (identity, result, wanted)
        assert enrichment['candidate_technique_id'] == saved['candidate_technique_id']
        is_web = str(record['baseline_predicted_label']).casefold().startswith('web attack') and 'brute' in str(record['baseline_predicted_label']).casefold()
        expected_rule = 'RULE_OUT_OF_COVERAGE' if policy == 'corrected' and is_web else saved['original_rule_id']
        assert result['rule_id'] == expected_rule
        expected_smt = ('sat' if result['disposition'] == 'supported' else 'unsat') if result['rule_coverage'] else 'not_applicable'
        assert result['smt_result'] == expected_smt
        if policy == 'original':
            assert result['smt_result'] == original[identity]['smt_result']
        rows.append({'phase': phase, 'policy': policy, 'repeat': repeat,
                     'position': n, 'row_index': identity, 'y_true': int(record['y_true']),
                     'candidate_technique_id': enrichment['candidate_technique_id'],
                     'rule_id': result['rule_id'], 'disposition': result['disposition'],
                     'smt_result': result['smt_result'], 'web_coverage_guard': policy == 'corrected' and is_web,
                     'enrichment_ns': b - a, 'validation_ns': c - b, 'total_ns': c - a})
        if phase == 'full' and n % 4000 == 0:
            print(f'Full corrected timing: {n:,}/{len(records):,} alerts', flush=True)
    assert all(r['total_ns'] == r['enrichment_ns'] + r['validation_ns'] for r in rows)
    summary = {'phase': phase, 'policy': policy, 'repeat': repeat,
               'started_at_utc': started_utc, 'ended_at_utc': ce.utc(), **summarize(rows)}
    return rows, summary


def load_replay(replay, state):
    replay = Path(replay).resolve()
    manifest = read(replay / "manifest.json")
    require(manifest.get("status") == "complete", "Replay is not complete")
    for label, digest in state["hashes"].items():
        require(manifest["input_hashes"].get(label) == digest, f"Replay used different input: {label}")
    for name in ["alert_dispositions.csv", "results.json"]:
        require(manifest["output_hashes"].get(name) == ce.sha(replay / name), f"Replay output receipt mismatch: {name}")
        label = "replay/" + name
        state["files"][label] = replay / name
        state["hashes"][label] = ce.sha(replay / name)
    state["files"]["replay/manifest.json"] = replay / "manifest.json"
    state["hashes"]["replay/manifest.json"] = ce.sha(replay / "manifest.json")
    rows = pd.read_csv(replay / "alert_dispositions.csv").to_dict("records")
    expected = {int(r["identity"]): r for r in rows}
    require(len(expected) == len(rows) and set(expected) == set(state["expected"]), "Replay alert identity mismatch")
    for identity, row in expected.items():
        for key, value in state["expected"][identity].items():
            require(row[key] == value, f"Replay original field mismatch: {identity}/{key}")
    return expected, read(replay / "results.json")["policies"][POLICY]


def select_workload(state):
    frame, repeat_frame = state["frame"], state["repeat_frame"]
    records = frame.loc[frame.baseline_probability >= ce.REFERENCE].to_dict("records")
    eligible = repeat_frame.loc[repeat_frame.baseline_probability >= ce.REFERENCE]
    sample = eligible.sample(n=min(1000, len(eligible)), random_state=SEED).to_dict("records")
    return records, sample


def measure_workload(records, sample, expected, original):
    """October 13 warmup/order design; tiny synthetic fixtures use all rows."""
    for record in records[:25]:
        corrected.validate_hypothesis(record, legacy.mock_enrich(record))
    full, full_summary = timed_pass(records, corrected.validate_hypothesis, "corrected", "full", 0, expected, original)
    validators = {"original": legacy.validate_hypothesis, "corrected": corrected.validate_hypothesis}
    for validator in validators.values():
        for record in sample[:25]:
            validator(record, legacy.mock_enrich(record))
    repeat_rows, summaries, order = [], [], []
    for repetition in range(1, 6):
        policies = ["original", "corrected"] if repetition % 2 else ["corrected", "original"]
        for policy in policies:
            rows, summary = timed_pass(sample, validators[policy], policy, "repeat", repetition, expected, original)
            repeat_rows.extend(rows)
            summaries.append(summary)
            order.append({"repeat": repetition, "policy": policy})
    return full, full_summary, repeat_rows, summaries, order


def run(frozen_run, replay, data_root, output):
    started = ce.utc()
    entry_hash = ce.sha(__file__)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    boundaries = self_test()
    state = load_frozen(frozen_run, data_root)
    expected, replay_metrics = load_replay(replay, state)
    entry_label = "code/" + Path(__file__).relative_to(ROOT).as_posix()
    state["files"][entry_label] = Path(__file__)
    state["hashes"][entry_label] = entry_hash
    records, sample = select_workload(state)
    # All expected-decision checks occur outside the measured span.
    for record in records:
        result = corrected.validate_hypothesis(record, legacy.mock_enrich(record), check_smt=False)
        require(result["disposition"] == expected[int(record["row_index"])][POLICY], "Corrected preflight decision mismatch")
    workload = {"full_ids": [r["row_index"] for r in records], "repeat_sample_ids": [r["row_index"] for r in sample],
                "full_record_fields": list(state["frame"].columns), "repeat_record_fields": list(state["repeat_frame"].columns),
                "sample_seed": SEED, "test_rows": len(state["frame"]), "dataset_receipts": state["receipts"]}
    # Release reconstruction frames before timing, retaining the original dictionary shape.
    del state["frame"], state["repeat_frame"]
    full, full_summary, repeated, summaries, order = measure_workload(records, sample, expected, state["original"])
    require(full_summary["dispositions"] == replay_metrics["dispositions"], "Full-pass dispositions differ from replay")
    removed = Counter(r["y_true"] for r in full if r["disposition"] == "unsupported")
    require((removed[0], removed[1]) == (replay_metrics["fp_removed"], replay_metrics["tp_removed"]), "Timing removal counts differ from replay")
    pd.DataFrame(full).to_csv(output / "full_corrected_timings.csv", index=False)
    pd.DataFrame(repeated).to_csv(output / "sample_repeat_timings.csv", index=False)
    ce.write_json(output / "workload.json", workload)
    ce.write_json(output / "environment.json", environment())
    ce.write_json(output / "boundary_checks.json", boundaries)
    result = {"status": "passed", "classification": "synthetic_QA" if state["synthetic"] else "local_timing_diagnostic",
              "policy": POLICY, "full_corrected": full_summary, "repeat_summaries": summaries, "repeat_order": order,
              "full_warmup_alerts": min(25, len(records)), "repeat_warmup_alerts_per_policy": min(25, len(sample)),
              "fp_removed": removed[0], "tp_removed": removed[1], "decision_mismatches": 0, "smt_disagreements": 0,
              "criterion_seconds": 1.0, "corrected_local_mean_target_met": full_summary["mean_seconds"] < 1.0,
              "included": ["fresh mock enrichment", "ordinary fact normalization", "corrected rule dispatch", "applicable SMT construction and solve", "returned in-memory record"],
              "excluded": ["dataset loading", "detector fitting/inference", "input dictionary construction", "serialization and disk I/O", "network and hosted calls"],
              "confidence_interval": None, "replaces_historical_results": False,
              "interpretation": "New warmed serial local measurements on this machine; not independent traffic samples, a causal speedup, throughput, hosted latency, or safe alert suppression."}
    ce.write_json(output / "results.json", result)
    write_manifest(output, state, __file__, started, {"full_warmup_alerts": result["full_warmup_alerts"], "repeat_passes_per_policy": 5})
    print(json.dumps({"output": str(output), "classification": result["classification"], "mean_ms": full_summary["mean_seconds"] * 1000}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Dataset-free corrected-rule and SMT boundary checks")
    parser.add_argument("--frozen-run", type=Path)
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--data-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, help="New output directory; existing paths are refused")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), indent=2))
    elif args.frozen_run and args.replay and args.output:
        run(args.frozen_run, args.replay, args.data_root, args.output)
    else:
        parser.error("Use --self-test, or supply --frozen-run, --replay and --output")


if __name__ == "__main__":
    main()
