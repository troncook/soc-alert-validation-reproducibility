"""Small synthetic contracts for the public October paths; no research data."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import october_frozen_common as common
import replay_october_policy as replay
import time_corrected_policy_20261013 as timing
from october_frozen_common import ce, corrected, legacy


def fixture(root):
    """Write seven synthetic rows in the actual September frozen-file contract."""
    labels = ["Web Attack - Brute Force", "PortScan", "PortScan", "FTP-Patator", "DoS Hulk", "unclassified", "BENIGN"]
    scores = [1., .2, .8, .9, .9, .5, .1]
    raw = pd.DataFrame({"Destination Port": [80, 0, 0, 21, 80, 0, 0],
                        "Flow Packets/s": [0., 0., 1001., 0., 0., 0., 0.],
                        "Flow Bytes/s": [0.] * 7, "SYN Flag Count": [0, 3, 1, 0, 0, 0, 0],
                        "Total Fwd Packets": [4] * 7, "Total Backward Packets": [4] * 7,
                        "Total Length of Bwd Packets": [0.] * 7, "Extra numeric feature": list(range(7)),
                        "Label": ["attack", "BENIGN", "attack", "attack", "BENIGN", "BENIGN", "attack"],
                        "__source_file": ["synthetic.csv"] * 7, "__source_row": list(range(7)), "__day": ["Monday"] * 7})
    x = ce.features(raw)
    frame = raw.copy()
    frame["row_index"] = np.arange(len(raw))
    frame["feature_group"] = ce.fingerprints(x)
    frame["baseline_probability"] = scores
    frame["baseline_predicted_label"] = labels
    frame["y_true"] = legacy.binary_labels(raw)
    stored, removed = [], np.zeros(len(frame), dtype=bool)
    for row in frame.loc[frame.baseline_probability >= .15].to_dict("records"):
        enrichment = legacy.mock_enrich(row)
        result = legacy.validate_hypothesis(row, enrichment)
        removed[row["row_index"]] = result["disposition"] == "unsupported"
        stored.append({"row_index": row["row_index"], "y_true": int(row["y_true"]), "baseline_probability": row["baseline_probability"],
                       "candidate_technique_id": enrichment["candidate_technique_id"], **result})
    frame["unsupported"] = removed
    group = root / common.CONDITION
    group.mkdir(parents=True)
    columns = ["row_index", "feature_group", "Label", *ce.META, "baseline_probability", "baseline_predicted_label", "y_true", "unsupported"]
    frame[columns].to_csv(group / "test_predictions.csv", index=False)
    (group / "test_validation.jsonl").write_text("\n".join(json.dumps(row) for row in stored) + "\n", encoding="utf-8")
    selection = {"selection_partition": "development_only", "reference_cutoff": .15, "score_only_cutoff": .21}
    ce.write_json(group / "selection_lock.json", selection)
    base = frame.baseline_probability.to_numpy() >= .15
    ce.write_json(group / "results.json", {"policies": {"symbolic": ce.metrics(frame, base, base & ~removed)},
                                            "selection_lock_sha256": ce.sha(group / "selection_lock.json")})
    manifest = {"status": "complete", "source_unchanged_during_run": True, "classification": "synthetic_QA", "conditions": [common.CONDITION],
                "source_hashes": {p: ce.sha(ROOT / p) for p in ["src/soc_validation_experiment/pipeline.py", "src/soc_validation_experiment/corrective_evaluation.py"]},
                "output_hashes": {p.relative_to(root).as_posix(): ce.sha(p) for p in group.iterdir()},
                "dataset_inputs": [], "config": {"run": {"enricher": "mock"}, "data": {"csv_paths": []}},
                "sample_rows": len(raw), "feature_columns": list(x)}
    ce.write_json(root / "manifest.json", manifest)
    return raw


class OctoberReproductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.frozen = self.root / "frozen"
        self.raw = fixture(self.frozen)

    def tearDown(self):
        self.temp.cleanup()

    def load(self):
        with patch.object(ce, "load_sample", return_value=(self.raw.copy(), [])):
            return common.load_frozen(self.frozen, self.root)

    def test_original_october_boundary_suite(self):
        self.assertEqual(timing.self_test()["count"], 9)

    def test_web_guard_preserves_mapping_and_skips_solver_for_label_variants(self):
        for label in ["Web Attack - Brute Force", "WEB ATTACK – BRUTE FORCE", "web attack brute force"]:
            row = {"baseline_predicted_label": label, "baseline_probability": 1., "Destination Port": 21}
            enrichment = legacy.mock_enrich(row)
            with patch.object(corrected, "smt_rule_check", side_effect=AssertionError("Solver executed")):
                result = corrected.validate_hypothesis(row, enrichment)
            self.assertEqual(enrichment["candidate_technique_id"], "T1110")
            self.assertEqual(result["disposition"], "inconclusive")
            self.assertEqual(result["smt_result"], "not_applicable")
            self.assertFalse(result["rule_coverage"])

    def test_preserves_all_raw_columns_order_and_repeat_metadata(self):
        state = self.load()
        expected = list(self.raw) + ["row_index", "feature_group", "baseline_probability", "baseline_predicted_label", "y_true"]
        self.assertEqual(list(state["frame"]), expected)
        self.assertEqual(list(state["repeat_frame"]), expected + ["unsupported"])
        records, sample = timing.select_workload(state)
        self.assertEqual(list(records[0]), expected)
        self.assertEqual(list(sample[0]), expected + ["unsupported"])
        expected_ids = state["repeat_frame"].loc[state["repeat_frame"].baseline_probability >= .15].sample(n=6, random_state=42).row_index.tolist()
        self.assertEqual([r["row_index"] for r in sample], expected_ids)

    def test_tampered_frozen_file_rejected_before_dataset_load(self):
        path = self.frozen / common.CONDITION / "test_predictions.csv"
        path.write_bytes(path.read_bytes() + b"\n")
        with patch.object(ce, "load_sample", side_effect=AssertionError("Should reject receipt first")):
            with self.assertRaisesRegex(ValueError, "Frozen output receipt mismatch"):
                common.load_frozen(self.frozen, self.root)

    def test_historical_source_drift_rejected(self):
        path = self.frozen / "manifest.json"
        manifest = common.read(path)
        manifest["source_hashes"]["src/soc_validation_experiment/pipeline.py"] = "0" * 64
        ce.write_json(path, manifest)
        with self.assertRaisesRegex(ValueError, "Historical source mismatch"):
            self.load()

    def test_failed_upstream_preservation_is_not_a_complete_run(self):
        path = self.frozen / "manifest.json"
        manifest = common.read(path)
        manifest["source_unchanged_during_run"] = False
        ce.write_json(path, manifest)
        with self.assertRaisesRegex(ValueError, "source-preservation check did not pass"):
            self.load()

    def test_driver_hash_is_verified_against_preexecution_snapshot(self):
        state = self.load()
        entrypoint = Path(replay.__file__)
        label = "code/" + entrypoint.relative_to(common.ROOT).as_posix()
        state["files"][label] = entrypoint
        state["hashes"][label] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Protected input changed: code/scripts/replay_october_policy.py"):
            common.write_manifest(self.root, state, entrypoint, ce.utc())

    def test_dataset_receipt_and_feature_drift_rejected(self):
        with patch.object(ce, "load_sample", return_value=(self.raw, [{"sha256": "changed"}])):
            with self.assertRaisesRegex(ValueError, "Dataset receipt drift"):
                common.load_frozen(self.frozen, self.root)
        self.raw.loc[0, "Flow Packets/s"] = 5.
        with self.assertRaisesRegex(ValueError, "Feature fingerprint mismatch"):
            self.load()

    def test_full_cli_contract_and_timing_order(self):
        replay_out, timing_out = self.root / "replay", self.root / "timing"
        with patch.object(ce, "load_sample", side_effect=lambda *a, **kw: (self.raw.copy(), [])), contextlib.redirect_stdout(io.StringIO()):
            with patch.object(sys, "argv", ["replay_october_policy.py", "--frozen-run", str(self.frozen), "--output", str(replay_out)]):
                replay.main()
            with patch.object(sys, "argv", ["time_corrected_policy_20261013.py", "--frozen-run", str(self.frozen), "--replay", str(replay_out), "--output", str(timing_out)]):
                timing.main()
        report = common.read(timing_out / "results.json")
        self.assertEqual(report["classification"], "synthetic_QA")
        self.assertEqual(report["full_corrected"]["alerts"], 6)
        self.assertEqual(report["full_warmup_alerts"], 6)
        self.assertEqual(report["repeat_warmup_alerts_per_policy"], 6)
        self.assertEqual(len(report["repeat_summaries"]), 10)
        self.assertEqual([r["policy"] for r in report["repeat_order"]], ["original", "corrected", "corrected", "original", "original", "corrected", "corrected", "original", "original", "corrected"])
        full = pd.read_csv(timing_out / "full_corrected_timings.csv")
        repeats = pd.read_csv(timing_out / "sample_repeat_timings.csv")
        self.assertTrue((full.total_ns == full.enrichment_ns + full.validation_ns).all())
        self.assertTrue((repeats.total_ns == repeats.enrichment_ns + repeats.validation_ns).all())
        self.assertEqual(len(full), 6)  # Untimed warmups are absent.
        self.assertEqual(len(repeats), 60)
        workload = common.read(timing_out / "workload.json")
        for _, group in repeats.groupby(["repeat", "policy"], sort=False):
            self.assertEqual(group.row_index.tolist(), workload["repeat_sample_ids"])
        manifest = common.read(timing_out / "manifest.json")
        for name, digest in manifest["output_hashes"].items():
            self.assertEqual(ce.sha(timing_out / name), digest)
        self.assertEqual(manifest["network_calls"], 0)
        # A second invocation cannot overwrite the first result.
        with self.assertRaises(FileExistsError):
            replay.run(self.frozen, self.root, replay_out)
        # A changed saved replay is rejected, even when its CSV remains readable.
        path = replay_out / "alert_dispositions.csv"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "Replay output receipt mismatch"):
            timing.load_replay(replay_out, self.load())

    def test_timer_components_exclude_record_assembly(self):
        state = self.load()
        records, _ = timing.select_workload(state)
        row = records[0]
        identity = row["row_index"]
        enrichment = legacy.mock_enrich(row)
        result = corrected.validate_hypothesis(row, enrichment)
        expected = {identity: {**state["expected"][identity], common.POLICY: result["disposition"]}}
        with patch.object(timing.time, "perf_counter_ns", side_effect=[10, 13, 21]):
            rows, _ = timing.timed_pass([row], lambda r, e: result, "corrected", "full", 0, expected, state["original"])
        self.assertEqual((rows[0]["enrichment_ns"], rows[0]["validation_ns"], rows[0]["total_ns"]), (3, 8, 11))


if __name__ == "__main__":
    unittest.main()
