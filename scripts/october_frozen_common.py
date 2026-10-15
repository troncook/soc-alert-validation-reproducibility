"""Shared local input/provenance checks for the focused October reproduction.

Reconstructs the record shape used by the retained timing script. No training,
threshold selection, network access, credentials, or private manuscript inputs.
"""
from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import numpy as np
import pandas as pd
from soc_validation_experiment import corrective_evaluation as ce
from soc_validation_experiment import pipeline as legacy
import corrected_validator_for_timing_20261013 as corrected

POLICY = "combined_web_brute_and_scan"
CONDITION = "duplicate_group_split"
SEED = 42


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def normalized(mapping):
    return {key.replace("\\", "/"): value for key, value in mapping.items()}


def web_brute(label):
    label = str(label).casefold()
    return label.startswith("web attack") and "brute" in label


def verify_hashes(files, hashes):
    for label, path in files.items():
        require(ce.sha(path) == hashes[label], f"Protected input changed: {label}")


def input_files(frozen_run):
    files = {"frozen/manifest.json": frozen_run / "manifest.json"}
    for name in ["test_predictions.csv", "test_validation.jsonl", "results.json", "selection_lock.json"]:
        files[f"frozen/{CONDITION}/{name}"] = frozen_run / CONDITION / name
    for path in [Path(__file__), Path(corrected.__file__), Path(legacy.__file__), Path(ce.__file__)]:
        files["code/" + path.relative_to(ROOT).as_posix()] = path
    return files


def load_frozen(frozen_run, data_root):
    """Validate receipts, reconstruct all test fields, and verify stored decisions.

    Input construction follows time_corrected_policy_20261013.py:run exactly:
    raw test fields first, then five prediction metadata fields; `unsupported`
    is added only to the repeat frame. Non-alert rows remain for recall metrics.
    """
    frozen_run, data_root = Path(frozen_run).resolve(), Path(data_root).resolve()
    frozen = read(frozen_run / "manifest.json")
    require(frozen.get("status") == "complete", "Frozen September run is not complete")
    require(frozen.get("source_unchanged_during_run") is True, "Frozen September source-preservation check did not pass")
    require(CONDITION in frozen["conditions"], f"Frozen run lacks {CONDITION}")
    synthetic = frozen.get("classification") == "synthetic_QA"
    require(synthetic or frozen.get("classification") == "corrective_re_evaluation", "Unsupported frozen-run classification")
    require(frozen["config"]["run"]["enricher"] == "mock", "Only local mock enrichment is supported")
    source_hashes = normalized(frozen["source_hashes"])
    for relative in ["src/soc_validation_experiment/pipeline.py", "src/soc_validation_experiment/corrective_evaluation.py"]:
        require(source_hashes.get(relative) == ce.sha(ROOT / relative), f"Historical source mismatch: {relative}")
    outputs = normalized(frozen["output_hashes"])
    files = input_files(frozen_run)
    for label, path in files.items():
        if label.startswith("frozen/") and label != "frozen/manifest.json":
            relative = label.removeprefix("frozen/")
            require(outputs.get(relative) == ce.sha(path), f"Frozen output receipt mismatch: {relative}")
    config = frozen["config"]
    if not synthetic:
        for relative in config["data"]["csv_paths"]:
            path = data_root / relative
            files["dataset/" + path.name] = path
    hashes = {label: ce.sha(path) for label, path in files.items()}
    raw, receipts = ce.load_sample(data_root, config, synthetic=synthetic)
    require(receipts == frozen["dataset_inputs"], "Dataset receipt drift")
    x = ce.features(raw)
    require(len(raw) == frozen["sample_rows"] and list(x) == frozen["feature_columns"], "Reconstructed sample dimensions/columns differ")
    if not synthetic:
        require(len(raw) == 400000 and x.shape[1] == 78, "The selected real-data protocol requires 400,000 rows and 78 features")
    groups = ce.fingerprints(x)
    group = frozen_run / CONDITION
    prediction = pd.read_csv(group / "test_predictions.csv")
    require(prediction.row_index.is_unique, "Duplicate test row identity")
    ids = prediction.row_index.to_numpy()
    require(np.issubdtype(ids.dtype, np.integer) and np.all((ids >= 0) & (ids < len(raw))), "Invalid test row identity")
    require(np.array_equal(groups[ids], prediction.feature_group.to_numpy()), "Feature fingerprint mismatch")
    for key in ["Label", "__source_file", "__source_row", "__day"]:
        require(np.array_equal(raw.iloc[ids][key].astype(str).to_numpy(), prediction[key].astype(str).to_numpy()), f"Source identity mismatch: {key}")
    require(np.array_equal(legacy.binary_labels(raw.iloc[ids]).to_numpy(), prediction.y_true.to_numpy()), "Outcome label mismatch")
    selection = read(group / "selection_lock.json")
    prior = read(group / "results.json")
    require(selection["selection_partition"] == "development_only" and selection["reference_cutoff"] == ce.REFERENCE, "Frozen selection scope/threshold mismatch")
    require(prior["selection_lock_sha256"] == ce.sha(group / "selection_lock.json"), "Selection lock mismatch")
    frame = raw.iloc[ids].copy().reset_index(drop=True)
    for key in ["row_index", "feature_group", "baseline_probability", "baseline_predicted_label", "y_true"]:
        frame[key] = prediction[key].to_numpy()
    require(np.isfinite(frame.baseline_probability.to_numpy()).all(), "Nonfinite frozen score")
    eligible = frame.loc[frame.baseline_probability >= ce.REFERENCE]
    require(len(eligible) > 0, "No baseline alerts to replay or time")
    stored_rows = [json.loads(line) for line in (group / "test_validation.jsonl").read_text(encoding="utf-8").splitlines()]
    original = {int(row["row_index"]): row for row in stored_rows}
    require(len(original) == len(stored_rows) and set(original) == set(eligible.row_index), "Stored validation identities differ")
    removal_flags = prediction.set_index("row_index")["unsupported"].to_dict()
    expected = {}
    for record in eligible.to_dict("records"):
        identity = int(record["row_index"])
        saved = original[identity]
        enrichment = legacy.mock_enrich(record)
        result = legacy.validate_hypothesis(record, enrichment, check_smt=False)
        for key in ["rule_id", "disposition"]:
            require(result[key] == saved[key], f"Original {key} mismatch at {identity}")
        require(enrichment["candidate_technique_id"] == saved["candidate_technique_id"], f"Candidate mismatch at {identity}")
        require(int(record["y_true"]) == int(saved["y_true"]), f"Stored outcome mismatch at {identity}")
        require(abs(record["baseline_probability"] - saved["baseline_probability"]) <= 1e-12, f"Stored score mismatch at {identity}")
        smt = {"supported": "sat", "unsupported": "unsat", "inconclusive": "not_applicable"}[result["disposition"]]
        require(saved["smt_result"] == smt, f"Stored SMT mismatch at {identity}")
        require(bool(removal_flags[identity]) == (result["disposition"] == "unsupported"), f"Stored removal flag mismatch at {identity}")
        expected[identity] = {"identity": identity, "y_true": int(record["y_true"]), "candidate_technique_id": enrichment["candidate_technique_id"], "original_rule_id": result["rule_id"], "existing_rules": result["disposition"]}
    repeat_frame = frame.copy()
    repeat_frame["unsupported"] = prediction["unsupported"].to_numpy()
    verify_hashes(files, hashes)
    return {"frame": frame, "repeat_frame": repeat_frame, "original": original, "expected": expected,
            "selection": selection, "prior": prior, "frozen": frozen, "receipts": receipts,
            "files": files, "hashes": hashes, "synthetic": synthetic}


def environment():
    def git(*args):
        try:
            value = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
            return value.stdout.strip() if value.returncode == 0 else None
        except OSError:
            return None
    return {"python": sys.version, "platform": platform.platform(), "cpu": platform.processor() or None,
            "logical_cores": os.cpu_count(), "clock": vars(time.get_clock_info("perf_counter")),
            "packages": {p: importlib.metadata.version(p) for p in ["numpy", "pandas", "scipy", "scikit-learn", "z3-solver"]},
            "git_head": git("rev-parse", "HEAD"), "git_status": git("status", "--porcelain")}


def write_manifest(output, state, entrypoint, started, extra=None):
    files = dict(state["files"])
    files["code/" + Path(entrypoint).relative_to(ROOT).as_posix()] = Path(entrypoint)
    hashes = dict(state["hashes"])
    require("code/" + Path(entrypoint).relative_to(ROOT).as_posix() in hashes, "Entrypoint was not recorded before execution")
    verify_hashes(files, hashes)
    manifest = {"status": "complete", "classification": "synthetic_QA" if state["synthetic"] else "local_frozen_prediction_reproduction",
                "condition": CONDITION, "started_at_utc": started, "finished_at_utc": ce.utc(),
                "entrypoint": Path(entrypoint).name, "command": sys.argv,
                "input_hashes": hashes, "dataset_receipts": state["receipts"], "config": state["frozen"]["config"],
                "protected_inputs_unchanged": True, "environment": environment(), "network_calls": 0,
                "hosted_calls": 0, "credentials_read": False, "detector_fits": 0, "threshold_selection": False,
                "replaces_historical_results": False, "seed": SEED,
                "output_hashes": {p.name: ce.sha(p) for p in output.iterdir() if p.is_file() and p.name != "manifest.json"}}
    if extra:
        manifest.update(extra)
    ce.write_json(output / "manifest.json", manifest)
