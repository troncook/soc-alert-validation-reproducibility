from __future__ import annotations

import json
import math
import os
import random
import statistics
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


LABEL_COLUMN = "Label"


@dataclass(frozen=True)
class RunContext:
    root: Path
    config_path: Path
    config: dict[str, Any]
    started_at: str
    run_dir: Path


def read_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def make_run_context(root: Path, config_path: Path, config: dict[str, Any]) -> RunContext:
    started_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_root = root / config["run"].get("output_root", "outputs/runs")
    run_dir = output_root / f"{started_at}_{config['run'].get('name', 'run')}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return RunContext(root=root, config_path=config_path, config=config, started_at=started_at, run_dir=run_dir)


def standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    df = df.replace([np.inf, -np.inf], np.nan)
    return df


def stratified_cap_frame(df: pd.DataFrame, max_rows: int, seed: int) -> pd.DataFrame:
    if max_rows <= 0 or len(df) <= max_rows:
        return df
    if LABEL_COLUMN not in df.columns:
        return df.sample(n=max_rows, random_state=seed)

    label_series = df[LABEL_COLUMN].astype(str).str.strip()
    selected_parts: list[pd.DataFrame] = []
    selected_indices: set[int] = set()
    budget = max_rows

    # Preserve rare attack classes first so full-coverage pilots do not lose them by chance.
    for label, group in df.groupby(label_series, sort=False):
        is_benign = label.upper() == "BENIGN"
        if not is_benign and len(group) <= 5000 and budget > 0:
            take = min(len(group), budget)
            part = group if take == len(group) else group.sample(n=take, random_state=seed)
            selected_parts.append(part)
            selected_indices.update(part.index.tolist())
            budget -= take

    remaining = df.drop(index=list(selected_indices)) if selected_indices else df
    if budget <= 0:
        return pd.concat(selected_parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)
    if remaining.empty:
        return pd.concat(selected_parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)

    remaining_labels = remaining[LABEL_COLUMN].astype(str).str.strip()
    allocations: dict[str, int] = {}
    label_counts = remaining_labels.value_counts()
    for label, count in label_counts.items():
        allocations[label] = max(1, int(round(budget * (count / len(remaining)))))
    while sum(allocations.values()) > budget:
        largest = max(allocations, key=lambda k: allocations[k])
        allocations[largest] -= 1
        if allocations[largest] <= 0:
            del allocations[largest]
    while sum(allocations.values()) < budget:
        largest = max(label_counts.index, key=lambda k: label_counts[k] - allocations.get(k, 0))
        allocations[largest] = allocations.get(largest, 0) + 1

    for label, group in remaining.groupby(remaining_labels, sort=False):
        take = min(len(group), allocations.get(label, 0))
        if take > 0:
            selected_parts.append(group.sample(n=take, random_state=seed))

    capped = pd.concat(selected_parts, ignore_index=True)
    return capped.sample(frac=1, random_state=seed).reset_index(drop=True)


def build_synthetic_cicids(rows: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    labels = rng.choice(
        ["BENIGN", "DoS Hulk", "PortScan", "FTP-Patator", "SSH-Patator", "Web Attack"],
        size=rows,
        p=[0.70, 0.10, 0.08, 0.05, 0.04, 0.03],
    )
    is_attack = labels != "BENIGN"
    dst_port = np.where(
        labels == "FTP-Patator",
        21,
        np.where(labels == "SSH-Patator", 22, np.where(labels == "Web Attack", rng.choice([80, 443], rows), rng.integers(1, 65535, rows))),
    )
    flow_packets = rng.gamma(shape=2.0, scale=50.0, size=rows)
    flow_packets = np.where(labels == "DoS Hulk", flow_packets + rng.gamma(5.0, 900.0, rows), flow_packets)
    flow_packets = np.where(labels == "PortScan", flow_packets + rng.gamma(2.0, 350.0, rows), flow_packets)
    flow_bytes = rng.gamma(shape=2.0, scale=400.0, size=rows)
    flow_bytes = np.where(is_attack, flow_bytes + rng.gamma(3.0, 900.0, rows), flow_bytes)
    syn_flags = np.where(np.isin(labels, ["PortScan", "FTP-Patator", "SSH-Patator"]), rng.integers(1, 8, rows), rng.binomial(1, 0.05, rows))
    duration = rng.gamma(shape=2.0, scale=90000.0, size=rows).astype(int)
    duration = np.where(labels == "DoS Hulk", rng.integers(1000, 60000, rows), duration)

    return pd.DataFrame(
        {
            "Destination Port": dst_port,
            "Flow Duration": duration,
            "Total Fwd Packets": np.maximum(1, (flow_packets * rng.uniform(0.45, 0.75, rows)).astype(int)),
            "Total Backward Packets": np.maximum(0, (flow_packets * rng.uniform(0.10, 0.55, rows)).astype(int)),
            "Total Length of Fwd Packets": np.maximum(0, (flow_bytes * rng.uniform(0.30, 0.80, rows)).astype(int)),
            "Total Length of Bwd Packets": np.maximum(0, (flow_bytes * rng.uniform(0.10, 0.70, rows)).astype(int)),
            "Flow Bytes/s": flow_bytes / np.maximum(duration / 1_000_000, 0.001),
            "Flow Packets/s": flow_packets / np.maximum(duration / 1_000_000, 0.001),
            "SYN Flag Count": syn_flags,
            "ACK Flag Count": rng.binomial(5, 0.50, rows),
            "PSH Flag Count": rng.binomial(3, 0.25, rows),
            "Label": labels,
        }
    )


def load_data(root: Path, config: dict[str, Any], synthetic: bool = False) -> pd.DataFrame:
    seed = int(config["run"].get("seed", 42))
    if synthetic or not config["data"].get("csv_paths"):
        rows = int(config["data"].get("synthetic_rows", 2000))
        return standardize_columns(build_synthetic_cicids(rows, seed))

    frames: list[pd.DataFrame] = []
    max_rows = int(config["run"].get("max_rows", 0) or 0)
    for raw_path in config["data"]["csv_paths"]:
        path = Path(raw_path)
        if not path.is_absolute():
            path = root / path
        frame = pd.read_csv(path, low_memory=False)
        frame = standardize_columns(frame)
        if max_rows and len(frame) > max_rows:
            frame = stratified_cap_frame(frame, max_rows, seed)
        frames.append(frame)
    if not frames:
        raise ValueError("No CSV paths were configured and synthetic data was disabled.")
    return standardize_columns(pd.concat(frames, ignore_index=True))


def binary_labels(df: pd.DataFrame) -> pd.Series:
    if LABEL_COLUMN not in df.columns:
        raise ValueError(f"Missing required label column: {LABEL_COLUMN}")
    return df[LABEL_COLUMN].astype(str).str.strip().str.upper().ne("BENIGN").astype(int)


def numeric_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    skip = {
        LABEL_COLUMN,
        "Flow ID",
        "Source IP",
        "Src IP",
        "Destination IP",
        "Dst IP",
        "Timestamp",
        "SimillarHTTP",
    }
    candidates = [c for c in df.columns if c not in skip]
    features = pd.DataFrame(index=df.index)
    for col in candidates:
        numeric = pd.to_numeric(df[col], errors="coerce")
        if numeric.notna().sum() > 0:
            features[col] = numeric
    if features.empty:
        raise ValueError("No numeric feature columns were available for baseline training.")
    medians = features.median(numeric_only=True).replace([np.inf, -np.inf], np.nan).fillna(0)
    return features.fillna(medians)


def train_baseline(df: pd.DataFrame, config: dict[str, Any]) -> tuple[pd.DataFrame, dict[str, Any]]:
    seed = int(config["run"].get("seed", 42))
    baseline_cfg = config["baseline"]
    y = binary_labels(df)
    x = numeric_feature_frame(df)
    if y.nunique() < 2:
        raise ValueError("Baseline training requires both benign and malicious labels.")

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
    except ModuleNotFoundError:
        return heuristic_baseline(df, x, y, config)

    task = str(baseline_cfg.get("task", "binary")).lower()
    test_size = float(baseline_cfg.get("test_size", 0.30))
    if task == "multiclass":
        y_model = df[LABEL_COLUMN].astype(str).str.strip()
        stratify_target = y_model
    else:
        y_model = y
        stratify_target = y
    train_idx, test_idx = train_test_split(np.arange(len(df)), test_size=test_size, random_state=seed, stratify=stratify_target)
    model = RandomForestClassifier(
        n_estimators=int(baseline_cfg.get("n_estimators", 100)),
        random_state=seed,
        class_weight=baseline_cfg.get("class_weight", "balanced"),
        n_jobs=-1,
    )
    model.fit(x.iloc[train_idx], y_model.iloc[train_idx])
    probability_matrix = model.predict_proba(x.iloc[test_idx])
    threshold = float(baseline_cfg.get("alert_threshold", 0.50))
    if task == "multiclass":
        classes = np.array([str(c) for c in model.classes_])
        benign_mask = np.char.upper(classes.astype(str)) == "BENIGN"
        attack_indices = np.where(~benign_mask)[0]
        if len(attack_indices) == 0:
            raise ValueError("Multiclass baseline requires at least one non-BENIGN class.")
        attack_probabilities = probability_matrix[:, attack_indices].sum(axis=1)
        best_attack_positions = attack_indices[np.argmax(probability_matrix[:, attack_indices], axis=1)]
        predicted_attack_labels = classes[best_attack_positions]
        predictions = (attack_probabilities >= threshold).astype(int)
        probabilities = attack_probabilities
        predicted_labels = np.where(predictions == 1, predicted_attack_labels, "BENIGN")
    else:
        class_list = list(model.classes_)
        positive_index = class_list.index(1) if 1 in class_list else -1
        probabilities = probability_matrix[:, positive_index]
        predictions = (probabilities >= threshold).astype(int)
        predicted_labels = np.where(predictions == 1, "MALICIOUS", "BENIGN")
    test = df.iloc[test_idx].copy().reset_index(drop=True)
    test["y_true"] = y.iloc[test_idx].to_numpy()
    test["baseline_probability"] = probabilities
    test["baseline_predicted_malicious"] = predictions
    test["baseline_predicted_label"] = predicted_labels
    metadata = {
        "baseline_model": "RandomForestClassifier",
        "baseline_task": task,
        "train_rows": int(len(train_idx)),
        "test_rows": int(len(test_idx)),
        "feature_count": int(x.shape[1]),
        "feature_columns": list(x.columns),
        "threshold": threshold,
    }
    return test, metadata


def heuristic_baseline(df: pd.DataFrame, x: pd.DataFrame, y: pd.Series, config: dict[str, Any]) -> tuple[pd.DataFrame, dict[str, Any]]:
    seed = int(config["run"].get("seed", 42))
    rng = np.random.default_rng(seed)
    indices = np.arange(len(df))
    rng.shuffle(indices)
    split = int(len(indices) * (1 - float(config["baseline"].get("test_size", 0.30))))
    test_idx = indices[split:]
    feature_names = list(x.columns)
    z = (x - x.mean()) / x.std(ddof=0).replace(0, 1)
    score_columns = [c for c in feature_names if any(key in c.lower() for key in ["packet", "byte", "flow", "syn", "duration"])]
    if not score_columns:
        score_columns = feature_names[: min(5, len(feature_names))]
    scores = z[score_columns].mean(axis=1).fillna(0)
    threshold = float(scores.quantile(0.75))
    probabilities = 1 / (1 + np.exp(-(scores.iloc[test_idx].to_numpy() - threshold)))
    predictions = (scores.iloc[test_idx].to_numpy() >= threshold).astype(int)
    test = df.iloc[test_idx].copy().reset_index(drop=True)
    test["y_true"] = y.iloc[test_idx].to_numpy()
    test["baseline_probability"] = probabilities
    test["baseline_predicted_malicious"] = predictions
    return test, {
        "baseline_model": "heuristic_fallback",
        "warning": "scikit-learn was not installed; used a deterministic heuristic for pipeline QA only.",
        "train_rows": int(split),
        "test_rows": int(len(test_idx)),
        "feature_count": int(x.shape[1]),
        "feature_columns": feature_names,
        "threshold": threshold,
    }


def get_float(record: dict[str, Any], *names: str) -> float:
    lowered = {str(k).strip().lower(): v for k, v in record.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is None:
            continue
        try:
            if isinstance(value, str) and not value.strip():
                continue
            parsed = float(value)
            if math.isfinite(parsed):
                return parsed
        except (TypeError, ValueError):
            continue
    return 0.0


def select_alert_fields(record: dict[str, Any]) -> dict[str, Any]:
    wanted = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "SYN Flag Count",
        "ACK Flag Count",
        "PSH Flag Count",
        "baseline_probability",
        "baseline_predicted_label",
    ]
    return {key: record.get(key) for key in wanted if key in record}


def mock_enrich(record: dict[str, Any]) -> dict[str, Any]:
    dst_port = int(get_float(record, "Destination Port", "Dst Port"))
    packets_per_second = get_float(record, "Flow Packets/s")
    bytes_per_second = get_float(record, "Flow Bytes/s")
    syn_count = get_float(record, "SYN Flag Count")
    fwd_packets = get_float(record, "Total Fwd Packets")
    bwd_packets = get_float(record, "Total Backward Packets")
    predicted_label = str(record.get("baseline_predicted_label", "")).lower()

    if "ddos" in predicted_label or "dos" in predicted_label:
        technique = "T1498"
        category = "denial_of_service"
        hypothesis = "The flow may represent volumetric or protocol-level denial-of-service behavior."
    elif "portscan" in predicted_label or "scan" in predicted_label:
        technique = "T1046"
        category = "network_service_discovery"
        hypothesis = "The flow may represent scanning or service discovery behavior."
    elif "patator" in predicted_label or "brute" in predicted_label or "ssh" in predicted_label or "ftp" in predicted_label:
        technique = "T1110"
        category = "brute_force"
        hypothesis = "The flow may represent credential brute-force activity against a remote service."
    elif "web" in predicted_label:
        technique = "T1190"
        category = "web_or_public_service_exploitation"
        hypothesis = "The flow may represent exploitation activity against a public-facing web service."
    elif packets_per_second > 1000 or fwd_packets + bwd_packets > 1000:
        technique = "T1498"
        category = "denial_of_service"
        hypothesis = "The flow may represent volumetric or protocol-level denial-of-service behavior."
    elif syn_count > 2 and dst_port not in {21, 22, 80, 443}:
        technique = "T1046"
        category = "network_service_discovery"
        hypothesis = "The flow may represent scanning or service discovery behavior."
    elif dst_port in {21, 22} and syn_count >= 1:
        technique = "T1110"
        category = "brute_force"
        hypothesis = "The flow may represent credential brute-force activity against a remote service."
    elif dst_port in {80, 443, 8080} and bytes_per_second > 5000:
        technique = "T1190"
        category = "web_or_public_service_exploitation"
        hypothesis = "The flow may represent exploitation activity against a public-facing web service."
    else:
        technique = "unmapped"
        category = "generic_suspicious_flow"
        hypothesis = "The flow is suspicious according to the baseline alert source but lacks a specific mapped hypothesis."

    return {
        "narrative": hypothesis,
        "candidate_entities": [{"type": "network_service", "value": str(dst_port)}],
        "relationships": [{"subject": "source", "predicate": "connected_to", "object": f"destination_port_{dst_port}"}],
        "candidate_technique_id": technique,
        "candidate_category": category,
        "hypothesis": hypothesis,
        "evidence_references": list(select_alert_fields(record).keys()),
        "provider": "mock",
    }


def smt_rule_check(rule_id: str, facts: dict[str, float]) -> str:
    try:
        import z3
    except ModuleNotFoundError:
        return "z3_not_available"

    solver = z3.Solver()
    packets_per_second = z3.Real("packets_per_second")
    total_packets = z3.Real("total_packets")
    syn_count = z3.Real("syn_count")
    dst_port = z3.Real("dst_port")
    bytes_per_second = z3.Real("bytes_per_second")
    total_bwd_bytes = z3.Real("total_bwd_bytes")
    baseline_probability = z3.Real("baseline_probability")

    solver.add(packets_per_second == float(facts.get("packets_per_second", 0.0)))
    solver.add(total_packets == float(facts.get("total_packets", 0.0)))
    solver.add(syn_count == float(facts.get("syn_count", 0.0)))
    solver.add(dst_port == float(facts.get("dst_port", 0.0)))
    solver.add(bytes_per_second == float(facts.get("bytes_per_second", 0.0)))
    solver.add(total_bwd_bytes == float(facts.get("total_bwd_bytes", 0.0)))
    solver.add(baseline_probability == float(facts.get("baseline_probability", 0.0)))

    if rule_id == "RULE_DOS_FLOW_VOLUME":
        solver.add(
            z3.Or(
                packets_per_second > 250,
                total_packets > 1000,
                bytes_per_second > 100000,
                total_bwd_bytes > 10000,
                z3.And(z3.Or(dst_port == 80, dst_port == 443, dst_port == 8080), baseline_probability >= 0.65),
            )
        )
    elif rule_id == "RULE_SCAN_SYN_ACTIVITY":
        solver.add(z3.Or(z3.And(syn_count > 2, total_packets < 300), z3.And(baseline_probability >= 0.80, packets_per_second > 1000)))
    elif rule_id == "RULE_REMOTE_SERVICE_BRUTE_FORCE":
        solver.add(
            z3.And(
                z3.Or(dst_port == 21, dst_port == 22),
                z3.Or(syn_count >= 1, baseline_probability >= 0.80, total_packets >= 10),
            )
        )
    elif rule_id == "RULE_PUBLIC_WEB_SERVICE":
        solver.add(z3.And(z3.Or(dst_port == 80, dst_port == 443, dst_port == 8080), bytes_per_second > 5000))
    else:
        return "not_applicable"
    return str(solver.check())


def enrichment_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "narrative": {"type": "string"},
            "candidate_entities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"type": {"type": "string"}, "value": {"type": "string"}},
                    "required": ["type", "value"],
                },
            },
            "relationships": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "subject": {"type": "string"},
                        "predicate": {"type": "string"},
                        "object": {"type": "string"},
                    },
                    "required": ["subject", "predicate", "object"],
                },
            },
            "candidate_technique_id": {"type": "string", "enum": ["T1498", "T1046", "T1110", "T1190", "unmapped"]},
            "candidate_category": {
                "type": "string",
                "enum": [
                    "denial_of_service",
                    "network_service_discovery",
                    "brute_force",
                    "web_or_public_service_exploitation",
                    "generic_suspicious_flow",
                ],
            },
            "hypothesis": {"type": "string"},
            "evidence_references": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "narrative",
            "candidate_entities",
            "relationships",
            "candidate_technique_id",
            "candidate_category",
            "hypothesis",
            "evidence_references",
        ],
    }


def extract_response_text(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"]
    chunks: list[str] = []
    for item in payload.get("output", []):
        for part in item.get("content", []):
            if part.get("type") in {"output_text", "text"} and "text" in part:
                chunks.append(part["text"])
    return "".join(chunks)


def openai_enrich(record: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not available. Use mock enrichment or set the key in .env.local.")

    llm_cfg = config["llm"]
    body = {
        "model": llm_cfg.get("model", "gpt-5.4-mini"),
        "instructions": (
            "You enrich IDS flow alerts for a defensive SOC validation experiment. "
            "Use only the provided alert fields. Do not infer facts that are not supported by the fields. "
            "Use the baseline_predicted_label as a candidate alert type, not as ground truth. "
            "Map only to these covered techniques: T1498 denial_of_service, T1046 network_service_discovery, "
            "T1110 brute_force, T1190 web_or_public_service_exploitation. If the alert is outside those "
            "covered rules, use candidate_technique_id unmapped and candidate_category generic_suspicious_flow. "
            "Return the required JSON schema only."
        ),
        "input": json.dumps(select_alert_fields(record), sort_keys=True),
        "temperature": float(llm_cfg.get("temperature", 0)),
        "top_p": float(llm_cfg.get("top_p", 1)),
        "max_output_tokens": int(llm_cfg.get("max_output_tokens", 500)),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "soc_alert_enrichment",
                "strict": True,
                "schema": enrichment_schema(),
            }
        },
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=int(llm_cfg.get("timeout_seconds", 60))) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI enrichment request failed with HTTP {exc.code}: {message}") from exc

    text = extract_response_text(response_payload)
    parsed = json.loads(text)
    parsed["provider"] = "openai"
    parsed["response_id"] = response_payload.get("id")
    parsed["model"] = response_payload.get("model", llm_cfg.get("model"))
    return parsed


def validate_hypothesis(record: dict[str, Any], enrichment: dict[str, Any], *, check_smt: bool = True) -> dict[str, Any]:
    technique = enrichment.get("candidate_technique_id", "unmapped")
    category = enrichment.get("candidate_category", "generic_suspicious_flow")
    dst_port = int(get_float(record, "Destination Port", "Dst Port"))
    packets_per_second = get_float(record, "Flow Packets/s")
    bytes_per_second = get_float(record, "Flow Bytes/s")
    syn_count = get_float(record, "SYN Flag Count")
    total_packets = get_float(record, "Total Fwd Packets") + get_float(record, "Total Backward Packets")
    total_bwd_bytes = get_float(record, "Total Length of Bwd Packets")
    baseline_probability = get_float(record, "baseline_probability")

    evidence: list[str] = []
    disposition = "inconclusive"
    rule_id = "RULE_OUT_OF_COVERAGE"

    if technique == "T1498" or category == "denial_of_service":
        rule_id = "RULE_DOS_FLOW_VOLUME"
        if (
            packets_per_second > 250
            or total_packets > 1000
            or bytes_per_second > 100000
            or total_bwd_bytes > 10000
            or (dst_port in {80, 443, 8080} and baseline_probability >= 0.65)
        ):
            disposition = "supported"
            evidence.append("DoS-compatible flow evidence or high-confidence web-target alert")
        else:
            disposition = "unsupported"
            evidence.append("DoS preconditions not present in flow facts or baseline confidence")
    elif technique == "T1046" or category == "network_service_discovery":
        rule_id = "RULE_SCAN_SYN_ACTIVITY"
        if (syn_count > 2 and total_packets < 300) or (baseline_probability >= 0.80 and packets_per_second > 1000):
            disposition = "supported"
            evidence.append("scan-compatible SYN pattern or high-confidence high-rate probe flow")
        else:
            disposition = "unsupported"
            evidence.append("scan preconditions not present in the flow facts")
    elif technique == "T1110" or category == "brute_force":
        rule_id = "RULE_REMOTE_SERVICE_BRUTE_FORCE"
        if dst_port in {21, 22} and (syn_count >= 1 or baseline_probability >= 0.80 or total_packets >= 10):
            disposition = "supported"
            evidence.append("remote login service port with confidence or repeated-flow evidence")
        else:
            disposition = "unsupported"
            evidence.append("remote login service preconditions not present")
    elif technique == "T1190" or category == "web_or_public_service_exploitation":
        rule_id = "RULE_PUBLIC_WEB_SERVICE"
        if dst_port in {80, 443, 8080} and bytes_per_second > 5000:
            disposition = "supported"
            evidence.append("web service port with elevated byte rate")
        else:
            disposition = "unsupported"
            evidence.append("web-service exploitation preconditions not present")

    smt_result = smt_rule_check(
        rule_id,
        {
            "dst_port": float(dst_port),
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "syn_count": syn_count,
            "total_packets": total_packets,
            "total_bwd_bytes": total_bwd_bytes,
            "baseline_probability": baseline_probability,
        },
    ) if check_smt else "not_requested_development_only"
    return {
        "disposition": disposition,
        "rule_id": rule_id,
        "smt_result": smt_result,
        "evidence": evidence,
        "attack_mapping_available": technique != "unmapped",
        "rule_coverage": rule_id != "RULE_OUT_OF_COVERAGE",
    }


def calculate_metrics(test: pd.DataFrame, validation_rows: list[dict[str, Any]]) -> dict[str, Any]:
    alerts = pd.DataFrame(validation_rows)
    total_test = int(len(test))
    malicious_total = int(test["y_true"].sum())
    benign_total = int(total_test - malicious_total)
    baseline_alerts = test[test["baseline_predicted_malicious"] == 1]
    evaluated_ids = set(alerts["alert_id"].tolist()) if not alerts.empty else set()
    evaluated_baseline_alerts = baseline_alerts[baseline_alerts["alert_id"].isin(evaluated_ids)] if evaluated_ids else baseline_alerts.iloc[0:0]
    baseline_true_positive_alerts = evaluated_baseline_alerts[evaluated_baseline_alerts["y_true"] == 1]
    baseline_false_positive_alerts = evaluated_baseline_alerts[evaluated_baseline_alerts["y_true"] == 0]

    if alerts.empty:
        retained = pd.DataFrame()
    else:
        retained = alerts[alerts["disposition"].isin(["supported", "inconclusive", "enrichment_failure"])]

    retained_ids = set(retained["alert_id"].tolist()) if not retained.empty else set()
    removed_ids = set(alerts.loc[alerts["disposition"] == "unsupported", "alert_id"].tolist()) if not alerts.empty else set()
    tp_removed = int(len(set(baseline_true_positive_alerts["alert_id"].tolist()) & removed_ids))
    fp_removed = int(len(set(baseline_false_positive_alerts["alert_id"].tolist()) & removed_ids))
    validated_true_positive_alerts = int(len(set(baseline_true_positive_alerts["alert_id"].tolist()) & retained_ids))
    retained_false_positive_alerts = int(len(set(baseline_false_positive_alerts["alert_id"].tolist()) & retained_ids))

    full_baseline_true_positive_alerts = baseline_alerts[baseline_alerts["y_true"] == 1]
    full_baseline_false_positive_alerts = baseline_alerts[baseline_alerts["y_true"] == 0]
    partial_alert_run = int(len(evaluated_baseline_alerts)) < int(len(baseline_alerts))
    baseline_recall = full_baseline_true_positive_alerts.shape[0] / malicious_total if malicious_total else 0.0
    if partial_alert_run:
        validated_recall = (
            validated_true_positive_alerts / baseline_true_positive_alerts.shape[0]
            if baseline_true_positive_alerts.shape[0]
            else 0.0
        )
        recall_delta = validated_recall - 1.0 if baseline_true_positive_alerts.shape[0] else 0.0
        recall_metric_name = "evaluated_true_positive_alert_retention"
    else:
        validated_recall = validated_true_positive_alerts / malicious_total if malicious_total else 0.0
        recall_delta = validated_recall - baseline_recall
        recall_metric_name = "full_test_validated_recall"
    fp_reduction = fp_removed / len(baseline_false_positive_alerts) if len(baseline_false_positive_alerts) else 0.0
    baseline_fpr = len(full_baseline_false_positive_alerts) / benign_total if benign_total else 0.0
    validated_fpr = retained_false_positive_alerts / benign_total if benign_total else 0.0

    latencies = alerts["latency_seconds"].astype(float).tolist() if not alerts.empty else []
    enrichment_latencies = alerts["enrichment_latency_seconds"].astype(float).tolist() if "enrichment_latency_seconds" in alerts else []
    validation_latencies = alerts["validation_latency_seconds"].astype(float).tolist() if "validation_latency_seconds" in alerts else []
    p95 = float(np.percentile(latencies, 95)) if latencies else 0.0

    dispositions = alerts["disposition"].value_counts().to_dict() if not alerts.empty else {}
    return {
        "total_test_records": total_test,
        "metrics_scope": "evaluated_alert_subset" if int(len(evaluated_baseline_alerts)) < int(len(baseline_alerts)) else "full_baseline_alert_stream",
        "malicious_test_records": malicious_total,
        "benign_test_records": benign_total,
        "baseline_alerts": int(len(baseline_alerts)),
        "evaluated_baseline_alerts": int(len(evaluated_baseline_alerts)),
        "partial_alert_run": partial_alert_run,
        "baseline_true_positive_alerts": int(len(full_baseline_true_positive_alerts)),
        "baseline_false_positive_alerts": int(len(full_baseline_false_positive_alerts)),
        "evaluated_baseline_true_positive_alerts": int(len(baseline_true_positive_alerts)),
        "evaluated_baseline_false_positive_alerts": int(len(baseline_false_positive_alerts)),
        "baseline_recall": baseline_recall,
        "baseline_false_positive_rate": baseline_fpr,
        "validated_true_positive_alerts": validated_true_positive_alerts,
        "validated_false_positive_alerts_retained": retained_false_positive_alerts,
        "validated_recall": validated_recall,
        "validated_recall_metric_name": recall_metric_name,
        "validated_false_positive_rate": validated_fpr,
        "false_positive_alerts_removed": fp_removed,
        "true_positive_alerts_removed": tp_removed,
        "false_positive_reduction": fp_reduction,
        "recall_delta": recall_delta,
        "mean_added_latency_seconds": statistics.fmean(latencies) if latencies else 0.0,
        "median_added_latency_seconds": statistics.median(latencies) if latencies else 0.0,
        "p95_added_latency_seconds": p95,
        "mean_enrichment_latency_seconds": statistics.fmean(enrichment_latencies) if enrichment_latencies else 0.0,
        "mean_symbolic_validation_latency_seconds": statistics.fmean(validation_latencies) if validation_latencies else 0.0,
        "dispositions": dispositions,
    }


def add_inference_metrics(metrics: dict[str, Any], validation_rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(metrics)
    validation_cfg = config.get("validation", {})
    fp_target = float(validation_cfg.get("false_positive_reduction_target", 0.30))
    recall_margin = float(validation_cfg.get("recall_margin", 0.05))
    latency_target = float(validation_cfg.get("latency_target_seconds", 1.0))

    metrics["h1_false_positive_reduction_target"] = fp_target
    metrics["h1_target_met"] = metrics["false_positive_reduction"] >= fp_target
    metrics["h2_recall_margin"] = recall_margin
    metrics["h2_target_met"] = metrics["recall_delta"] >= -recall_margin
    metrics["h3_latency_target_seconds"] = latency_target
    metrics["h3_target_met"] = metrics["mean_added_latency_seconds"] < latency_target

    fp_n = int(metrics.get("evaluated_baseline_false_positive_alerts", 0))
    fp_removed = int(metrics.get("false_positive_alerts_removed", 0))
    try:
        from scipy import stats

        if fp_n:
            ci = stats.binomtest(fp_removed, fp_n).proportion_ci(confidence_level=0.95, method="wilson")
            metrics["false_positive_reduction_ci95"] = [float(ci.low), float(ci.high)]
            metrics["mcnemar_exact_p_value"] = float(stats.binomtest(0, fp_removed, p=0.5).pvalue) if fp_removed else 1.0
        else:
            metrics["false_positive_reduction_ci95"] = [0.0, 0.0]
            metrics["mcnemar_exact_p_value"] = None
    except Exception as exc:
        metrics["inference_warning"] = f"Could not calculate scipy inference metrics: {exc}"

    latencies = [float(row.get("latency_seconds", 0.0)) for row in validation_rows]
    if latencies:
        rng = random.Random(int(config["run"].get("seed", 42)))
        means = []
        for _ in range(1000):
            sample = [latencies[rng.randrange(len(latencies))] for _ in latencies]
            means.append(statistics.fmean(sample))
        means.sort()
        metrics["mean_added_latency_bootstrap_ci95"] = [means[int(0.025 * len(means))], means[int(0.975 * len(means)) - 1]]
    else:
        metrics["mean_added_latency_bootstrap_ci95"] = [0.0, 0.0]
    return metrics


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def write_chapter4_summary(path: Path, metrics: dict[str, Any], metadata: dict[str, Any]) -> None:
    lines = [
        "# Chapter 4 Run Summary",
        "",
        "## Baseline",
        "",
        f"- Baseline model: {metadata.get('baseline_model')}",
        f"- Test records: {metrics['total_test_records']}",
        f"- Baseline alerts: {metrics['baseline_alerts']}",
        f"- Evaluated baseline alerts: {metrics['evaluated_baseline_alerts']}",
        f"- Metrics scope: {metrics['metrics_scope']}",
        f"- Baseline false-positive alerts: {metrics['baseline_false_positive_alerts']}",
        f"- Baseline recall: {metrics['baseline_recall']:.4f}",
        "",
        "## Validation",
        "",
        f"- False-positive alerts removed: {metrics['false_positive_alerts_removed']}",
        f"- False-positive reduction: {metrics['false_positive_reduction']:.4f}",
        f"- False-positive reduction 95% CI: {metrics.get('false_positive_reduction_ci95')}",
        f"- H1 target met: {metrics.get('h1_target_met')}",
        f"- Validated recall metric: {metrics['validated_recall_metric_name']}",
        f"- Validated recall/retention value: {metrics['validated_recall']:.4f}",
        f"- Recall delta: {metrics['recall_delta']:.4f}",
        f"- H2 target met: {metrics.get('h2_target_met')}",
        f"- Mean added latency seconds: {metrics['mean_added_latency_seconds']:.4f}",
        f"- Mean added latency 95% bootstrap CI: {metrics.get('mean_added_latency_bootstrap_ci95')}",
        f"- Mean enrichment latency seconds: {metrics['mean_enrichment_latency_seconds']:.4f}",
        f"- Mean symbolic validation latency seconds: {metrics['mean_symbolic_validation_latency_seconds']:.4f}",
        f"- Median added latency seconds: {metrics['median_added_latency_seconds']:.4f}",
        f"- 95th percentile latency seconds: {metrics['p95_added_latency_seconds']:.4f}",
        f"- H3 target met: {metrics.get('h3_target_met')}",
        "",
        "## Dispositions",
        "",
    ]
    for disposition, count in sorted(metrics["dispositions"].items()):
        lines.append(f"- {disposition}: {count}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_result_tables(run_dir: Path, test: pd.DataFrame, validation_rows: list[dict[str, Any]], metrics: dict[str, Any]) -> None:
    tables_dir = run_dir / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)

    pd.DataFrame(
        [
            {"metric": key, "value": json.dumps(value) if isinstance(value, (dict, list)) else value}
            for key, value in sorted(metrics.items())
        ]
    ).to_csv(tables_dir / "metric_summary.csv", index=False)

    pd.DataFrame(
        [
            {
                "hypothesis": "H1",
                "metric": "false_positive_reduction",
                "target": metrics.get("h1_false_positive_reduction_target"),
                "result": metrics.get("false_positive_reduction"),
                "decision": "met" if metrics.get("h1_target_met") else "not_met",
            },
            {
                "hypothesis": "H2",
                "metric": "recall_delta",
                "target": f">= -{metrics.get('h2_recall_margin')}",
                "result": metrics.get("recall_delta"),
                "decision": "met" if metrics.get("h2_target_met") else "not_met",
            },
            {
                "hypothesis": "H3",
                "metric": "mean_added_latency_seconds",
                "target": f"< {metrics.get('h3_latency_target_seconds')}",
                "result": metrics.get("mean_added_latency_seconds"),
                "decision": "met" if metrics.get("h3_target_met") else "not_met",
            },
        ]
    ).to_csv(tables_dir / "hypothesis_decisions.csv", index=False)

    pd.DataFrame(
        [{"disposition": key, "count": value} for key, value in sorted(metrics.get("dispositions", {}).items())]
    ).to_csv(tables_dir / "disposition_counts.csv", index=False)

    validation = pd.DataFrame(validation_rows)
    if not validation.empty:
        validation.groupby(["label", "disposition"], dropna=False).size().reset_index(name="count").to_csv(
            tables_dir / "disposition_by_label.csv", index=False
        )

    label_counts = test[LABEL_COLUMN].astype(str).value_counts().rename_axis("label").reset_index(name="test_records")
    label_counts.to_csv(tables_dir / "label_distribution_test.csv", index=False)

    baseline_tp = int(((test["baseline_predicted_malicious"] == 1) & (test["y_true"] == 1)).sum())
    baseline_fp = int(((test["baseline_predicted_malicious"] == 1) & (test["y_true"] == 0)).sum())
    baseline_tn = int(((test["baseline_predicted_malicious"] == 0) & (test["y_true"] == 0)).sum())
    baseline_fn = int(((test["baseline_predicted_malicious"] == 0) & (test["y_true"] == 1)).sum())
    rows = [
        {"condition": "baseline", "tp": baseline_tp, "fp": baseline_fp, "tn": baseline_tn, "fn": baseline_fn}
    ]
    if not metrics.get("partial_alert_run"):
        unsupported_ids = set(validation.loc[validation["disposition"] == "unsupported", "alert_id"].tolist())
        validated_pred = test["baseline_predicted_malicious"].copy()
        validated_pred = validated_pred.mask(test["alert_id"].isin(unsupported_ids), 0)
        rows.append(
            {
                "condition": "validated",
                "tp": int(((validated_pred == 1) & (test["y_true"] == 1)).sum()),
                "fp": int(((validated_pred == 1) & (test["y_true"] == 0)).sum()),
                "tn": int(((validated_pred == 0) & (test["y_true"] == 0)).sum()),
                "fn": int(((validated_pred == 0) & (test["y_true"] == 1)).sum()),
            }
        )
    pd.DataFrame(rows).to_csv(tables_dir / "confusion_counts.csv", index=False)


def run_pipeline(root: Path, config_path: Path, synthetic: bool = False, enricher: str | None = None, max_alerts: int | None = None) -> RunContext:
    config = read_config(config_path)
    if enricher:
        config["run"]["enricher"] = enricher
    if max_alerts is not None:
        config["run"]["max_alerts"] = max_alerts
    # Local/synthetic runs do not need or read credential files.
    if config["run"].get("enricher", "mock") == "openai":
        load_env_file(root / ".env.local")

    context = make_run_context(root, config_path, config)
    df = load_data(root, config, synthetic=synthetic)
    test, baseline_metadata = train_baseline(df, config)
    test = test.reset_index(drop=True)
    test["alert_id"] = [f"alert_{i:06d}" for i in range(len(test))]
    baseline_alerts = test[test["baseline_predicted_malicious"] == 1].copy()
    max_alerts_value = int(config["run"].get("max_alerts", 0) or 0)
    if max_alerts_value:
        baseline_alerts = baseline_alerts.head(max_alerts_value).copy()

    validation_rows: list[dict[str, Any]] = []
    provider = config["run"].get("enricher", "mock")
    for _, alert in baseline_alerts.iterrows():
        record = alert.to_dict()
        started = time.perf_counter()
        try:
            enrichment_started = time.perf_counter()
            enrichment = openai_enrich(record, config) if provider == "openai" else mock_enrich(record)
            enrichment_latency = time.perf_counter() - enrichment_started
            validation_started = time.perf_counter()
            validation = validate_hypothesis(record, enrichment)
            validation_latency = time.perf_counter() - validation_started
            latency = time.perf_counter() - started
            validation_rows.append(
                {
                    "alert_id": record["alert_id"],
                    "y_true": int(record["y_true"]),
                    "baseline_probability": float(record["baseline_probability"]),
                    "label": str(record.get(LABEL_COLUMN, "")),
                    "provider": enrichment.get("provider", provider),
                    "candidate_technique_id": enrichment.get("candidate_technique_id"),
                    "candidate_category": enrichment.get("candidate_category"),
                    "hypothesis": enrichment.get("hypothesis"),
                    "response_id": enrichment.get("response_id"),
                    "model": enrichment.get("model"),
                    "disposition": validation["disposition"],
                    "rule_id": validation["rule_id"],
                    "smt_result": validation["smt_result"],
                    "rule_coverage": validation["rule_coverage"],
                    "attack_mapping_available": validation["attack_mapping_available"],
                    "evidence": validation["evidence"],
                    "input_alert_fields": select_alert_fields(record),
                    "enrichment_latency_seconds": enrichment_latency,
                    "validation_latency_seconds": validation_latency,
                    "latency_seconds": latency,
                }
            )
        except Exception as exc:
            validation_rows.append(
                {
                    "alert_id": record["alert_id"],
                    "y_true": int(record["y_true"]),
                    "baseline_probability": float(record["baseline_probability"]),
                    "label": str(record.get(LABEL_COLUMN, "")),
                    "provider": provider,
                    "candidate_technique_id": None,
                    "candidate_category": None,
                    "hypothesis": None,
                    "disposition": "enrichment_failure",
                    "rule_id": "RULE_ENRICHMENT_FAILURE",
                    "smt_result": "not_applicable",
                    "rule_coverage": False,
                    "attack_mapping_available": False,
                    "evidence": [str(exc)],
                    "input_alert_fields": select_alert_fields(record),
                    "enrichment_latency_seconds": time.perf_counter() - started,
                    "validation_latency_seconds": 0.0,
                    "latency_seconds": time.perf_counter() - started,
                }
            )

    metrics = add_inference_metrics(calculate_metrics(test, validation_rows), validation_rows, config)
    manifest = {
        "started_at": context.started_at,
        "config_path": str(config_path),
        "enricher": provider,
        "synthetic_data": bool(synthetic or not config["data"].get("csv_paths")),
        "baseline_metadata": baseline_metadata,
        "input_rows": int(len(df)),
        "validated_alert_rows": int(len(validation_rows)),
    }

    test.to_csv(context.run_dir / "test_predictions.csv", index=False)
    baseline_alerts.to_csv(context.run_dir / "baseline_alerts.csv", index=False)
    write_jsonl(context.run_dir / "validation_results.jsonl", validation_rows)
    write_json(context.run_dir / "metrics.json", metrics)
    write_json(context.run_dir / "manifest.json", manifest)
    write_result_tables(context.run_dir, test, validation_rows, metrics)
    write_chapter4_summary(context.run_dir / "chapter4_run_summary.md", metrics, baseline_metadata)
    return context
