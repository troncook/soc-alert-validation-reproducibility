"""Isolated corrected-policy timing adapter; historical pipeline remains untouched.

Derived from the current pipeline functions. Differences: web-brute coverage
exit; Python and SMT scan branch retirement; accurate scan evidence wording.
All seven solver fact bindings and ordinary fact normalization are retained.
"""
from typing import Any
from soc_validation_experiment.pipeline import get_float


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
        solver.add(z3.And(baseline_probability >= 0.80, packets_per_second > 1000))
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


def validate_hypothesis(record: dict[str, Any], enrichment: dict[str, Any], *, check_smt: bool = True) -> dict[str, Any]:
    technique = enrichment.get("candidate_technique_id", "unmapped")
    category = enrichment.get("candidate_category", "generic_suspicious_flow")
    predicted_label = str(record.get("baseline_predicted_label", "")).casefold()
    if predicted_label.startswith("web attack") and "brute" in predicted_label:
        return {
            "disposition": "inconclusive",
            "rule_id": "RULE_OUT_OF_COVERAGE",
            "smt_result": "not_applicable",
            "evidence": ["Predicted web brute force is outside the coverage of the available flow facts"],
            "attack_mapping_available": technique != "unmapped",
            "rule_coverage": False,
        }
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
        if baseline_probability >= 0.80 and packets_per_second > 1000:
            disposition = "supported"
            evidence.append("high-confidence high-rate probe flow under corrected scan predicate")
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
