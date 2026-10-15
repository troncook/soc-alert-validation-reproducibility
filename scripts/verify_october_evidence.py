"""Check published October bytes and aggregate consistency, without rerunning research.

Uses only the Python standard library. It cannot recompute a bootstrap interval
or timing distribution from aggregates, and does not verify raw-row identities.
Those are recorded in the explicitly scoped saved independent-check receipts.
"""
import csv
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_CONDITIONS = {
    'duplicate_group_split', 'historical_june', 'leave_day_out_Monday',
    'leave_day_out_Tuesday', 'leave_day_out_Wednesday',
    'leave_day_out_Thursday', 'leave_day_out_Friday',
}
POLICIES = {
    'existing_rules', 'web_brute_out_of_coverage', 'scan_dead_branch_retired',
    'combined_web_brute_and_scan', 'all_predicted_web_out_of_coverage_sensitivity',
    'training_median_validator_facts_sensitivity',
    'missing_required_fact_inconclusive_sensitivity',
}


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise AssertionError(message)


def equal(a, b, message):
    if a is None or b is None:
        require(a is b, message)
    else:
        require(math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-12), message)


def verify_manifest(date):
    folder = ROOT / 'evidence' / date
    manifest = read(folder / 'public_manifest.json')
    require(manifest['export_kind'] == 'derived_sanitized_public_provenance', date)
    require(manifest['original_manifest']['included'] is False, date)
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
    require(actual == set(manifest['files']) | {'public_manifest.json'}, f'{date}: inventory')
    for name, receipt in manifest['files'].items():
        target = (folder / name).resolve()
        require(target.is_relative_to(folder.resolve()), f'{date}: path outside bundle')
        require(sha(target) == receipt['sha256'], f'{date}/{name}: hash')
        require(target.stat().st_size == receipt['bytes'], f'{date}/{name}: bytes')
        if receipt['transformation'].startswith('exact bytes'):
            require(receipt['sha256'] == receipt['source']['sha256'], f'{name}: original bytes')
    return manifest


def main():
    manifests = {d: verify_manifest(d) for d in ['20261002', '20261013']}
    replay_dir = ROOT / 'evidence/20261002'
    results = {p.parent.name: read(p) for p in replay_dir.glob('*/results.json')}
    require(set(results) == EXPECTED_CONDITIONS, 'Seven selected replay conditions')
    policy_count = 0
    for name, result in results.items():
        require(result['condition'] == name, name)
        require(set(result['policies']) == POLICIES, f'{name}: policy coverage')
        require(not any(result['reproduction_mismatches'].values()), f'{name}: reproduction')
        require(result['scan_audit']['syn_branch_true'] == 0, f'{name}: impossible branch')
        original = result['policies']['existing_rules']
        scan = result['policies']['scan_dead_branch_retired']
        require(scan == original, f'{name}: scan-only zero effect')
        require(result['policies']['web_brute_out_of_coverage'] ==
                result['policies']['combined_web_brute_and_scan'], f'{name}: combined effect')
        for policy, m in result['policies'].items():
            tag = f'{name}/{policy}'
            require(m['baseline_tp'] - m['retained_tp'] == m['tp_removed'], tag)
            require(m['baseline_fp'] - m['retained_fp'] == m['fp_removed'], tag)
            require(m['validated_fn'] == m['baseline_fn'] + m['tp_removed'], tag)
            require(m['validated_tn'] == m['baseline_tn'] + m['fp_removed'], tag)
            require(m['malicious'] + m['benign'] == m['test_rows'], tag)
            require(m['baseline_tp'] + m['baseline_fn'] == m['malicious'], tag)
            require(m['baseline_tn'] + m['baseline_fp'] == m['benign'], tag)
            require(sum(m['dispositions'].values()) == m['baseline_tp'] + m['baseline_fp'], tag)
            require(m['dispositions']['unsupported'] == m['fp_removed'] + m['tp_removed'], tag)
            equal(m['fp_reduction'], m['fp_removed'] / m['baseline_fp'] if m['baseline_fp'] else None, tag)
            equal(m['baseline_recall'], m['baseline_tp'] / m['malicious'] if m['malicious'] else None, tag)
            equal(m['validated_recall'], m['retained_tp'] / m['malicious'] if m['malicious'] else None, tag)
            equal(m['recall_delta'], -m['tp_removed'] / m['malicious'] if m['malicious'] else None, tag)
            if 'feature_group_bootstrap' in m:
                group = m['feature_group_bootstrap']
                expected_ci = [-100 * group['recall_delta_ci95'][1], -100 * group['recall_delta_ci95'][0]]
                for a, b in zip(m['recall_loss_percentage_points_ci95'], expected_ci):
                    equal(a, b, tag + ': CI unit conversion')
            policy_count += 1
    with (replay_dir / 'policy_comparison.csv').open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle))
    require(len(rows) == policy_count, 'Aggregate CSV row count')
    require(len({(r['condition'], r['policy']) for r in rows}) == policy_count, 'Unique aggregate rows')
    for row in rows:
        m = results[row['condition']]['policies'][row['policy']]
        for key, value in row.items():
            if key not in ['condition', 'policy']:
                equal(float(value) if value else None, m[key], f'CSV {key}')

    chosen = results['duplicate_group_split']['policies']['combined_web_brute_and_scan']
    old = results['duplicate_group_split']['policies']['existing_rules']
    require((old['fp_removed'], old['tp_removed']) == (117, 795), 'Original pair')
    require((chosen['fp_removed'], chosen['tp_removed']) == (82, 325), 'Corrected pair')
    require(old['fp_removed'] - chosen['fp_removed'] == 35 and old['tp_removed'] - chosen['tp_removed'] == 470,
            '505 retained outcomes')
    require(chosen['changed_dispositions'] == 505 and chosen['malicious'] == 23603, 'Current denominator')
    require(chosen['feature_group_bootstrap']['groups'] == 114073, 'Exact-feature groups')
    require(chosen['feature_group_bootstrap']['draws'] == 1000, 'Bootstrap draws')
    require(manifests['20261002']['recorded_run_metadata']['seed'] == 42, 'Recorded seed')
    require(chosen['fp_reduction'] < 0.30 and not chosen['h1_interval_support'], 'H1 not met')
    require(chosen['recall_loss_percentage_points_ci95'][1] < 5 and
            chosen['h2_interval_within_five_percentage_points'], 'Conditional H2 margin')
    september = next(r for r in read(ROOT / 'evidence/20260905/results.json') if r['condition'] == 'duplicate_group_split')
    score = september['policies']['development_score_filter']
    require((score['fp_removed'], score['tp_removed']) == (110, 11), 'Preserved score comparator')
    require(september['selection']['score_only_cutoff'] == 0.21, 'Development-locked cutoff')
    prior_replay_check = read(replay_dir / 'independent_checks.json')
    require(prior_replay_check['status'] == 'passed' and not prior_replay_check['issues'], 'Saved replay audit')
    require(prior_replay_check['replay_manifest_sha256'] == manifests['20261002']['original_manifest']['sha256'], 'Replay audit binding')

    timing = read(ROOT / 'evidence/20261013/results.json')
    full = timing['full_corrected']
    require(timing['status'] == 'passed' and timing['decision_mismatches'] == timing['smt_disagreements'] == 0,
            'Timing status')
    require((timing['fp_removed'], timing['tp_removed']) == (82, 325), 'Timing policy outcomes')
    require(full['alerts'] == 23939 and full['dispositions'] == chosen['dispositions'], 'Full timing workload')
    require(full['smt_results'] == {'sat': 22693, 'unsat': 407, 'not_applicable': 839}, 'SMT aggregate counts')
    require(timing['full_warmup_alerts'] == timing['repeat_warmup_alerts_per_policy'] == 25, 'Warmup protocol')
    require(timing['confidence_interval'] is None, 'No timing CI')
    require(full['mean_seconds'] < timing['criterion_seconds'] == 1.0 and timing['corrected_local_mean_target_met'], 'Local H3')
    repeats = timing['repeat_summaries']
    require(len(repeats) == 10, 'Five passes per policy')
    require({(r['policy'], r['repeat']) for r in repeats} ==
            {(p, n) for p in ['original', 'corrected'] for n in range(1, 6)}, 'Repeat labels')
    require(all(r['alerts'] == 1000 for r in repeats), 'Repeated sample size')
    for m in [full] + repeats:
        equal(m['mean_seconds'], m['mean_enrichment_seconds'] + m['mean_validation_seconds'], 'Mean component sum')
        require(sum(m['dispositions'].values()) == sum(m['smt_results'].values()) == m['alerts'], 'Timing count sums')
        require(0 <= m['median_seconds'] <= m['p95_seconds'] <= m['maximum_seconds'], 'Timing summary order')
    audit = read(ROOT / 'evidence/20261013/independent_checks.json')
    require(audit['status'] == 'passed' and not audit['issues'] and audit['checks_count'] == 66, 'Saved timing audit')
    require(len(audit['checks']) == 66 and all(c['passed'] for c in audit['checks']), 'Saved timing checks')
    require(audit['manifest_sha256'] == manifests['20261013']['original_manifest']['sha256'], 'Timing audit binding')
    for key, value in audit['full_recomputed'].items():
        if isinstance(value, dict):
            require(value == full[key], f'Prior recount {key}')
        else:
            equal(value, full[key], f'Prior recount {key}')
    means = [r['mean_seconds'] * 1000 for r in repeats if r['policy'] == 'corrected']
    print(json.dumps({
        'status': 'passed', 'public_evidence_files_hashed': sum(len(m['files']) for m in manifests.values()),
        'replay_conditions': len(results), 'policy_arithmetic_blocks': policy_count,
        'corrected_fp_tp_removed': [chosen['fp_removed'], chosen['tp_removed']],
        'locked_score_fp_tp_removed': [score['fp_removed'], score['tp_removed']],
        'recall_loss_percentage_points': -100 * chosen['recall_delta'],
        'recorded_loss_ci95_percentage_points': chosen['recall_loss_percentage_points_ci95'],
        'H1_target_met': False, 'H2_recorded_group_interval_within_margin': True,
        'full_corrected_local_mean_ms': full['mean_seconds'] * 1000,
        'corrected_repeat_mean_range_ms': [min(means), max(means)],
        'scope': 'Public bytes and aggregate consistency only; not raw-data replication, bootstrap recomputation or a timing rerun.',
    }, indent=2))


if __name__ == '__main__':
    main()
