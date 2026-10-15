# October policy correction and local timing

Release 1.1.0 · October 15, 2026

This release adds two dated evidence sets to the preserved September package:
the October 2 retrospective policy replay and the October 13 corrected-policy
local timing diagnostic. The analytical replay and timing run reused frozen
predictions; neither fitted a detector or selected a new score threshold.

## What changed

The correction addresses two specific rule boundaries:

1. **Predicted web brute force is outside coverage.** A predicted label starting
   with `Web Attack` and containing `brute` remains a candidate but is retained
   as inconclusive. Available flow fields cannot establish a web login attempt.
   This decision uses the predicted label, not the ground-truth label.
2. **The impossible scan branch is retired.** Remove
   `SYN Flag Count > 2 AND total_packets < 300`; retain
   `baseline_probability >= 0.80 AND Flow Packets/s > 1000`. The sampled SYN field
   spans 0–1, so retiring the first branch changes no observed disposition. The
   retained score-plus-rate rule remains a heuristic, not independent proof of
   scanning.

On the September group-split queue, the combined correction changes 505 alerts
from unsupported to inconclusive: 35 benign and 470 malicious. Thus original
removals of 117 FP / 795 TP become **82 FP / 325 TP**. The web-coverage correction
accounts for all of this change; scan-branch retirement contributes zero.
The narrow selected correction is distinct from retaining all predicted Web
Attack alerts or changing missing-fact semantics.

This is a retrospective correction after examining an already known benchmark.
It is not a new independent confirmation, and it does not recover undocumented
original threshold rationales. Supported, unsupported and inconclusive describe
consistency with encoded facts and rules. Unsupported is not equivalent to
benign; these results do not justify automatic alert suppression.

## Current accuracy comparison

The frozen test set contains 120,059 rows, with 23,603 malicious rows. At the
fixed 0.15 emission threshold, 23,939 alerts comprise 23,564 TP and 375 FP.
The corrected policy retains 23,239 TP, giving recall of 98.4578% compared with
the reference detector's 99.8348%.

| Measure | Corrected result | Interpretation |
| --- | --- | --- |
| FP reduction | 82 / 375 = 21.8667% | H1 does not meet the 30% target. |
| 95% FP-reduction interval | 17.2826%–26.2052% | Exact-feature-group bootstrap; also below 30%. |
| Additional recall loss | 325 / 23,603 = 1.3769 percentage points | Removal of detected attacks remains a material cost. |
| 95% recall-loss interval | 1.2260–1.5505 percentage points | Within the five-point H2 margin under this resampling scheme. |
| Frozen score comparator (0.21) | 110 FP / 11 TP removed | Removes 28 more FP and 314 fewer TP than the corrected rules. |

The interval uses 1,000 resamples of exact-feature groups with seed 42. Matching
feature vectors stay together; the malicious-row denominator is recomputed in
each draw. These intervals do not establish independence of near-related traffic
or transport to another SOC. H2 is a conditional margin result, not a formal
non-inferiority trial or operational safety finding. The 30% and five-point
criteria, the one-second timing criterion and numerical rule thresholds remain
study-specific. No retained original calibration makes them general standards.

The frozen score cutoff was selected on September development data against the
original symbolic policy. October keeps that lock; it does not retune the
comparator after seeing corrected test results. Poor capture-day transfer,
dataset-label defects and benchmark dependence remain limitations. No analyst
workload, trust, decision-quality or time-saving benefit was measured.

## Corrected local timing

On October 13, the corrected local implementation processed all 23,939 saved
baseline alerts after 25 untimed warmups. The mean was **2.336 ms per alert**
(2.3365 ms at four decimal places); median 2.0981 ms, 95th percentile 4.2632 ms,
and maximum 51.3031 ms. This meets H3's one-second **mean** criterion on this
workload and machine; it is not a worst-case guarantee for other workloads.

The timer starts immediately before fresh deterministic `mock_enrich` and ends
when corrected validation returns its in-memory record. It includes fact
normalization, rule dispatch and applicable Z3 construction/checks. Predicted
web brute force returns inconclusive without an obsolete rule/solver check.
The scan correction is applied in both Python and SMT.

The interval excludes dataset loading, reconstruction/preprocessing, detector
fitting or inference, input-dictionary construction, serialization, disk I/O,
network/hosted calls, program startup and warmup. The adapter is isolated from
the preserved historical pipeline; this benchmark is not proof of a deployed
application change.

All corrected decisions matched the saved replay. The full pass produced
22,693 supported, 407 unsupported and 839 inconclusive records, with 23,100
applicable solver checks. The 407 unsupported records are the same 82 FP and
325 TP reported above. Five passes of one fixed, seeded 1,000-alert sample had
corrected means of **2.086–2.267 ms**. Each policy received 25 untimed warmups before the repeat series; record order
stayed fixed and policy order alternated across passes.

These repeats are measurements of one sample, not five independent traffic
samples. No iid confidence interval, causal speedup or hardware-normalized
comparison is claimed. The historical September mean of 3.552 ms is preserved.
The October measurement used Python 3.11.4 on an Intel i7-9750H workstation with
approximately 15.88 GiB RAM, in one sequential process; operating-system and
other application load were not experimentally controlled. The
[environment receipt](../evidence/20261013/environment.json) records details.
It is not hosted-model latency, concurrent throughput or production capacity.

## Public evidence and verification

| Public record | Scope |
| --- | --- |
| [October policy summary](../evidence/20261002/SUMMARY.md) and [comparison CSV](../evidence/20261002/policy_comparison.csv) | Retained aggregate records for seven policies across June plus six September conditions. |
| [October policy manifest](../evidence/20261002/public_manifest.json) | Public file hashes and source-evidence provenance. |
| [October timing results](../evidence/20261013/results.json) and [protocol](../evidence/20261013/protocol.md) | The separate corrected local timing diagnostic. |
| [October timing manifest](../evidence/20261013/public_manifest.json) | Public file hashes and source-evidence provenance. |
| [September evidence](../evidence/20260905/results.json) | Preserved original corrective evaluation. |

From the repository root:

```sh
python scripts/verify_published_evidence.py
python scripts/verify_october_evidence.py
```

These checks use only the standard library and published aggregate files. They
verify arithmetic, consistency and hashes; they cannot independently recount
unpublished per-alert records. The included independent-check receipts report
the original local review, not a fresh public raw-data audit. Public provenance
is a sanitized derivative; raw rows, alert identities, absolute local paths and
private repository state are excluded.

The portable October runner reproduces the main **duplicate-group-split**
comparison and corrected timing procedure. Auxiliary June, capture-day,
broader-web and missing-fact sensitivity aggregates are retained historical
records; this runner does not regenerate all 49 archived policy-condition
combinations. Do not treat missing-fact sensitivities as part of the selected
combined correction or sum overlapping conditions as unique traffic records.

The [code adaptation receipt](../OCTOBER_CODE_PROVENANCE.json) distinguishes
the portable public entry points from the original run scripts. The corrected
validator adapter is copied byte for byte; portable orchestration replaces
private paths while preserving the declared rule and timing boundaries.

## Local reproduction

Install the pinned dependencies and obtain the eight configured CSVs as described
in the [README](../README.md#reproduce-locally). Run commands from the repository
root with new output directories.

```sh
# Regenerate the September group-split model, predictions and locked selection.
python scripts/run_corrective_evaluation.py --conditions duplicate_group_split --output outputs/corrective_evaluation/september_reproduction

# Replay four policies against those frozen predictions; no model fitting.
python scripts/replay_october_policy.py --frozen-run outputs/corrective_evaluation/september_reproduction --output outputs/october_replay

# Measure fresh mock enrichment and corrected validation on the frozen alerts.
python scripts/time_corrected_policy_20261013.py --frozen-run outputs/corrective_evaluation/september_reproduction --replay outputs/october_replay --output outputs/october_timing
```

The first step fits the September model because original row-level predictions
are not distributed. The replay and timing steps then require that saved run,
its frozen configuration/selection records and output receipts, matching
historical source hashes, and local raw CSVs for reconstruction. Both October commands accept `--data-root PATH` when the base
for the manifest's configured relative CSV paths differs from the repository
root. Their input checks must pass; published aggregates are not substitute
inputs for the saved run.

Replay writes `alert_dispositions.csv`, `results.json`, `manifest.json` and
`policy_comparison.csv` directly beneath its output directory. The timing run
writes `full_corrected_timings.csv`, `sample_repeat_timings.csv`, `results.json`,
`workload.json`, `environment.json`, `boundary_checks.json` and `manifest.json`
beneath its own directory.
All generated row-level evidence stays local and is ignored by Git. New elapsed
times depend on the execution environment and are not expected to match the
recorded October measurement exactly.

The pinned environment and input/source hashes support checking a reproduction.
Any disagreement should be investigated and reported, not resolved by editing
generated metrics or replacing preserved evidence with a more favorable run.

## Release history

The [v1.0.0 source](https://github.com/troncook/soc-alert-validation-reproducibility/tree/v1.0.0)
remains the September snapshot. Version 1.1.0 adds October evidence and portable
entry points without replacing the September protocol, original source,
aggregate evidence or executed notebook. The historical June pipeline and the
small hosted diagnostic remain distinct from the October local claims.
