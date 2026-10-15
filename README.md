# SOC alert validation reproducibility

Research code for local post-detection symbolic validation of CICIDS2017 alerts.
The system records supported, unsupported or inconclusive rule checks. These
are model-relative dispositions: **unsupported does not mean benign**.

## Current results — version 1.1.0

This release adds the October 2 policy correction and the separate October 13
local timing diagnostic. The correction reuses frozen September predictions;
it does not retrain the detector, select new thresholds or use a hosted model.

The group-separated test set contains 120,059 records, including 23,603 malicious
records. The fixed 0.15 reference queue has 23,939 alerts: 375 false positives
(FP) and 23,564 true positives (TP). All three rows use that same queue.

| Policy | FP removed | TP removed | Additional recall loss (percentage points) |
| --- | ---: | ---: | ---: |
| October corrected symbolic policy | 82 | 325 | 1.3769 |
| Frozen development-selected score filter (0.21) | 110 | 11 | 0.0466 |
| September original symbolic policy — historical | 117 | 795 | 3.3682 |

The score filter removes **28 more false positives and 314 fewer true positives**
than the corrected symbolic policy. The correction improves the symbolic
policy's recall tradeoff, but does not establish an advantage over this comparator.

- **H1: not met.** FP reduction is 21.867%, below the study's 30% target.
- **H2: met conditionally on the declared analysis.** Additional recall loss is
  1.3769 percentage points; its 95% exact-feature-group bootstrap interval is
  1.2260–1.5505 points, within the five-point margin. Losing 325 detected attacks
  remains consequential. Grouping exact feature matches does not establish
  independence of all related traffic or safe alert suppression.
- **H3: met for the measured local workload.** Fresh deterministic enrichment
  plus corrected validation, including applicable Z3 checks, averaged 2.336 ms
  across 23,939 alerts after 25 untimed warmups. Five repeats of one fixed
  1,000-alert sample had means of 2.086–2.267 ms. This excludes detector inference,
  hosted/network calls and I/O; it is not production throughput or a speedup claim.

The historical targets and rule thresholds are study-specific. No retained
original calibration establishes them as universal SOC standards. No analyst
workload, decision-quality or time-saving benefit was measured.

See the [October methods and evidence guide](docs/october_update_20261015.md),
[policy evidence](evidence/20261002/SUMMARY.md) and
[timing evidence](evidence/20261013/SUMMARY.md) for the exact scope and limitations.

## Check the published evidence

These standard-library checks need no dataset, API key or model fitting:

```sh
python scripts/verify_published_evidence.py
python scripts/verify_october_evidence.py
```

They check the public aggregate records, arithmetic and hashes. They cannot
independently recount unpublished row-level evidence or rerun the recorded
benchmark. The original local review receipts are retained as evidence of those
checks, separately from what a reader can verify from this public package.

## Reproduce locally

The recorded environment is Python 3.11.4 with packages pinned in
`requirements-lock.txt`. Use an isolated environment. No API key is required.

```sh
python -m venv .venv
# Activate the environment for your operating system.
python -m pip install -r requirements-lock.txt
python -m unittest discover -s tests -v
python scripts/run_corrective_evaluation.py --synthetic --output outputs/synthetic_check
```

Obtain the eight CICIDS2017 MachineLearningCSV files named in
`config/cicids2017_full_candidate.toml` from the
[original UNB dataset source](https://www.unb.ca/cic/datasets/ids-2017.html) and
place them under `data/raw/cicids2017/`. Raw data are not redistributed here.

First regenerate the September group-split inputs. **This first step fits the
September detector**; the two October steps reuse its saved predictions.

```sh
python scripts/run_corrective_evaluation.py --conditions duplicate_group_split --output outputs/corrective_evaluation/september_reproduction
python scripts/replay_october_policy.py --frozen-run outputs/corrective_evaluation/september_reproduction --output outputs/october_replay
python scripts/time_corrected_policy_20261013.py --frozen-run outputs/corrective_evaluation/september_reproduction --replay outputs/october_replay --output outputs/october_timing
```

Use new output folders. Generated row-level records stay local under the ignored
`outputs/` directory. The October replay covers the group-split original policy,
web-brute correction, scan-branch retirement and combined correction, with the
frozen score comparator. It does not regenerate the archived June, capture-day,
broader web or missing-fact sensitivity records. Timing depends on the host and
background load; exact elapsed times are not expected to match the saved run.
See the [guide](docs/october_update_20261015.md#local-reproduction) for inputs,
outputs and the timing boundary.

## Preserved September evaluation

[Version 1.0.0](https://github.com/troncook/soc-alert-validation-reproducibility/tree/v1.0.0)
and [September evidence](evidence/20260905/results.json) preserve the original
corrective evaluation. It used the capped 400,000-row, eight-file sample and a
100-tree Random Forest, with training-only imputation, exact-duplicate-group
separation, development-only threshold selection and five capture-day holdouts.
The [September protocol](docs/remediation_protocol_20260905.md) preceded those
new calculations, but earlier dataset outcomes were already known. It was a
retrospective correction, not an independent external confirmation.

Under the September original rules, the group-split policy removed 117 FP and
795 TP; its serial local mean was 3.552 ms. These are historical measurements,
not the corrected policy's current results. The severe Wednesday and Thursday
recall losses remain relevant transfer limitations. Capture-day challenges use
different models and attack compositions; they are not independent replications
or a forward-time deployment simulation.

To reproduce all six September conditions instead of only the group split:

```sh
python scripts/run_corrective_evaluation.py --output outputs/september_all_conditions
```

The [September reconciliation](evidence/20260905/corrective_verification.json)
and [executed audit notebook](notebooks/review_corrective_evidence.ipynb) are
unchanged. The notebook audits aggregates; it is not a second model fit.
`scripts/run_experiment.py` also preserves the earlier random-record-split,
pre-split-imputation pipeline. It is historical and separate from the corrected
evaluation. Optional hosted enrichment is not used by these reproduction commands.

## Publication boundaries and citation

Cite [version 1.1.0](https://github.com/troncook/soc-alert-validation-reproducibility/tree/v1.1.0)
using [CITATION.cff](CITATION.cff); see the [changelog](CHANGELOG.md).
Versioned source hashes identify the implementation bytes. GitHub tags provide
version identifiers, not a permanent DOI archive.

This clean public package contains no private manuscript, advisor correspondence,
private Git history, raw dataset rows, trained-model pickle, credentials or hosted
response payloads. No software license has been selected; public visibility is
not an open-source license grant. The system is not a production intrusion
prevention system, and these results do not establish operational safety.

Code and analysis preparation used AI assistance under student review. The
student remains responsible for understanding, checking and explaining the
methods and any submitted academic claims.
