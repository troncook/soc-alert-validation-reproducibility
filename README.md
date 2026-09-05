# SOC alert validation reproducibility

Research code for a local post-detection symbolic validation experiment using
CICIDS2017. This repository supports professor review and reproducibility; it is
not a production intrusion prevention system or evidence of operational safety.

## Scope

The corrective evaluation keeps the existing capped eight-file sample,
100-tree Random Forest, deterministic enrichment and symbolic predicates. It
adds train-only imputation, duplicate-group separation, development-only
threshold selection and five capture-day holdout challenges. Historical study
targets are sensitivity anchors, not universal SOC standards.

The [dated protocol](docs/remediation_protocol_20260905.md) was recorded before
the new outcome calculations. Earlier dataset results were already known, so
this is a retrospective corrective re-evaluation, not an externally independent
confirmation or a claim of retrospective preregistration.

## Reproduce

The recorded execution environment is Python 3.11.4 with the pinned packages in
`requirements-lock.txt`. Use an isolated local environment. No API key is needed.

```sh
python -m venv .venv
# Activate the environment for your operating system.
python -m pip install -r requirements-lock.txt
python -m unittest discover -s tests -v
python scripts/run_corrective_evaluation.py --synthetic --output outputs/synthetic_check
```

Obtain CICIDS2017 MachineLearningCSV files from the
[original UNB dataset source](https://www.unb.ca/cic/datasets/ids-2017.html).
Place the eight files named in `config/cicids2017_full_candidate.toml` under
`data/raw/cicids2017/`. The data are not redistributed here. Then run:

```sh
python scripts/run_corrective_evaluation.py --output outputs/corrective_reproduction
```

Output folders must not already exist. The run saves per-condition split
assignments, training medians, development threshold curves, locked selection
records, test predictions, validation records, aggregate metrics and hashes.
These row-level outputs stay local and are ignored by Git. The same protocol
can be run on Windows or another supported Python host; latency is host-specific.
Fit and inference times are separate from serial enrichment-plus-Z3 timing.

## Historical path

`scripts/run_experiment.py` preserves the original pipeline for traceability.
That path used a random record split and pre-split imputation and is not the
corrected evaluation. Its optional hosted enrichment is not required or used in
this repository's reproduction commands. The new experiment does not replace
the recorded historical primary result or merge in the five-alert hosted
diagnostic.

## Evidence and limits

The completed September 5, 2026 corrective run evaluated 400,000 sampled rows
under six prewritten conditions. The initial source/protocol commit preceded
the run. [Aggregate evidence](evidence/20260905/results.json),
[independent reconciliation](evidence/20260905/corrective_verification.json),
and an [executed audit notebook](notebooks/review_corrective_evidence.ipynb)
are included. The notebook uses only standard-library computations and public
aggregates; its execution is not a second full model fit.

The group-separated test set contained 120,059 records, including 23,603
malicious records. All counts below use the same 0.15 reference queue.

| Policy | False positives removed | True positives removed | Recall change (percentage points) |
| --- | ---: | ---: | ---: |
| Symbolic filter | 117 | 795 | -3.368 |
| Development-selected score filter (0.21) | 110 | 11 | -0.047 |
| Development-selected detector (0.16) | 17 | 1 | -0.004 |
| Selected detector plus symbolic filter | 121 | 796 | -3.372 |

Symbolic false-positive reduction was 31.200%, but its Wilson 95% interval
was 26.721%-36.060%, crossing the historical 30% target. The score-only filter
removed seven fewer false positives and 784 fewer true positives: this is not
strict dominance on both counts, but it exposes the symbolic recall cost.
Under equal FP/FN count costs the symbolic policy's net benefit is -678.
Historical criteria are not operational safety tolerances.

Day-held-out baseline/symbolic recalls were: Tuesday 39.072%/19.536%, Wednesday
24.593%/6.983%, Thursday 84.296%/1.489%, and Friday 31.106%/30.956%. Monday has
no malicious examples, so recall is undefined. These separately trained models
face previously unseen attack labels; do not pool their outputs as independent
replications or describe this as forward-time deployment testing.

The group-split mean serial local enrichment-plus-Z3 latency was 3.552 ms.
Five warmed 1,000-alert passes had means of 3.079-4.048 ms. The manifest records
the Intel i7-9750H host, approximately 15.88 GiB RAM, software, source hashes,
input hashes, and output hashes. This is new timing evidence, not a recovery
of the unrecorded historical hardware environment.

All six conditions independently reconciled counts, training-only medians,
development-only selection, and zero raw/transformed exact-feature overlap
between partitions. The complete raw artifacts remain local. The public
manifest lists their hashes but a public aggregate check cannot independently
recount unavailable row-level records; full reproduction regenerates them.

To verify this published package without obtaining the dataset:

```sh
python scripts/verify_published_evidence.py
```

The [version 1.0.0 source](https://github.com/troncook/soc-alert-validation-reproducibility/tree/v1.0.0)
is the citation target. Source hashes identify the actual bytes because the
experiment was executed from a dirty private worktree; the private commit ID
alone does not identify the evaluated implementation.

Exact-feature separation does not guarantee independence of related traffic.
Capture days contain different attacks; leave-day-out evaluation is not a
forward-time deployment simulation. Original dataset-label defects remain a
limitation. A passing aggregate recall margin does not establish safe alert
suppression. The source and hypotheses may yield negative results.

## Publication boundaries

This is a clean source snapshot, not the private manuscript repository or its
history. It contains no manuscript, advisor comments, credentials, raw dataset
rows, trained-model pickle or hosted response payloads. No software license has
been selected; public visibility should not be described as an open-source
license grant. GitHub commits and tags provide version identifiers, not a
permanent DOI archive.

Code and analysis preparation used AI assistance under student review. The
student remains responsible for understanding, checking and explaining the
methods and any submitted academic claims.
