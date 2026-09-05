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

The initial version contains the protocol and tested source. Aggregate outcome
records will be added after the planned runs finish; an initial source commit
does not establish successful experimental completion.

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
