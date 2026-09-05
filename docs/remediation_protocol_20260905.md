# Corrected evaluation and reproducibility protocol

Date: September 5, 2026. Purpose: respond to professor comments 2, 3, 11, 16,
19 and 21 within the existing CICIDS2017 symbolic-validation experiment.

## Authority and scope

The student authorized corrective experiments and a public GitHub reproducibility
repository. This protocol is recorded before the new outcome calculations. It is
not a retrospective preregistration: the dataset and earlier results have already
been examined. The new analyses are a corrective, internally validated
re-evaluation, not an independent external replication.

Preserve primary run `20260623T101437Z_cicids2017_full_candidate`, its 30% H1
target, five-percentage-point H2 margin, one-second mean H3 criterion, and all
historical artifacts. Keep the five-alert hosted diagnostic separate. No hosted
API, new dataset, new model family, new symbolic predicate, or raw-data upload is
part of this work. The manuscript input is the September 4 professor-review DOCX;
the output will be a new September 5 derivative.

## Work plan and acceptance checks

1. Trace the original choices using retained configurations, run manifests and
   Git history. Distinguish evidence of a setting from evidence of its rationale.
2. Implement the protocol below as a separate entry point reusing the existing
   sampling, deterministic enrichment and symbolic-validation functions. Verify
   synthetic cases, leakage checks, threshold isolation and metric arithmetic.
3. Run the existing capped 400,000-row sample through one duplicate-group split
   and five leave-one-capture-day-out evaluations. Report every planned fold,
   including failures, absent classes and undefined metrics.
4. Publish a clean, versioned GitHub repository with code, locked dependencies,
   protocol, aggregate results, hashes and instructions. Verify a fresh clone;
   publish neither private history/manuscripts nor dataset rows or credentials.
5. Update the manuscript, source/claim records and all six comment responses.
   Check numbers against generated evidence and render every page before handoff.

## Fixed dataset and model

Use the same eight configured CSV files, the same existing label-aware cap of
50,000 rows per file, and sampling seed 42. Preserve raw file and source-row
identities locally. Use the same 78 feature columns, 100-tree multiclass Random
Forest, balanced class weights and model seed 42. Use four parallel fit workers
to bound host load; enrichment and Z3 validation remain serial. Do not tune tree
parameters or symbolic rules. Development selection uses the same deterministic
predicates without requesting their redundant SMT mirror; every test alert uses
the original Z3 check. This reduces selection cost without altering dispositions.
Finite negative dataset artifacts remain disclosed
and unchanged; nonfinite numeric inputs become missing.

## Splitting and leakage prevention

Hash feature vectors without labels or source metadata; equal feature vectors,
including those with conflicting labels, form one group. Assign groups
deterministically using a seeded hash: approximately 50% train, 20% development,
30% test. These proportions use the existing 30% test and 20% validation settings;
the latter was configured but unused in the historical implementation. Report
actual row and class proportions rather than forcing exact row totals by
splitting duplicate groups.

For each capture-day challenge, hold out all records from that day. Assign the
remaining groups approximately 70% train and 30% development. Purge any training
or development group also present in the held-out day. Days contain different
attack families, so this is a leave-day-out distribution-shift challenge, not a
forward-time operational test. Report classes absent from training and undefined
recall when a day has no malicious records.

Learn imputation medians only from training rows; all-missing training columns
use a declared zero fallback without consulting evaluation values. Apply those
medians unchanged to development and test. Check for feature equality again
after imputation. If imputation creates cross-partition duplicates, purge the
overlap with priority test, then development, then training, refit medians and
repeat to a fixed point (maximum five passes; otherwise fail). Record removals.
This is a mechanical contamination check, not an outcome-based selection.

Verify zero raw and transformed feature overlap, disjoint row identities and
finite model matrices. Preserve same-partition duplicate multiplicity, report
unique-group metrics alongside row metrics, and do not claim that exact-duplicate
controls eliminate every possible dependency or dataset-label error.

## Locked comparisons and threshold selection

Keep 0.15 as the historical reference emission threshold. It is a comparison
setting, not an independently justified optimal threshold. On development data
only, evaluate the fixed 0.15–1.00 score grid in increments of 0.01.

Select a score-only cutoff that removes at least as many development false
positives as the unchanged symbolic policy. Among qualifying cutoffs minimize
true-positive removals, then maximize false-positive removals, then choose the
lowest cutoff. If no cutoff qualifies, report no eligible comparator; do not
consult test results or extend the grid after seeing outcomes.

Also select a detector-only operating point: the highest grid threshold retaining
the same number of development malicious records as the 0.15 reference. This
provides a documented, development-selected sensitivity-preserving alternative
without introducing another numerical recall tolerance. Freeze both choices in
a hashed selection record before reading test labels into metric calculations.

On test data report: baseline 0.15, unchanged symbolic policy, locked score-only
filter, development-selected detector threshold alone and with the unchanged
symbolic policy. The existing missing-fact and web-boundary definitions may be
reported as explicitly secondary diagnostics, never silently substituted for the
historical policy. Report all counts and family-specific recall costs.

## Study targets and decision relevance

Do not manufacture a universal or original rationale for 30% or five points.
Retain them as historical study-specific design benchmarks. Quantify target
sensitivity across FP-reduction targets 10%, 20%, 30%, 40%, 50% and recall-loss
margins 0, 0.1, 0.5, 1, 2 and 5 percentage points. Report point-estimate attainment
and uncertainty separately; do not call a point-estimate margin check a formal
non-inferiority trial or SOC safety certification.

Report the full FP-removal/TP-removal tradeoff and a transparent cost sensitivity:
net benefit = FP removed minus lambda times TP removed, for lambda 1, 5, 10, 20,
100 and 1000. Lambda is the assumed relative cost of losing one malicious alert,
not a measured SOC cost. Report the break-even ratio FP removed / TP removed
where defined, including zero-removal cases. Conclusions must not rely solely on
the selected H1/H2 margins, and the same analysis applies to the historical run.

Use Wilson intervals for FP-removal proportions, descriptive group-aware
bootstrap intervals (1,000 draws, fixed seed) for FP reduction and recall change,
and paired count differences. Do not manufacture independence from a large row
count. Leave-day-out results are descriptive with only five capture days and
different training models; do not pool them as a single independent test set.

## Latency and provenance

Time the original local enrichment plus unchanged Python/Z3 validation serially
on every emitted test alert. Exclude model fitting and prediction from the added
validation-latency measurement and report their elapsed times separately. Record
mean, median, p95, maximum and stage timing. Repeat a deterministic random sample
of up to 1,000 reference test alerts five times after a separately reported
25-alert warm-up, retaining each pass summary. Record OS, CPU model, physical
RAM, logical cores, exact package versions, source/config/schema/rule hashes,
seed, run times, input hashes, dirty-tree source receipts and output hashes.

New latency is a new measurement; it cannot backfill missing historical CPU/RAM.
Require Z3 to be installed and verify every covered result agrees with its
deterministic disposition. Save only aggregate provenance publicly; local row
artifacts remain untracked.

## Interpretation and publication gates

Results may strengthen or weaken the claims. Neither the protocol nor publication
requires a favorable result. Preserve failed/negative conditions and report which
concerns are corrected experimentally versus retained as bounded historical
limitations. Professor acceptance and institutional submission approval remain
separate from completing this response.

Publish an allowlisted source snapshot in a separate public repository under the
authenticated student account, retaining the existing private repository. Do not
select a legal license or release private manuscript text by implication. Use
immutable commit/tag URLs for reproducibility and distinguish GitHub versioning
from a permanent DOI archive.

## Method sources

- [scikit-learn preprocessing and leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage): learn transformations on training data only.
- [scikit-learn grouped evaluation guidance](https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-iterators-for-grouped-data): use disjoint groups when observations are dependent.
- [scikit-learn threshold selection](https://scikit-learn.org/stable/modules/classification_threshold.html): tune using separate validation data or suitable cross-validation.
- [UNB CICIDS2017 collection schedule](https://www.unb.ca/cic/datasets/ids-2017.html): capture days have different attack compositions.

These sources support the corrective methods, not universal values for the
dissertation's numerical margins. No new source is automatically inserted into
the manuscript bibliography without a claim-level check.
