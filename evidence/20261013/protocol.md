# Corrected local timing protocol October 13 2026

## Purpose and fixed scope

The student explicitly requested the missing timing check for the corrected
validation policy. This is a local timing diagnostic supporting the narrow H3
serial-processing criterion. It does not replace June primary or September
corrective evidence and does not run training, hosted services or new thresholds.
The existing paper is preserved. Target policy: October
`combined_web_brute_and_scan` on September `duplicate_group_split` predictions.

## Plan

1. Preserve source, manuscript, configuration and experiment hashes. Use the
   existing research virtual environment. Reconstruct the exact raw records and
   full dictionary shape used in the prior local timing path, with frozen
   predictions; verify source receipts, row identities and feature fingerprints.
2. Create an isolated timing implementation derived from the existing validator.
   Change only predicted web-brute coverage and the retired scan branch; retain
   the mock enrichment and all seven fact bindings in the solver. Compare code
   and synthetic boundary results before real timing. Run the required mock
   synthetic smoke with its output redirected to this diagnostic directory.
3. Time fresh mock enrichment plus corrected validation for all 23,939 eligible
   alerts once. Use perf_counter_ns component clocks, serial execution, normal
   process priority, no parallel benchmarks and no dataset/model/I/O work inside
   the measured span. Run 25 untimed warmups; retain the first timed alert and all
   outliers. No latency-based exclusions, selective reruns or result trimming.
4. Sample the same 1,000 eligible records using pandas sample with seed 42, as
   in the prior protocol. After 25 untimed warmups per policy, run five paired
   original/corrected serial passes, alternating which policy runs first. Keep
   input order fixed. The repeats assess run variability, not independent traffic
   samples or a causal speed comparison with September.
5. Recount every decision and component duration independently. Record full and
   repeat mean, median, P95, maximum and policy-specific SMT counts. Compare the
   full corrected mean strictly against one second. Complete the provenance
   template and save raw timings, identities, hashes, environment and scope.

## Measurement boundary

Includes fresh deterministic enrichment, normal per-record fact normalization,
corrected rule decisions, applicable Z3 construction/checks and returned
in-memory validation record. Excludes loading/reconstructing the dataset,
detector training/inference, prebuilt-record conversion, output serialization,
disk/network I/O and hosted language-model calls. Solver checks remain mirrored
instrumentation, not independent attack adjudication. Uncovered alerts return
inconclusive with SMT not_applicable. No obsolete solver work is charged to a
rule after the coverage guard.

The corrected validator is an isolated benchmark adapter, not a change to the
historical pipeline or a claim that an operational application was deployed.
The same saved records must reproduce the selected corrected policy exactly.
Neither fresh timing nor the repeat results change H1/H2 or establish throughput,
production capacity, hosted end-to-end latency or safe alert suppression.

## Acceptance checks fixed before execution

- All eight dataset receipts and all test identities/fingerprints match.
- All 23,939 baseline-alert identities appear once in the full pass; no errors.
- Every candidate, corrected disposition and underlying rule matches retained
  replay evidence; original policy reproduces saved outcomes in untimed checks.
- Corrected counts: 22,693 supported, 407 unsupported, 839 inconclusive;
  82 benign and 325 malicious records removed. Web guard: 505 alerts.
- Exactly 23,100 applicable SMT checks: 22,693 sat and 407 unsat;
  839 not_applicable, with zero predicate/SMT disagreements.
- The seven original SMT fact equalities remain present for the scan rule;
  only its retired branch is removed. Synthetic SYN=3 verifies that removal.
- Total elapsed nanoseconds equal enrichment plus validation nanoseconds for
  every record; aggregate summaries reconcile with raw rows.
- Five repeats per policy contain the same 1,000 declared sample identities.
- All protected inputs remain unchanged. Report failures and timing variability
  honestly; do not rerun to obtain a more favorable number.

## Interpretation

The threshold is the study's existing mean < 1.0 second. An observed pass
supports serial local feasibility of this instrumented corrected implementation
on the declared workload and current machine. The repeated sample is descriptive;
no independent traffic-level confidence interval or performance speedup is claimed.
