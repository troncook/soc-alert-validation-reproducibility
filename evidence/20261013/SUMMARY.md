# October 13 corrected local timing

`results.json` is an exact copy of the saved aggregate timing output. The full
corrected pass covers all 23,939 frozen alerts after 25 untimed warmups. Its mean
is 2.336484894941309 ms, median 2.0981 ms, P95 4.26322 ms and maximum
51.3031 ms. Mean enrichment and validation components add to the total mean.
Every corrected decision matches: 82 benign and 325 malicious alerts removed;
22,693 supported, 407 unsupported and 839 inconclusive. Applicable solver checks
are 22,693 sat and 407 unsat; the 839 inconclusive records are not_applicable.

Five passes per policy reuse one fixed 1,000-alert seed-42 sample in the same
order, with 25 warmups per policy before that series and alternating policy order.
The five corrected means range from 2.0860877 to 2.2666169 ms. They describe
repeat variability, not independent samples or a confidence interval.

The measured span includes fresh mock enrichment, ordinary fact normalization,
corrected rule dispatch, applicable SMT construction and solve, and the returned
in-memory record. It excludes loading/reconstruction, training/inference, input
dictionary construction, serialization/disk I/O and network/hosted calls.
The run used one serial process at normal priority on the recorded workstation,
with uncontrolled background load. The pre-execution protocol and sanitized
environment are included.

The observed warmed local mean is below the study's one-second H3 criterion.
This is neither a causal speedup nor concurrent throughput, hosted end-to-end
latency, operational safety or a production guarantee. Timing varies by machine
and workload. The original September timing remains historical evidence.

`independent_checks.json` records the prior independent arithmetic and hash review
of 33,939 saved timing rows (23,939 full plus 10,000 repeat rows), not a benchmark
rerun or independent external replication. It reports 66 checks and no issues.
The public export omits per-alert timings, workload identities, raw data, private
Git state and the executable's absolute path. The source manifest hash and
logical provenance locators preserve the relation to retained originals.
