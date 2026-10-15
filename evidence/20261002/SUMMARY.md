# October 2 validation-only replay

These saved aggregates cover the September exact-feature-group split, five
capture-day holdouts and the separate historical June condition. Each condition
contains seven policy comparisons. The selected current policy is
`combined_web_brute_and_scan` in `duplicate_group_split/results.json`.

That policy removes 82 false positives and 325 true positives from the frozen
reference queue of 23,939 alerts (375 false positives and 23,564 true positives).
The original rules removed 117 and 795. The web-brute coverage correction retains
505 previously unsupported alerts: 35 benign and 470 malicious. Retiring the
unreachable SYN > 2 scan branch changes zero decisions in every condition.
Missing-fact and broader-web alternatives remain separate sensitivities.

The false-positive reduction is 21.8667%, so H1's 30% target is not met. Recall
falls from 23,564/23,603 to 23,239/23,603: a loss of 1.37694360886328 percentage
points. The saved 95% exact-feature-group bootstrap loss interval is
1.2260476945691765–1.550474984367058 points (1,000 draws, seed 42,
114,073 groups). Its upper endpoint is below H2's five-point margin. These groups
do not resolve all dependence among related flows; this is not an external-SOC
or corrected capture-day interval and does not establish safe suppression.

The development-locked score cutoff of 0.21 removes 110 false positives and
11 true positives in the preserved September evidence. It removes 28 more false
positives and 314 fewer true positives than the selected corrected policy.
This superiority applies to the corrected comparison; it must not be described
as strict dominance over the original 117/795 pair.

This is a retrospective policy replay on frozen predictions, with no detector
retraining or threshold selection. It has no new H3 timing result. The separate
October 13 timing evidence is under `../20261013/`.

`independent_checks.json` records a prior saved-output recount and boundary
review, including its unverified scope; it is not independent external
replication. The public files omit all per-alert records and data. Manifest
logical locators and original hashes identify preserved source artifacts without
publishing private paths. Numeric aggregate results are copied byte for byte.
