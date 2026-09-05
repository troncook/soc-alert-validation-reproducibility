# Historical settings and present decision rationale

The 0.15 detector threshold is present in `20260524T073248Z_cicids2017_friday_ddos_sensitive_pilot`. The
30% false-positive target and five-percentage-point recall margin are present
in `20260524T073605Z_cicids2017_friday_ddos_sensitive_pilot`. Both precede the declared June 23 primary run.
The first retained Git commit occurred at 10:58:36 UTC on June 23, after the
primary run started at 10:14:37 UTC. Git alone does not establish preregistration.

These are observations from saved records. They do not establish an external SOC
standard or prove a contemporaneous independent calibration. Earlier pilot
models, rules and evaluation coverage differ, so their outcomes are not treated
as a controlled threshold-selection experiment.

The rationale now made explicit is limited: 30% is a study target representing
three tenths of the baseline false-positive count; five points is an aggregate
recall-loss tolerance used in the historical feasibility study. Neither is a
measured analyst-workload or production-risk tolerance. Keeping them preserves
the research record; it does not supply missing external validation.

The corrective response removes dependence on these arbitrary boundaries by
reporting a target/margin grid, family-specific losses, the development-locked
score comparator and a decision-cost sensitivity. On the historical sample,
119 false positives and 782 true positives were removed. Under the transparent
count-cost model, its break-even relative cost of losing a malicious alert is
119/782 = 0.152174 times the cost of retaining a false positive. For any
relative cost at least one, this policy has negative net count benefit. This is
an illustrative sensitivity, not an estimate of real incident costs.

Consequently, passing 30% and five points cannot by itself support an operational
benefit claim. The revised inference must use the comparative tradeoff and its
uncertainty. The original hypothesis decisions remain historical point-criterion
results, not a formal non-inferiority demonstration or a suppression approval.

Source receipts and every evaluated margin/cost assumption are in
`decision_audit.json`. No past record was edited.
