# Changelog

## 1.1.0 — 2026-10-15

- Add the October 2 retrospective policy correction on frozen predictions:
  retain predicted web brute force as inconclusive and retire the impossible
  scan branch. The selected group-split correction removes 82 FP and 325 TP;
  the unchanged score comparator removes 110 FP and 11 TP. No detector was
  retrained or threshold reselected for the recorded October replay.
- Report H1's 21.867% FP reduction as below target and H2's 1.3769-point recall
  loss with a 95% exact-feature-group interval of 1.2260–1.5505 points as a
  conditional margin result, with the remaining recall cost explicit.
- Add the separate October 13 corrected local timing diagnostic: 2.336 ms mean
  across 23,939 alerts after 25 warmups, with fixed-sample repeat means of
  2.086–2.267 ms. This is local enrichment-plus-validation timing only.
- Add sanitized aggregate evidence, public hash/arithmetic verification and
  portable group-split replay/timing commands with focused tests. The portable
  runner does not regenerate every archived auxiliary sensitivity condition.
- Update reproduction guidance and citation metadata. Preserve the v1.0.0 tag,
  September evidence, protocol, original code and audit notebook. No private
  manuscript, raw dataset or row-level result is included.

## 1.0.0 — 2026-09-05

- Publish the September corrective evaluation with training-only imputation,
  exact-feature-group separation, development-locked selection and five
  capture-day holdouts, using the existing capped sample and model family.
- Publish source, pinned dependencies, protocol, aggregate evidence and an
  executed aggregate-audit notebook.
- Record the original group-split symbolic policy's 117 FP / 795 TP removals
  and 3.552 ms local mean as historical results. These remain preserved;
  version 1.1.0 supplies the later corrected-policy evidence.
