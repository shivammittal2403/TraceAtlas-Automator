# Evaluation results

Updated: 2026-10-04. Results below are freshly observed in this checkout unless
marked historical. Environment failures are not reported as code passes.

| Evaluation | Result | Scope and limitation |
|---|---|---|
| Python `unittest discover -s tests -q` | 317 run; 311 passed; 3 skipped; 3 failed (2 errors, 1 failure) | All failures are OpenCTI submodule prerequisite: files unavailable and vendor count 72 vs expected 308. Seven new ER evaluation tests and one resolution regression pass. |
| Node graph/target suite | 25/25 passed | Set `PYTHON` to the bundled Python executable so Node could spawn Python; tests are local synthetic cases. |
| PGlite database/RLS | 1/1 passed | Installed exact project dev dependencies with `pnpm install --frozen-lockfile`; local disposable PGlite/Auth-shim gate only. |
| Python source compilation | Passed | `compileall -q src`. |
| Secret scan | Passed, clean | `scripts/check_secrets.py`. |
| `git diff --check` | Passed at baseline | Baseline had no tracked program changes yet. |
| Employee UI workflow | Passed | `tests/test_employee_ui.cjs`; local workflow check only, not hosted UX acceptance. |
| Live source tests | None | No provider credentials or intended-runtime deployment available. |

## Entity-resolution baseline

The existing ranker uses weighted Jaro-Winkler similarities over name,
organization, domain, username and location. It returns a candidate class and a
score described as a heuristic, always requires analyst review and never merges
automatically. Existing G10 only checks a synthetic identifier conflict; it
does not measure population-level precision/recall or false-merge rate.

The first evaluation slice is synthetic and must not be presented as operational
accuracy. The existing 0.72 `possible_candidate` score boundary was retained and
not tuned on this set. Six queries contain 24 labeled pairs (4 positive, 20
negative). Results: TP=4, FP=1, TN=19, FN=0; precision=.80, recall=1.00,
F1=.889, false-positive rate=.05; ranking recall@1=1.00 and @3=1.00 across the
four positive queries. The false positive is the synthetic same-name Meridian
company candidate (score .7258), with differing organization, domain, username
and location. Output now makes exact-agreement/differing fields explicit. It
remains a review candidate, not a merge. Saved result:
[`entity-resolution-synthetic-2026-10-04.json`](../verification/entity-resolution-synthetic-2026-10-04.json).

False-merge rate stays undefined while the automated-merge count denominator is
zero. No representative authorized adjudicated set exists; operational
precision/recall, calibration, candidate-generation recall and false merge/split
rates are still unknown.

No market-parity, 8/10 weighted maturity or production-readiness score is
currently supportable.
