# Verification gates

Run the full Python unittest suite with the pinned OpenCTI submodule,
compile sources, scan secrets and validate shell/JavaScript syntax. Existing graph
and target Node tests, PGlite migration/RLS regressions and Playwright synthetic
analyst flow remain regression gates. CI also builds package/SBOM/worker images
and runs CodeQL; local runs do not substitute for remote gate results.

New tests cover complete product/replay, idempotent completion, independent versus
circular assertions, conflicting/historical/multivalue facts, injection, unknown
schemas, wrong subjects, expired authority, dynamic kill switch, forged metadata,
acquisition mismatch, tamper, provider target mismatch, attempt budget, tool
secrets and exact capability selection. G01–G12 exercise the whole controlled
pipeline. See IMPLEMENTATION_REPORT.md for actual results.
