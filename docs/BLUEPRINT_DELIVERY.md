# Blueprint delivery checkpoint — 2026-09-30

This is a local, fixture-verified engineering checkpoint, **not completion of the blueprint, a 9/10 release, or Maltego parity**. No commit, push, hosted migration, provider query, active probe, or deployment was performed.

## Evaluated baseline

- Repository: `shivammittal2403/TraceAtlas-Automator`; local branch `codex/blueprint-delivery`.
- Base HEAD / remote main at clone: `97e92175a89a6877f3c2da9b7d3490d919ea1566`, version 1.8.0.
- Initial checkout was clean. There was no repository AGENTS.md.
- The earlier downloaded v1.3.0 ZIP is not this baseline. Its edits were not blindly applied.
- Blueprint historical SHA `e4729f3875285e7a5bdf0fca793fc54c6cb39801` is absent from the cloned object database and remains unverified.
- Windows, Python 3.12.14, Node 24.19.0, pnpm 11.19.0. Baseline: 167 Python tests, 165 passed, two Windows harness errors (Bash absent; executable Python shebang fixture).

## Implemented and fixture verified

1. **R02/R04, B03/B12:** IP employee plans obey the four-action budget before approval. IPv6 omits unsupported local connector families. HTTP probe reserves an action. Omissions are included in the hashed approval plan. Browser parsing rejects malformed/private/special-purpose IP literals. This does not broaden active-test authority.
2. **R01/R03/R04, B06/B10/B11:** Hosted job keys are organisation + case scoped; identical retries return the same job, changed bodies conflict. Replays bypass new-admission counters and duplicate audit writes. Transaction advisory locks serialize admission counters. Hosted review decisions use immutable task ID as operation key and permit only same-actor/same-body replay. Local employee approval replay does not renew expiry. Browser retries retain the same job key after an uncertain response within the page session.
3. **R02/R04/R09, B12:** Shared HTTPS transport pins a validated public DNS address, verifies TLS for the original allowlisted provider, ignores environment proxies, rejects redirects/compression/non-JSON responses, and caps bytes and elapsed time. Retry attempts share one deadline. Source-specific destination manifests are checked. Missing credentials persist `failure_code=not_configured`, without fallback. Four IP connectors reject wrong-target responses before storing findings. Skipped-only batch runs are partial, not successful.
4. **R05/R12, B07/B19:** InternetDB has a versioned evidence envelope linking response digest, source run, normalized evidence hashes, case, retrieval time, connector version and limitations. Raw response is not retained. Evidence verification checks actual files as well as ledger hashes; missing/malformed/tampered data fails. Portable ZIP export carries SHA-256 manifest and rejects tampering and overwrite. Identical content is indexed independently per local case; legacy SQLite evidence metadata is transactionally migrated with `evidence_legacy_v1` retained.
5. **R01/R09, B06:** All eight SQL migrations execute on PGlite PostgreSQL with pgcrypto. Two synthetic tenant identities, a viewer, and anon exercise RLS/RPC denial, replay, conflict and saturated admission. This is **one PostgreSQL session with an auth shim**, not Supabase Auth/JWT/storage or concurrency validation.

## Reproducible verification

```text
pnpm install --frozen-lockfile --ignore-scripts
python -m unittest discover -s tests -q              # PYTHONPATH=src
node --test tests/test_graph_model.cjs tests/test_target_validation.cjs
node --test tests/test_database.mjs
node node_modules/playwright/cli.js install chromium
node tests/test_employee_ui.cjs
python scripts/verify_delivery.py --output <new-evidence-directory> --browser
```

Set `PYTHON` to the real Python executable for Node/Python interoperability tests. `PLAYWRIGHT_BROWSERS_PATH` may point to a workspace-local browser cache. The verification script sets PYTHONPATH and PYTHON for its subprocesses and refuses to overwrite a prior evidence directory.

Observed checkpoint results: 178 Python tests run, 177 passed, one explicitly skipped because Bash is unavailable; 25 JavaScript tests passed; database regression scenario passed; Chromium fixture flow passed (uncertain job response retry, IP validation, brief, untrusted text, review, case switching, logout). Source compilation and secret scan passed. Existing AI contract benchmark passed 8/8; this is not factual-accuracy or held-out model evaluation. Nonempty local SQLite restore and synthetic evidence bundle verification passed. Linux CI was extended but **not run remotely**.

## Migration and compatibility notes

- SQL files were generated with Supabase CLI 2.118.0, then edited; never applied to a hosted project. Review sequential and multi-session behaviour in isolated staging before rollout. Hosted advisors were not run.
- `20260929172809_case_bound_job_replay.sql` changes the job uniqueness boundary and RPC/trigger logic. No job rows are removed. Downgrading to org-only keys can fail after the same key is used in different cases: do not drop data to force a downgrade.
- `20260929173702_review_decision_replay.sql` preserves RPC signature, role grants and explicit search path; conflicting repeated decisions return SQLSTATE 23505.
- Local SQLite upgrade preserves a metadata snapshot named `evidence_legacy_v1`; evidence payload files are untouched. Back up an existing workspace before applying to a real case archive. The snapshot is not kept current after migration and is not a full database backup.
- Existing CLI/source IDs and normalized evidence JSON are retained. New commands: `evidence-export --case CASE --output BUNDLE.zip` and `evidence-verify BUNDLE.zip`.
- The browser IP validator is deliberately conservative; backend validation remains authoritative. InternetDB integration is IPv4-only pending IPv6 qualification; this is a local contract, not a claim about every provider capability.
- **Redirect-dependent providers, especially the existing RDAP bootstrap URL, now fail closed with `provider_redirect_rejected`.** A vetted registry/bootstrap destination policy is still required before graduating RDAP. Providers requiring compressed responses likewise need a separately bounded decompression policy. No live compatibility claim is made.
- Export hashes are not digital signatures or independent proof of origin. Full-history deletion/rewrite needs a separately anchored ledger head. Local evidence envelopes do not supply hosted tenant/actor attestation or retention policy. Export memory is bounded to a 120 MiB payload budget.
- Browser retry keys survive an uncertain response only within the current page; reload-safe request reconciliation remains pending.
- PGlite 0.5.8 and Playwright 1.62.1 are pinned Apache-2.0 development dependencies; PGlite includes PostgreSQL components under their upstream licensing. Dependency payloads/browser binaries are not included in the source archive. Provider license/entitlement approval remains separate.

## Remaining acceptance failures (not hidden by fixture passes)

M0: approved five golden cases, provider licenses/entitlements and historical-baseline verification outstanding.

M1: complete tenant/case/actor/scope/policy evidence contract, hosted RLS/JWT/storage denial, case-role and retention enforcement still need end-to-end proof.

M2: fenced worker commits, atomic worker evidence/graph/review transaction, outbox, checkpoint/resume, cancellation propagation, budget reservations and unknown-charge reconciliation remain incomplete. Advisory-lock concurrency has not been exercised with multiple PostgreSQL sessions. Existing worker writes can be partially committed; do not call the queue exactly-once.

M3: zero newly live-verified release connectors. Eight justified entitled connectors plus approved targets/caps and provider failure evidence are required. Per-provider wrong-target checks beyond the four IP connectors remain pending.

M4: existing graph features passed regression fixtures, but complete golden workflows, reversible resolution, hosted evidence inspector/export integration and measured graph scale are not accepted.

M5: held-out, independently reviewed factual/citation/abstention evaluation and media acceptance remain pending. The 8-case contract test does not establish AI quality or unsupported-attribution safety across the release.

M6: load/concurrent failure tests, hosted restore, security review, measured 14-day pilot, three-analyst matched benchmark and release approval remain outstanding. Scores remain null; hard gates are false.

Next dependency: identify the isolated staging project and approved target/entitlement set, while continuing the uncompleted local worker/evidence reliability work. Production changes still require separate authorization. This checkpoint does not promise unattended future work.

## Primary references consulted

- [Supabase database testing](https://supabase.com/docs/guides/database/testing)
- [PostgreSQL INSERT/ON CONFLICT behaviour](https://www.postgresql.org/docs/current/sql-insert.html)
- [PGlite supported extensions](https://pglite.dev/extensions/)
- [InternetDB OpenAPI](https://internetdb.shodan.io/openapi.json)
- [GreyNoise Community API](https://docs.greynoise.io/reference/getcommunityip)

Supabase/Postgres skills guided migration generation and database-executed isolation checks. Browser-verification skills guided the local visual and synthetic flow checks; neither converts fixtures into live proof.
