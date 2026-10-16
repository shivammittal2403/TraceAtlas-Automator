# TraceAtlas 139-discipline audit and repair — 2026-10-16

Audit baseline: `ff995772d8140c7f1b148a5e3edda480ab7e98b9`
(`main`, inspected through the GitHub connector). This is an incremental phase-1
repair, not completion of the 139-module implementation objective.

## Verified inventory and reuse

- 140 native supplied-record discipline processors and 140 bundled Markdown
  procedures already exist. Repository documentation identifies these as 139
  requested intelligence labels plus umbrella OSINT.
- The maintained intelligence-v1 catalog has 135 unique entrypoints:
  68 supplied-record analysis, 53 planning-only and 14 unconfigured scope checks.
  Its live-verified and hosted-verified counts are zero.
- Deterministic native employee analysis reports zero network/model calls.
  Procedures and synthetic fixtures do not qualify a source collector.
- Preserve the existing workforce, EvidenceStore, authorization, native handlers,
  CLI, case lifecycle, source transport and hosted control plane.

The external master prompt and JSON catalog named by the user could not yet be
read: the local Windows sandbox failed before shell/Node execution or workspace
writes with `helper_unknown_error: setup refresh had errors`, including after an
access grant. The user elected to restore/restart the runtime. Exact external
catalog identity and minimum-requirement reconciliation remain pending; no
unseen attachment instruction was treated as authority.

## Repairs in this branch

1. All 140 shipped guides contained an unresolved `${id}` scope label. Their
   version is now 1.0.1 and every label is concrete.
2. DNSINT told employees to use legacy `domain`/`record_type` keys while its
   actual native handler uses `name`/`type`/`value` and optional `ttl`.
   Remove legacy schema hints throughout the guides; point to each existing
   native recipe and keep native validators authoritative. Retain the remaining
   discipline-specific review instructions.
3. Reject unresolved body templates in the guide loader.
4. Reject ambiguous duplicate observation/claim/hypothesis/span IDs and unknown
   hypothesis/span evidence references in the result envelope.
5. Generic workforce completion previously accepted a fabricated evidence header
   when no product was provided. Resolve every result evidence ID against the
   task case, validate both lookup keys, object integrity, preserved bytes and
   canonical acquisition metadata, then bind observations and task traces before
   completing or writing any result/product/outbox record.

These are structural and custody checks. They do not prove semantic entailment,
source authenticity, source independence or representative investigation quality.
Invalid previously persisted envelopes fail closed; no migration deletes records.
Hashing many artifacts inside the SQLite completion transaction may increase
completion time; normal existing generators reference one to eight artifacts.

## Verification

Baseline GitHub CI run `38891877322` succeeded: Linux Python 3.10/3.12 each ran
1,044 tests with two skips. These results certify the baseline, not this branch.

New regression coverage checks unknown evidence, mismatched observation
acquisitions, foreign case/task references, changed preserved bytes, canonical
row aliases, missing/changed acquisitions, duplicate IDs, atomic rejection and
valid same-case completion. Guide checks cover all 140 installed procedures,
DNSINT native keys and unresolved-template rejection. Existing Windows/Linux
Python 3.10/3.12 discipline CI now includes the result-integrity regressions and
triggers on procedure/test edits. Full core CI and CodeQL remain required.

No local tests ran in this session. Hosted checks were pending at commit creation;
read the exact proposed head's GitHub checks and PR validation record for their
final outcome. A successful CodeQL workflow is not a clean security review:
baseline scanner findings, including retained third-party code, need triage.
No live source/model call, source promotion, deployment or production claim is
part of this repair.

## Remaining objective

- Read and hash the user's master prompt/catalog; map all 139 exact names and
  minimum requirements to implemented native behavior, tests and source modes.
- Reconcile existing native and managed140 paths without adding duplicate
  policy/evidence authorities or count-only workers.
- Complete Manager → Team Lead → Employee planning and governed dispatch.
  Native manager planning currently requires separate approval.
- Connect competing hypotheses, contradictions and falsification checks to the
  canonical lifecycle: current pipeline/discipline ResultEnvelope generators
  still emit empty hypothesis tuples. Legacy hypothesis fixtures are not proof
  of that integration.
- Implement and qualify authorized live adapters with preserved evidence,
  reproducible failures, cross-checking and truthful unavailable states.
- Finish security triage, cross-platform full-flow acceptance and controlled
  delivery only against the actual tested head. Credentials, entitlements,
  source rights and independent verification require real operator inputs.
