# Engineering checklist and enterprise acceptance

`traceatlas maturity` inventories implementation signals and locally revalidated
integration evidence. It does not assign an enterprise maturity score.

## Output contract

JSON schema `traceatlas-engineering-checklist/v2` separates:

- `checklist`: passed checks, total checks, and completion percentage. Static file
  markers, installed tools, and synthetic guardrail tests are engineering signals.
- `dimensions`: each area's `passed_checks`, `total_checks`, and individual gates.
- `enterprise_assessment`: `NOT_ESTABLISHED`, `score: null`, `accepted: false`,
  target 8, and outstanding acceptance evidence categories.
- `evidence_context`: coded contracts, diagnostic health rows, revalidated local
  integration sources, stored run history, and static deployment configuration.

Legacy `overall` and `maximum` are null. `ten_of_ten` is false. Clients consuming
the previous numeric score must migrate to `checklist` for implementation counts
and `enterprise_assessment` for readiness. Do not convert checklist percentage
into an enterprise score. Dimension `score`/`maximum` fields have been replaced.

## What qualifies as a local integration

Counts use `IntegrationReceipts.verified()` against current implementation hashes,
recent non-fixture/non-cache executions, normalized same-case evidence and custody.
An outdated code digest, fixture response, altered execution or unresolved artifact
cannot count. This proves only a bounded lookup in the recorded local runtime.
It does not establish source rights, independent source authenticity, production
qualification, sustained availability, or representative investigative accuracy.

Generic connector and integration health rows cannot prove those properties.
MISP/model operational gates without adequate receipts remain unverified. Static
deployment configuration cannot satisfy hosted tenant, recovery, or UX verification.
The command does not perform live requests or deploy an environment.

## Regression evidence

On baseline `ca86a44`, injecting healthy rows and a passing static deployment
response changed the reported score from 6.8 to 8.8 and claimed 51 verified live
sources, without a live request. The repaired output leaves engineering checks at
41/60 and local revalidated integrations at zero; enterprise acceptance remains
unestablished. These numbers are a controlled regression demonstration only.
See [the recorded comparison](verification/maturity-output-2026-10-05.json).

Enterprise acceptance still requires representative independently reviewed results,
qualified source/runtime evidence, independent custody anchoring, hosted security
and recovery/SLO evidence, and authorized review of the defined acceptance gates.
