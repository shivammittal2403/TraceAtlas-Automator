# Dedicated discipline employees

The new employee runtime executes discipline-specific Python analyzers over
supplied records. The catalog separately reports the requested 140 labels and
the implemented count. An unimplemented label cannot execute or acquire an
employee definition. This is separate from the older native-module route catalog.

Install Python 3.10 or newer, then run:

~~~console
python -m pip install .
traceatlas-employees catalog
traceatlas-employees analyze DNSINT --input examples/employees/dns.json --output dns-review.json
~~~

The analyze command returns a deterministic, evidence-linked draft. It makes
zero network or model calls. Existing live collectors and model providers remain
separate capabilities; their configuration does not prove a live integration.

## Input contract

Every input supplies case_id, task_id (standalone only), discipline, objective,
as_of (ISO timestamp with timezone), sources and records. Optional parameters
must be an object. Sources have unique source_id and HTTP(S)/URN uri. Optional
original_source_id/publisher_id metadata identifies asserted upstream groups.
Records have unique record_id, registered source_id, data object and optional
observed_at timestamp. The example is synthetic and should not become case evidence.

Handlers reject malformed data or return explicit issues and unknowns. Empty input
returns INSUFFICIENT_DATA. Findings cite record IDs and submitted source IDs.
These IDs are not independently acquired evidence, verified identity or truth.
The standalone contract limits JSON to 2 MiB, 500 entries per collection, depth 20,
262144 characters per text value, 500 findings and 500 issues.

## Canonical employee workflow

Use a real, authorized supplied-record case. Persistent operations use the
existing workforce feature flag: TRACEATLAS_WORKFORCE_ENABLED=1. A task binds the
case, employee definition, exact input bytes, analyzer source identity, deadline,
budget and canonical evidence artifact. Changed bytes or source invalidate execution.

~~~console
traceatlas-employees --workspace .traceatlas case --case my-case --title "My review" --purpose "Supplied-record analysis"
traceatlas-employees --workspace .traceatlas authorize --case my-case --actor analyst --purpose "Review submitted records" --jurisdiction IN --authorized
traceatlas-employees --workspace .traceatlas plan DNSINT --context AUTH_ID --input case-records.json
traceatlas-employees --workspace .traceatlas approve --task TASK_ID --actor analyst --envelope-digest RETURNED_DIGEST --rationale "Approve these exact records" --authorized
traceatlas-employees --workspace .traceatlas run --task TASK_ID --authorized
~~~

Persistent input omits task_id; the lifecycle assigns it. The case must match its
authorization context. The canonical SourceDocument transport limits preserved
content to 512 KiB, smaller than standalone analysis. The manager command plans
assignments; each child task is planned and approved separately. Cancellation,
kill switch, budget, expiring leases, retry recovery, atomic results and outbox
are enforced by the existing workforce lifecycle. Results remain drafts for review.

The tests exercise nonempty discipline semantics and adversarial inputs, plus
canonical custody, actual DNS lifecycle, tampering, cancellation, expired leases,
rollback and idempotency. GitHub Actions runs them on Windows/Linux, Python3.10/3.12.
Local execution is not a claimed validation when the attached process runner is unavailable.

Radio, person, credentials, malware and industrial handlers analyze supplied
records statically. No interception, subject contact, code execution, credential
use or industrial control operation is part of these analyzers.

## Optional AI review

After standalone analysis, a configured local Ollama model can draft interpretations
and review questions: `traceatlas-employees reason --input dns-review.json --model YOUR_LOCAL_MODEL --authorized`.
This uses the existing provider router, limits context to100 supplied finding summaries,
validates cited finding IDs and keeps model prose separate from deterministic evidence.
Unavailable models return MODEL_UNAVAILABLE and preserve the deterministic draft.
Attempt counts include failed requests. Fixture transport tests do not establish that
a local model is installed or that live generation has been verified on this machine.

## Team coordinator

`traceatlas-employees team --input examples/employees/team.json --output team-review.json`
runs explicit discipline assignments under one case. Each assignment supplies its own
records and optional parameters. Child task IDs are deterministic, evidence IDs
cannot change meaning between disciplines, and empty/invalid work remains visible
as a gap. Team agreement is not independent corroboration. Persistent employee
tasks continue through the approved canonical runtime described above.

Derived output is bounded as well as input: large data arrays, artifact fields
or findings can be omitted with explicit output_budget counts and PARTIAL status.
Every retained finding keeps its complete canonical record/source references.
Source identity binds the full processor set and Python version, including shared
measurement, temporal and graph dependencies.
