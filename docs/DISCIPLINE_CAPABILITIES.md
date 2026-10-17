# Native discipline capability mapping

The additive capability catalog uses the repository's registered native Python
handlers and the ten groups in `traceatlas.osint_taxonomy`. It covers 139
disciplines plus the OSINT umbrella. The eleven Python implementation families
are file organization, and do not replace the ten domain groups.

Run `traceatlas-employees capabilities` to obtain the machine-readable
`traceatlas.discipline.capabilities.v1` report. Existing `catalog` and legacy
taxonomy commands retain their contracts.

Each row identifies the registered handler's underlying module, function,
source line, source hash and complete engine identity. Dispatch must continue
through `registered_handlers()[discipline]`. Module/function fields are source
metadata, not an executable user-selected import path. Economic handlers use
registered precision wrappers; importing the underlying function directly can
bypass that behavior.

`static_output_contract` extracts literal metric, artifact, finding and issue
names from trusted native source AST and its context helpers. Extraction never
evaluates the handler. The names are possible, nonexhaustive outputs. Dynamic
keys, data-dependent branches and semantic correctness cannot be established by
this inspection. Existing docstrings are preserved; missing docstrings remain
explicitly missing rather than receiving guessed algorithm descriptions.

Native recipes are identified by path and SHA-256. When repository assets are
available, their identity, nonempty records and shared input contract are
validated without running the analyzer. Recipes remain synthetic fixtures.
Installed distributions without repository examples or tests report their
absence and null hashes; they do not invent successful validation. The skill
reference uses the installed, metadata-validated Markdown procedure and hash,
and grants no source authority.

Semantic test references distinguish explicit test methods from the dynamically
generated positive/adversarial cases for software, economic, social and fraud
handlers. References describe source definitions only. Every test execution
receipt is null in this catalog; CI receipts and live source qualification remain
separate evidence. File or fixture presence cannot establish passing tests.

The native execution mode is supplied-record analysis with zero external or
model calls. Legacy routes are reported separately. The 135 legacy module
entries contain 68 supplied-record, 53 planning and 14 unconfigured modes.
Routing 140 labels onto those existing backends yields 53 supplied-record,
72 planning and 15 unconfigured label routes. These are different denominators.
For example, native DNSINT performs supplied typed-record analysis even though
its legacy route is planning only.

Record and source references remain supplied assertions. Approved canonical
tasks can link them to the preserved input artifact; this is not independent
source acquisition or factual verification. The catalog records the coded
HYPOTHESISINT canonical projection and FALSIFICATIONINT protocol sidecar.
FALSIFICATIONINT does not invent a missing proposition, and no catalog row
claims that a hypothesis, source or live provider has been verified.

The external 139-discipline catalog and master prompt have not been read or
compared. `external_specification_status` remains `UNREAD`, and
`minimum_requirements_met` remains null. This repository-native mapping is not a
declaration of compliance with unseen requirements.

## Group accessors

`domain_groups()` returns an ordered tuple of dictionaries with integer
`group_id`, string `group_name`, and tuple `disciplines`.
`discipline_group(label)` normalizes a known label and returns its group ID/name;
unknown or non-string labels fail. These accessors perform no collection and
grant no employee or team-lead authority.
