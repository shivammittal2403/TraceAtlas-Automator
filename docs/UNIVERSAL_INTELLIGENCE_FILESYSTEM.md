# TraceAtlas Universal Intelligence Filesystem Architecture

Status: canonical target architecture with incremental migration.  
Principle: reuse the existing evidence, workforce, source-fabric, graph, verification and employee runtime. Do not build a second platform beside them.

## 1. Permanent core

The long-lived core is:

```text
CASE
AUTHORITY
OBJECTIVE
TASK
SKILL
SOURCE
ACQUISITION
EVIDENCE
OBSERVATION
ENTITY
RELATIONSHIP
CLAIM
TIMELINE
CONTRADICTION
HYPOTHESIS
VERIFICATION
GAP
NEXT ACTION
DECISION
REPORT
REPLAY
```

Models, APIs, websites and specific OSINT tools are replaceable adapters.

## 2. Canonical repository target

```text
TraceAtlas-Automator/
├── README.md
├── Structure_file.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DATA_MODEL.md
│   ├── UNIVERSAL_INTELLIGENCE_FILESYSTEM.md
│   ├── WORKFLOW.md
│   ├── SOURCE_STRATEGY.md
│   ├── ACCEPTANCE_GATES.md
│   └── CHANGE_CONTROL.md
│
├── src/traceatlas/
│   ├── db.py
│   ├── evidence.py
│   ├── evidence_anchor.py
│   ├── policy.py
│   ├── resolution.py
│   │
│   ├── skills/                         # NEW canonical capability layer
│   │   ├── __init__.py
│   │   ├── domains.py                 # 140 intelligence domains -> 12 families
│   │   ├── contracts.py               # SkillDefinition / SkillResult
│   │   ├── registry.py                # capability lookup, never authority
│   │   ├── router.py                  # capability -> eligible skills
│   │   ├── executor.py                # governed execution facade
│   │   ├── dependency_graph.py        # skill DAG/dependency validation
│   │   ├── evaluator.py               # skill qualification
│   │   ├── health.py                  # skill health state
│   │   ├── manifests/                 # declarative skill manifests
│   │   │
│   │   ├── web_socmint/
│   │   │   ├── dorking/
│   │   │   ├── web_search/
│   │   │   ├── archives/
│   │   │   ├── news/
│   │   │   ├── social_public/
│   │   │   ├── forums/
│   │   │   ├── reputation/
│   │   │   └── narratives/
│   │   │
│   │   ├── geo_media/
│   │   │   ├── coordinates/
│   │   │   ├── maps/
│   │   │   ├── imagery/
│   │   │   ├── satellite/
│   │   │   ├── video/
│   │   │   ├── audio/
│   │   │   ├── exif/
│   │   │   ├── landmarks/
│   │   │   ├── maritime/
│   │   │   ├── aviation/
│   │   │   └── environment/
│   │   │
│   │   ├── infra_cyber/
│   │   │   ├── dns/
│   │   │   ├── rdap/
│   │   │   ├── ip/
│   │   │   ├── asn/
│   │   │   ├── certificates/
│   │   │   ├── tls/
│   │   │   ├── exposure/
│   │   │   ├── cloud/
│   │   │   ├── containers/
│   │   │   ├── code/
│   │   │   ├── repositories/
│   │   │   ├── packages/
│   │   │   ├── sbom/
│   │   │   ├── ics_ot/
│   │   │   ├── iot/
│   │   │   └── automotive/
│   │   │
│   │   ├── cti_malware/
│   │   │   ├── ioc/
│   │   │   ├── malware/
│   │   │   ├── cve/
│   │   │   ├── exploitation/
│   │   │   ├── actor/
│   │   │   ├── campaign/
│   │   │   ├── ttp/
│   │   │   ├── stix_taxii/
│   │   │   ├── breach/
│   │   │   └── credential_exposure/
│   │   │
│   │   ├── fin_scam/
│   │   │   ├── scam/
│   │   │   ├── fraud/
│   │   │   ├── payments/
│   │   │   ├── crypto/
│   │   │   ├── transaction_graph/
│   │   │   └── scam_network/
│   │   │
│   │   ├── corporate_public_records/
│   │   │   ├── company/
│   │   │   ├── ownership/
│   │   │   ├── directors/
│   │   │   ├── procurement/
│   │   │   ├── tenders/
│   │   │   ├── sanctions/
│   │   │   ├── legal/
│   │   │   ├── regulatory/
│   │   │   ├── government/
│   │   │   ├── trade/
│   │   │   ├── patents/
│   │   │   ├── academic/
│   │   │   ├── market/
│   │   │   └── supply_chain/
│   │   │
│   │   ├── document_forensics/
│   │   │   ├── file/
│   │   │   ├── pdf/
│   │   │   ├── document/
│   │   │   ├── email/
│   │   │   ├── metadata/
│   │   │   ├── structured_data/
│   │   │   └── dfir/
│   │   │
│   │   ├── identity_entity/
│   │   │   ├── username/
│   │   │   ├── phone/
│   │   │   ├── email_identity/
│   │   │   ├── person/
│   │   │   ├── account/
│   │   │   ├── organization/
│   │   │   ├── entity_resolution/
│   │   │   └── conflict/
│   │   │
│   │   ├── graph_timeline/
│   │   │   ├── entity_graph/
│   │   │   ├── relationship_graph/
│   │   │   ├── claim_graph/
│   │   │   ├── event_graph/
│   │   │   ├── timeline/
│   │   │   ├── paths/
│   │   │   └── clusters/
│   │   │
│   │   ├── evidence_verification/
│   │   │   ├── integrity/
│   │   │   ├── provenance/
│   │   │   ├── lineage/
│   │   │   ├── source_reliability/
│   │   │   ├── independence/
│   │   │   ├── corroboration/
│   │   │   └── staleness/
│   │   │
│   │   ├── hypothesis_analysis/
│   │   │   ├── claim_generation/
│   │   │   ├── hypothesis_generation/
│   │   │   ├── ach/
│   │   │   ├── contradiction/
│   │   │   ├── adversarial/
│   │   │   ├── deception/
│   │   │   ├── attribution/
│   │   │   ├── pattern/
│   │   │   ├── anomaly/
│   │   │   ├── gap_analysis/
│   │   │   ├── rag/
│   │   │   ├── kag/
│   │   │   └── fusion/
│   │   │
│   │   └── reporting_decision_support/
│   │       ├── investigator_brief/
│   │       ├── executive_brief/
│   │       ├── evidence_report/
│   │       ├── hypothesis_report/
│   │       ├── gap_report/
│   │       ├── replay/
│   │       └── decision_journal/
│   │
│   ├── employee/                       # AI Employee control plane
│   │   ├── service.py                 # existing assignment service
│   │   ├── autonomous.py              # existing bounded coordinator
│   │   ├── autonomous_analysis.py
│   │   ├── skills.py                  # existing analyst procedures
│   │   ├── knowledge.py               # existing methodology retrieval
│   │   ├── orchestrator.py            # target: evidence-first loop
│   │   ├── planner.py                 # objective -> capabilities
│   │   ├── fusion.py                  # combine SkillResults
│   │   ├── supervisor.py              # adversarial review
│   │   ├── gap_engine.py              # missing evidence
│   │   └── next_action.py             # next-best bounded collection
│   │
│   ├── source_fabric/                  # source/tool portability
│   │   ├── registry.py                # existing
│   │   ├── router.py                  # existing
│   │   ├── execution.py               # existing
│   │   ├── gateway.py                 # existing
│   │   ├── sdk.py                     # existing
│   │   ├── declarative.py             # target: YAML/JSON API definitions
│   │   ├── custom_schema.py
│   │   ├── health.py
│   │   └── qualification.py
│   │
│   ├── workforce/                      # governed execution + evidence analysis
│   │   ├── contracts.py               # existing strict canonical objects
│   │   ├── tools.py                   # existing governed tool facade
│   │   ├── model_fabric.py            # existing Ollama/model router
│   │   ├── source_sdk.py              # existing source contract
│   │   ├── source_mcp.py              # existing MCP gateway
│   │   ├── source_registry.py
│   │   ├── source_router.py
│   │   ├── source_state.py
│   │   ├── documents.py
│   │   ├── normalization.py
│   │   ├── lineage.py
│   │   ├── verification.py
│   │   ├── contradictions.py
│   │   ├── graph.py
│   │   ├── knowledge.py
│   │   ├── pipeline.py
│   │   ├── scheduler.py               # target: DAG execution
│   │   └── replay.py                  # target: workflow replay manifest
│   │
│   ├── knowledge/                      # target hybrid RAG/KAG layer
│   │   ├── ingest.py
│   │   ├── chunk.py
│   │   ├── lexical.py                 # wrap existing search_index BM25
│   │   ├── vector.py
│   │   ├── hybrid.py
│   │   ├── rerank.py
│   │   ├── citations.py
│   │   ├── case_memory.py
│   │   └── namespaces.py
│   │
│   ├── multimodal/                     # target modality routing
│   │   ├── router.py
│   │   ├── image.py
│   │   ├── video.py
│   │   ├── audio.py
│   │   ├── document.py
│   │   ├── geo.py
│   │   └── structured.py
│   │
│   └── intelligence/                   # current low-level providers remain
│       ├── hub.py
│       ├── provider.py
│       ├── sources.py
│       └── ...
│
└── tests/
    ├── test_skill_domains.py
    ├── test_skill_registry.py
    ├── test_employee_skill_routing.py
    ├── test_skill_evidence_contract.py
    ├── test_skill_dependency_graph.py
    ├── test_source_declarative.py
    ├── test_hybrid_retrieval.py
    ├── test_hypothesis_loop.py
    └── existing tests...
```

## 3. Domain grouping

The 140 intelligence labels are routing vocabulary, not 140 autonomous agents.

| Family | Main responsibility |
| --- | --- |
| web_socmint | public web, search, dorking, news, social/community and narrative research |
| geo_media | geography, imagery, video, audio, satellite, aviation, maritime and environmental context |
| infra_cyber | DNS/IP/ASN/certs/cloud/repositories/packages/host/IoT/OT technical intelligence |
| cti_malware | IOC, malware, CVE, exploitation, actor, campaign, TTP, breach and exposure metadata |
| fin_scam | scam/fraud/payment/crypto and transaction-network intelligence |
| corporate_public_records | companies, government/public records, legal/regulatory, procurement, sanctions, trade and research |
| document_forensics | files, documents, email, metadata and DFIR-derived observations |
| identity_entity | bounded identity candidates, accounts, handles, phones, people and organization resolution |
| graph_timeline | relationships, events, graph paths, clusters and chronology |
| evidence_verification | custody, provenance, lineage, independence, corroboration and freshness |
| hypothesis_analysis | claims, competing hypotheses, contradictions, gaps, RAG/KAG and fusion |
| reporting_decision_support | evidence-linked briefing, reporting, replay and human decision journal |

## 4. One skill pack

Every executable skill eventually uses:

```text
skills/<family>/<skill>/
├── manifest.yaml
├── procedure.md
├── executor.py
├── normalizer.py
├── output_schema.json
└── evals/
    ├── fixtures/
    └── expected/
```

The model reads procedure/manifest metadata. Python owns network/tool execution, schema validation, provenance, evidence capture and policy.

## 5. AI Employee runtime flow

```text
Investigator
  -> case intake
  -> objective parser
  -> policy/scope
  -> AI planner requests capabilities
  -> SkillRegistry returns eligible skills
  -> deterministic plan validator
  -> DAG scheduler
  -> parallel governed skill execution
  -> raw evidence preservation
  -> normalization
  -> observation generation
  -> entity candidate resolution
  -> graph + timeline
  -> claims
  -> independent-source verification
  -> contradictions
  -> competing hypotheses
  -> adversarial review
  -> information gaps
  -> next evidence request
  -> approved second wave
  -> evidence-linked investigator package
```

The model must never widen scope, supply credentials, invent a tool, bypass the registry, directly merge identities, or promote a hypothesis to fact.

## 6. Existing code ownership

Do not duplicate these owners:

- `evidence.py`: canonical evidence bytes, SHA-256 and ledger.
- `policy.py`: target/policy boundaries.
- `resolution.py`: human-reviewed identity resolution.
- `workforce/contracts.py`: canonical strict evidence/claim/workforce objects.
- `workforce/tools.py`: governed tool-call enforcement.
- `workforce/model_fabric.py`: model routing and local Ollama.
- `workforce/source_sdk.py`: provider result contract.
- `workforce/source_mcp.py`: bounded MCP source access.
- `workforce/lineage.py`: source lineage.
- `workforce/verification.py`: claim verification.
- `workforce/graph.py`: temporal provenance-rich analytical graph.
- `source_fabric/*`: source discovery/routing/execution.
- `employee/autonomous.py`: current bounded investigation coordinator.

The new `skills/` package sits above source/tool execution and below the AI planner.

## 7. Integration states

Every capability has exactly one state:

```text
CATALOGUED
PROCEDURE
ADAPTER
FIXTURE_TESTED
LIVE_TESTED
QUALIFIED
DEGRADED
RETIRED
```

A domain entry in `domains.py` is only CATALOGUED.

A Markdown procedure is PROCEDURE.

A Python adapter is ADAPTER.

It is not production-integrated until it is QUALIFIED.

## 8. Evidence-first contract

Every skill result must ultimately be reducible to:

```text
Acquisition
  -> EvidenceObject
  -> Observation
  -> Claim
  -> VerificationDecision
```

Analytical path:

```text
Verified/visible claims
  -> Entity/Relationship candidates
  -> Timeline
  -> Contradictions
  -> Competing Hypotheses
  -> Information Gaps
  -> Next Action
  -> Human Decision
```

## 9. RAG and KAG

RAG does not replace sources or skills.

```text
Sources/skills -> collect evidence
Evidence -> index
RAG -> retrieve relevant evidence/methodology
KAG -> traverse structured entities/claims/relationships
AI -> reason over retrieved references
Verifier -> enforce support/contradiction/independence
```

Namespaces:

```text
methodology/
skills/
research/
case/<case_id>/evidence/
case/<case_id>/observations/
case/<case_id>/claims/
case/<case_id>/hypotheses/
```

Cross-case retrieval is forbidden unless an explicit policy allows it.

## 10. Model strategy

Models are replaceable workers behind `workforce/model_fabric.py`.

Routing order:

```text
privacy
-> required modality
-> local availability
-> evaluated capability
-> source/tool requirement
-> health
-> cost
-> latency
```

Default: local Ollama first. Remote models are optional accelerators, not architectural dependencies.

## 11. Safety boundary for sensitive domains

SIGINT/COMINT/ELINT/RF/MASINT, person intelligence, credential exposure, criminal/counter-terrorism, attribution and similar sensitive categories are taxonomy entries only until a lawful, bounded workflow exists.

TraceAtlas should support evidence analysis and defensive/public-source workflows. Taxonomy registration must never be treated as authorization for interception, credential misuse, covert access, stalking, exploitation or arbitrary targeting.

## 12. MVP promotion order

```text
P0 universal skill contracts + registry + routing
P1 scam intake + dorking + web + company + domain/IP + CTI + payment records
P2 entity resolution + graph + timeline
P3 verification + source independence + contradiction
P4 competing hypotheses + gap/next-evidence loop
P5 hybrid RAG/KAG
P6 image/video/audio/GEO multimodal
P7 declarative bring-your-own sources
P8 broader intelligence families
P9 multi-model specialization
```

## 13. Definition of integrated

A capability is integrated only when it is:

1. catalogued in the domain taxonomy,
2. represented by a versioned skill definition,
3. discoverable by the registry,
4. selectable by the planner,
5. permitted by case authority,
6. executable through a governed tool/source,
7. normalized into canonical results,
8. evidence/provenance linked,
9. consumable by graph/timeline/verification,
10. usable by the hypothesis/gap loop,
11. covered by tests/evals,
12. replayable with visible failure state.

Presence in a ZIP or README is not integration.
