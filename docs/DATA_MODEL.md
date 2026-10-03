# Canonical data model

Existing case records are canonical in `db.py`. AuthorizationContext,
TaskEnvelope, EmployeeDefinition, EvidenceObject, Observation, Claim, Hypothesis,
SourceLineage, VerificationDecision, CostRecord, TraceSpan and ResultEnvelope are
strict dataclasses in `workforce/contracts.py`. `documents.py` adds strict
SourceDocument and StructuredFact; unknown fields are rejected at decoding.

Subject → fact → observation → evidence → acquisition links are validated before
claims. Confidence remains separate from verification status. Graph nodes and
edges retain evidence, observations, validity intervals, proposals and uncertainty.
Product/replay documents are versioned JSON with digest validation.

InvestigationObjective, Worker, Connector, Source, Dataset, EntityCandidate,
EntityResolution, Event, Location, Contradiction, InformationGap, NextBestAction
and Report do not all have unified strict canonical object schemas yet. Existing
services own partial equivalents. The proposed full object model remains a
roadmap; do not infer implementation from a schema name in the master brief.
