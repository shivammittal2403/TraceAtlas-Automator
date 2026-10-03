# Temporal analytical graph

`TemporalClaimGraph` remains storage-neutral; no Neo4j dependency is added.
Pipeline nodes and edges are derived from captured evidence. Each edge cites its
individual observation/evidence and preserves that fact's valid_from/valid_to;
retrieval time remains in the timeline. All generated edges remain PROPOSED.

Existing `public/graph-model.js` supplies interactive graph algorithms/filtering/
layouts in the hosted event graph. The new claim-graph snapshot is in the local
product; hosted UI integration is not implemented. Full GraphRepository query,
merge/split and rebuild adapters are future work. Do not conflate event graphs
with proven identities or causal relationships.

The integrated product also contains explicit Source, Evidence, Observation and
Claim nodes with ACQUIRED_FROM, DERIVED_FROM and CITES provenance edges. These
retain source/evidence/observation IDs, validity and verification separately from
confidence (null where no calibrated score exists). The provenance graph permits
traversal from a claim to its captured source without treating attributes as
proven identities.
