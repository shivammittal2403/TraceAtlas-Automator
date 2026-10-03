# Source lineage and corroboration

SourceIndependenceEngine builds connected components across all bounded
source pairs, rather than comparing only the first representative. Direct and
shared upstream IDs, publisher ownership/host, canonical URI, exact nonempty
content and token near-duplicates form conservative links. Input order does not
change grouping. Empty text alone does not collapse unrelated sources.

Declared lineage is operator/provider metadata and can be incomplete or wrong.
Distinct groups are candidate independence, not proof of corporate separation.
Cross-subdomain ownership requires declared ownership; no public-suffix database
is introduced. Claim corroboration counts only the observations for that same
structured assertion, never all sources gathered in the case.
