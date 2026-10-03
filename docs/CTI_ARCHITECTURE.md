# CTI integration state

Existing `cti.py` implements deterministic IOC/CVE/ATT&CK-reference
extraction, feed correlation and STIX export; governed service boundaries provide
optional enrichment. The new shared backbone can preserve structured indicator
assertions with provenance and verification. G05 tests that contract only.

A canonical threat-actor/campaign/malware/infrastructure graph using these
acquisitions and task contracts remains PARTIAL. No actor attribution is generated
by the pipeline. Reuse CTI_ENGINE.md before adding a dedicated vertical slice.
