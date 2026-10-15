# Release gates / blockers

1. Run existing full Python/Node/Playwright CI on branch without weakening checks.
2. Review both the Python monolith and SpiderFoot 4.0 snapshot for secrets, outdated dependencies, license preservation and transport security.
3. Promote recovered legacy fragments one by one: syntax -> isolated tests -> contract -> fixture replay -> source provenance -> policy -> live authorization review.
4. Connect case-evidence ingestion to canonical store only through existing approved worker APIs. These adapters intentionally do not write canonical DB state.
5. Qualify all 140 domain inputs and outputs with domain-specific fixtures; generic offline field extraction is NOT intelligence-depth parity with specialist tools.
6. Require policy, privacy and legal review before activating any sensitive collector, including SIGINT, COMINT, ELINT, HUMINT, MESSENGERINT, CREDINT, IDENTITYINT and PHONEINT.
7. Do not enable imported SpiderFoot modules by default. The pinned version may carry historical dependency advisories and active network behavior.

STATUS: CODED, automated test definitions added; NOT production-verified, NOT deployed.
