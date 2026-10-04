# Engineering decisions

## D-001 — Keep scope governed

Use only analyst-provided evidence and explicitly authorized public research.
Do not add account actions, autonomous contact, auth bypass, credential
harvesting, exploitation, malware execution, publication or intrusive scanning.

## D-002 — Preserve existing authorities

The source registry supplies maturity metadata; FabricStore owns persisted
qualification reviews/promotions; EvidenceStore owns case evidence and integrity.
Do not persist qualification proposals as trusted state without artifact checks.

## D-003 — One maturity vocabulary

`src/traceatlas/source_maturity.py` is canonical for lifecycle labels and gates.
Legacy spellings normalize at read/serialization boundaries. Fixture or
configured-source success never counts as live verification.

## D-004 — Level score requires measured evidence

Do not produce numeric category or overall scores until repeatable evaluation
results and a documented rubric exist. Missing measurements are UNKNOWN, not 0
or assumed passing.

## D-005 — PRs are the review boundary

Implementation changes target a new branch and reviewable PR. Never merge into
main from this autonomous engineering loop.
