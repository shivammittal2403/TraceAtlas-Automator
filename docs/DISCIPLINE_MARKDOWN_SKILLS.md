# AI-employee Markdown procedures (139 requested + OSINT)

The 139 requested intelligence labels, plus umbrella OSINT, now have 140 bundled Markdown instructions. They describe input, authorization, scope, a discipline-aware procedure, evidence grounding, hypothesis review, limitations, and negative tests. They map to the pre-existing **native** Python processors, and do not represent 140 new live collectors.

## Commands

```bash
traceatlas-employees skill DNSINT
traceatlas-employees skills
python -m unittest tests.test_discipline_skills -v
```

`skill` returns a SHA-256-identified, validated procedure. `skills` fails if a registered native discipline has no valid procedure. The loader requires the bundled `discipline.analyze` tool and `live_verified=false`, never grants source authority. A Python distribution must retain the package-data mapping in `pyproject.toml`.

For canonical authorization and evidence custody see `EMPLOYEES_README.md` and `EMPLOYEE_INPUTS.md`. External providers still require independent integration, credentials, license, policy and live qualification.

Procedure version 1.0.1 removes unresolved template labels and legacy field
hints from all 140 guides. Each guide points to its existing native recipe in
`examples/employees/recipes/LABEL.json`; these are synthetic examples, never
case evidence. DNSINT explicitly uses `name`, `type`, `value` and optional
`ttl`. Native Python validation remains authoritative. The loader rejects
unexpanded `${...}` placeholders. Installed-package guide and canonical result
integrity regressions run on Windows/Linux with Python 3.10/3.12.
