# Malvex Integration (pinned upstream, opt-in)

**Upstream:** https://github.com/JoasASantos/Malvex  
**Pinned upstream commit:** 75d86748c185aea0171b38682ab6a2bf15a5240c  
**Source placement:** third_party/malvex (Git submodule, not vendored code)  
**TraceAtlas adapter:** src/traceatlas/malvex_bridge.py  
**State:** registered and code-integrated, not execution-verified, not production-qualified.

Malvex is a Rust-based local-first malware reverse-engineering workflow with Ghidra,
YARA, dynamic analysis, agent runtimes, Ollama and an MCP server. TraceAtlas
remains the canonical case/evidence ledger and approval authority. The upstream
project's Cargo.toml declares MIT, but no standalone LICENSE was present in
the pinned tree during integration. Confirm licensing with the maintainer before
redistributing or vendoring a copy.

## Install (analyst workstation only)

    git submodule update --init third_party/malvex
    cd third_party/malvex
    cargo build --release -p malvex-cli

Make the resulting malvex binary available on PATH. Review upstream Rust code and
tool installation steps independently. Do **not** run upstream install scripts on
production servers. Git submodule checkout does not execute upstream code.

## TraceAtlas commands

    traceatlas --workspace ./cases malvex doctor
    traceatlas --workspace ./cases malvex coverage --source-root third_party/malvex
    traceatlas --workspace ./cases init investigation-1 --title "Malware lab" --purpose "Approved offline analysis"
    traceatlas --workspace ./cases malvex plan --case investigation-1 --sample /safe/inert.bin --authorized
    traceatlas --workspace ./cases malvex import-findings --case investigation-1 --file /safe/findings.json --authorized

The plan command invokes ONLY the upstream documented --dry-run mode, forces the
local Ollama runtime, validates the file and requires an existing approved case.
It does not execute a sample or automatically install dependencies.

The import command accepts a bounded Malvex findings JSON array (or an object
containing a findings array), SHA-256-preserves the report in the case evidence
ledger, and returns candidate summaries for analyst review. Even if Malvex
labels a finding "confirmed", TraceAtlas labels it **unverified_external_candidate**.
The imported report is **not** automatically a verified TraceAtlas finding,
graph edge, IOC assertion, or detection rule.

**Security boundary:** No malware sample detonation, PoC execution, unpacking,
unsafe subprocess, web exposure, or autonomous AI tool execution is enabled by
this integration. Dynamic analysis needs a separate isolated malware lab with
no production credentials, blocked egress, network segmentation, snapshot
rollback, custody review and explicit operator authorization. Never expose
Malvex or its MCP endpoint directly on a public IP. Ollama support upstream does
not mean Ollama or all 126 advertised tools were exercised here.

## Verification

    python -m unittest discover -s tests -p test_malvex_bridge.py
    python -m compileall -q src/traceatlas/malvex_bridge.py

Release gates: test a pinned Rust build, the upstream doctor/coverage, sample
dry-run, safe report ingestion into an authorized case, evidence-ledger
verification, and service-isolation review. Until then, mark runtime readiness
as **not verified**.
