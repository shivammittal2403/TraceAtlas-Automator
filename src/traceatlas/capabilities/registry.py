from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    id: str
    name: str
    upstream: str
    license: str
    integration: str
    capabilities: tuple[str, ...]
    binaries: tuple[str, ...] = ()
    credential_env: tuple[str, ...] = ()
    safety: tuple[str, ...] = ("authorization",)
    executable: bool = True
    restriction: str = ""
    protocol: str = "export"
    allowed_tool_prefixes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        row = asdict(self)
        for key in ("capabilities", "binaries", "credential_env", "safety", "allowed_tool_prefixes"):
            row[key] = list(row[key])
        return row


def _s(id: str, name: str, upstream: str, license: str, integration: str,
       capabilities: tuple[str, ...], **kwargs: Any) -> CapabilitySpec:
    return CapabilitySpec(id, name, upstream, license, integration, capabilities, **kwargs)


CAPABILITIES: dict[str, CapabilitySpec] = {spec.id: spec for spec in (
    _s("abster-intelligence", "Abster Intelligence", "github.com/AbsterHQ/abster-intelligence",
       "upstream-declared", "export", ("case-ui", "entity-graph", "timeline", "llm-analysis", "mcp"),
       safety=("authorization", "bring-your-own-key", "no-browser-secret-storage")),
    _s("agent-reach", "Agent Reach", "github.com/Panniantong/Agent-Reach", "MIT", "adapter",
       ("social-routing", "web-search", "platform-fallbacks", "doctor"), binaries=("agent-reach",),
       safety=("authorization", "subject-consent", "public-data-only", "no-cookie-import")),
    _s("claude-osint", "Claude OSINT", "github.com/anthropics/claude-osint", "Apache-2.0", "workflow",
       ("org-attribution", "idp-mapping", "spf-supply-chain", "fair-risk", "continuous-monitoring")),
    _s("freeosint", "FreeOSINT", "github.com/FreeOSINT/FreeOSINT", "upstream-declared", "training",
       ("training-modules", "module-authoring", "progress-tracking"), executable=False,
       restriction="Training content is catalogued; it never executes collection."),
    _s("iop-mvp", "IOP MVP", "local-supplied/IOP-MVP", "NO-LICENSE", "design-only",
       ("objective-decomposition", "dag-workflows", "evidence-gaps", "chain-of-custody", "rbac"),
       executable=False, restriction="No licence was supplied; concepts only, no source code copied."),
    _s("openosint", "OpenOSINT", "github.com/ankitdobhal/OpenOSINT", "MIT", "bundled",
       ("20-tools", "entity-graph", "mcp", "cloud-gateway", "reports"), binaries=("openosint",)),
    _s("agentic-osint-agent", "Agentic OSINT Agent", "local-supplied/agentic-osint-agent", "MIT", "workflow",
       ("bounded-react", "authority-record", "tui", "benchmarks", "hallucination-metrics")),
    _s("apify-mcp", "Apify MCP", "github.com/apify/apify-mcp-server", "Apache-2.0", "mcp",
       ("actors", "datasets", "key-value-stores", "tasks", "schedules", "builds"),
       binaries=("apify-mcp-server",), credential_env=("APIFY_TOKEN",),
       safety=("authorization", "actor-allowlist", "bounded-output"), protocol="mcp",
       allowed_tool_prefixes=("get-actor", "get_actor", "get-dataset", "get_dataset", "list-actors", "list_actors")),
    _s("browser-use", "Browser Use", "github.com/browser-use/browser-use", "MIT", "adapter",
       ("browser-agent", "cdp", "dom-references", "screenshots", "pdf", "structured-output"),
       binaries=("browser-use",), safety=("authorization", "isolated-profile", "domain-allowlist", "no-captcha-bypass")),
    _s("crawl4ai", "Crawl4AI", "github.com/unclecode/crawl4ai", "Apache-2.0", "adapter",
       ("web-crawl", "fit-markdown", "bm25", "structured-extraction", "deep-crawl", "cache"),
       binaries=("crawl4ai",), safety=("authorization", "public-data-only", "ssrf-guard", "rate-limit")),
    _s("deerflow", "DeerFlow", "github.com/bytedance/deer-flow", "MIT", "workflow",
       ("agent-harness", "skills", "subagents", "context-compaction", "memory", "sandboxes")),
    _s("exa-mcp", "Exa MCP", "github.com/exa-labs/exa-mcp-server", "MIT", "mcp",
       ("semantic-search", "people-search", "company-search", "code-search", "deep-research"),
       binaries=("exa-mcp-server",), credential_env=("EXA_API_KEY",),
       safety=("authorization", "subject-consent", "bounded-output"), protocol="mcp",
       allowed_tool_prefixes=("web_search", "research_paper", "get_code_context", "company_research")),
    _s("firecrawl", "Firecrawl", "github.com/firecrawl/firecrawl", "AGPL-3.0", "service",
       ("search", "scrape", "crawl", "map", "batch", "interact", "agent"),
       credential_env=("FIRECRAWL_API_KEY",), safety=("authorization", "service-boundary", "ssrf-guard"),
       restriction="Service/API adapter only; AGPL backend is not vendored."),
    _s("firecrawl-mcp", "Firecrawl MCP", "github.com/firecrawl/firecrawl-mcp-server", "MIT", "mcp",
       ("26-tools", "change-monitoring", "scientific-search", "developer-search", "alexandria"),
       binaries=("firecrawl-mcp",), credential_env=("FIRECRAWL_API_KEY",),
       safety=("authorization", "tool-allowlist", "bounded-output"), protocol="mcp",
       allowed_tool_prefixes=("firecrawl_search", "firecrawl_scrape", "firecrawl_map", "firecrawl_extract", "firecrawl_check")),
    _s("gpt-researcher", "GPT Researcher", "github.com/assafelovic/gpt-researcher", "CONFLICTING", "adapter",
       ("deep-research", "multi-agent-review", "local-docs", "citations", "report-export"),
       binaries=("gpt-researcher",), executable=False,
       restriction="Upstream licence metadata conflicts; export ingestion works, execution stays disabled."),
    _s("last30days", "Last30Days", "local-supplied/last30days", "MIT", "adapter",
       ("recency-search", "social-sources", "engagement-scoring", "clustering", "transcripts", "monitoring"),
       binaries=("last30days",), safety=("authorization", "public-data-only", "rate-limit")),
    _s("mcp-maigret", "MCP Maigret", "github.com/BurtTheCoder/mcp-maigret", "MIT", "mcp",
       ("username-search", "url-parse", "tag-filters", "reports"), binaries=("mcp-maigret",),
       safety=("authorization", "subject-consent", "exact-identifier", "no-bulk-enumeration"), protocol="mcp",
       allowed_tool_prefixes=("search_username", "parse_url", "get_supported")),
    _s("osint-agent", "OSINT Agent", "local-supplied/osint-agent", "MIT", "workflow",
       ("multilingual", "searxng", "translation", "satellite", "vector-memory"),
       credential_env=("SEARXNG_URL",), safety=("authorization", "source-provenance", "fact-inference-separation")),
    _s("osint-mcp-server", "OSINT MCP Server", "github.com/soxoj/osint-mcp-server", "MIT", "mcp",
       ("37-tools", "spf-chain", "dns-srv", "m365", "bgp", "geoip", "rate-limits", "cache"),
       binaries=("osint-mcp-server",), safety=("authorization", "tool-allowlist", "rate-limit", "bounded-output"),
       protocol="mcp", allowed_tool_prefixes=("dns_", "whois_", "rdap_", "spf_", "wayback_", "bgp_", "geoip_", "m365_")),
)}
