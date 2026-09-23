from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    binaries: tuple[str, ...]
    description: str
    category: str
    target_types: tuple[str, ...]
    mode: str  # passive, active, local, identity, blocked
    command: tuple[str, ...] = ()
    stdin_target: bool = False
    output_format: str = "lines"
    output_file: str | None = None
    emitted_type: str = "RAW_OBSERVATION"
    timeout: int = 120
    homepage: str = ""
    install_hint: str = ""
    required_options: tuple[str, ...] = ()
    optional_env: tuple[str, ...] = ()
    blocked_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("binaries", "target_types", "command", "required_options", "optional_env"):
            data[key] = list(data[key])
        return data


TOOLS: dict[str, ToolSpec] = {}


def _add(spec: ToolSpec) -> None:
    TOOLS[spec.name] = spec


_add(ToolSpec(
    "amass", ("amass",), "Attack-surface mapping and passive subdomain enumeration.",
    "domain-enumeration", ("domain",), "passive",
    ("{binary}", "enum", "-passive", "-d", "{target}", "-o", "{output}"),
    output_file="amass.txt", emitted_type="DOMAIN", timeout=600,
    homepage="https://owasp-amass.github.io/docs/",
    install_hint="Install OWASP Amass from its official release or package repository.",
))
_add(ToolSpec(
    "subfinder", ("subfinder",), "Fast passive subdomain discovery from curated sources.",
    "domain-enumeration", ("domain",), "passive",
    ("{binary}", "-d", "{target}", "-silent", "-oJ"), output_format="jsonl",
    emitted_type="DOMAIN", timeout=300, homepage="https://github.com/projectdiscovery/subfinder",
    install_hint="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    optional_env=("PDCP_API_KEY",),
))
_add(ToolSpec(
    "assetfinder", ("assetfinder",), "Find domains and subdomains related to a root domain.",
    "domain-enumeration", ("domain",), "passive",
    ("{binary}", "--subs-only", "{target}"), emitted_type="DOMAIN", timeout=180,
    homepage="https://github.com/tomnomnom/assetfinder",
    install_hint="go install github.com/tomnomnom/assetfinder@latest",
))
_add(ToolSpec(
    "findomain", ("findomain",), "Cross-platform subdomain enumeration.",
    "domain-enumeration", ("domain",), "passive",
    ("{binary}", "-t", "{target}", "-q"), emitted_type="DOMAIN", timeout=300,
    homepage="https://github.com/Findomain/Findomain",
    install_hint="Install the official Findomain release for your platform.",
))
_add(ToolSpec(
    "theharvester", ("theHarvester", "theharvester"),
    "Collect public hosts, emails and related intelligence from selected sources.",
    "osint-framework", ("domain",), "passive",
    ("{binary}", "-d", "{target}", "-b", "crtsh,duckduckgo"),
    output_format="mixed", emitted_type="OSINT_INDICATOR", timeout=600,
    homepage="https://github.com/laramies/theHarvester",
    install_hint="Use the official theHarvester installation guide and uv environment.",
))
_add(ToolSpec(
    "recon-ng", ("recon-cli",), "Run one installed Recon-ng module in a dedicated workspace.",
    "osint-framework", ("domain", "email", "username", "text"), "passive",
    ("{binary}", "--stealth", "-w", "{case}", "-m", "{module}",
     "-o", "SOURCE={target}", "-x"), output_format="mixed",
    emitted_type="OSINT_INDICATOR", timeout=900,
    homepage="https://github.com/lanmaster53/recon-ng",
    install_hint="Install Recon-ng and the selected marketplace module; ensure recon-cli is on PATH.",
    required_options=("module",),
))
_add(ToolSpec(
    "gau", ("gau",), "Fetch known URLs from public web archives and URL providers.",
    "archive-url", ("domain",), "passive", ("{binary}", "--json", "{target}"),
    output_format="jsonl", emitted_type="URL", timeout=300,
    homepage="https://github.com/lc/gau", install_hint="go install github.com/lc/gau/v2/cmd/gau@latest",
))
_add(ToolSpec(
    "waybackurls", ("waybackurls",), "Fetch public Wayback Machine URL observations.",
    "archive-url", ("domain",), "passive", ("{binary}",), stdin_target=True,
    emitted_type="URL", timeout=300, homepage="https://github.com/tomnomnom/waybackurls",
    install_hint="go install github.com/tomnomnom/waybackurls@latest",
))
_add(ToolSpec(
    "whois", ("whois",), "Retrieve public domain or IP registration records.",
    "registration", ("domain", "ip"), "passive", ("{binary}", "{target}"),
    emitted_type="WHOIS_RECORD", timeout=60, homepage="https://github.com/rfc1036/whois",
    install_hint="Install the whois package from your operating-system repository.",
))
_add(ToolSpec(
    "uncover", ("uncover",), "Query supported internet search engines through configured APIs.",
    "internet-intelligence", ("domain", "ip", "text"), "passive",
    ("{binary}", "-q", "{target}", "-j", "-silent"), output_format="jsonl",
    emitted_type="OSINT_INDICATOR", timeout=300,
    homepage="https://github.com/projectdiscovery/uncover",
    install_hint="go install github.com/projectdiscovery/uncover/cmd/uncover@latest",
    optional_env=("SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET"),
))
_add(ToolSpec(
    "dnsx", ("dnsx",), "Resolve and inspect DNS records using supplied targets.",
    "dns-validation", ("domain",), "active", ("{binary}", "-silent", "-json"),
    stdin_target=True, output_format="jsonl", emitted_type="DNS_RECORD", timeout=180,
    homepage="https://github.com/projectdiscovery/dnsx",
    install_hint="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
))
_add(ToolSpec(
    "httpx", ("httpx",), "Probe HTTP services and return structured response metadata.",
    "web-validation", ("domain", "url", "ip"), "active",
    ("{binary}", "-silent", "-json", "-u", "{target}", "-rl", "5"),
    output_format="jsonl", emitted_type="HTTP_RESPONSE", timeout=180,
    homepage="https://github.com/projectdiscovery/httpx",
    install_hint="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
))
_add(ToolSpec(
    "tlsx", ("tlsx",), "Collect TLS certificate and connection metadata.",
    "tls-validation", ("domain", "ip"), "active",
    ("{binary}", "-u", "{target}", "-json", "-silent"), output_format="jsonl",
    emitted_type="TLS_CERTIFICATE", timeout=180,
    homepage="https://github.com/projectdiscovery/tlsx",
    install_hint="go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
))
_add(ToolSpec(
    "whatweb", ("whatweb",), "Fingerprint technologies exposed by a website.",
    "technology", ("url", "domain"), "active",
    ("{binary}", "--log-json=-", "--no-errors", "{target}"), output_format="json",
    emitted_type="TECHNOLOGY", timeout=180, homepage="https://github.com/urbanadventurer/WhatWeb",
    install_hint="Install WhatWeb from the official repository or OS package.",
))
_add(ToolSpec(
    "katana", ("katana",), "Crawl authorized web applications for endpoints.",
    "web-crawler", ("url",), "active",
    ("{binary}", "-silent", "-jsonl", "-d", "2", "-u", "{target}", "-rl", "3"),
    output_format="jsonl", emitted_type="URL", timeout=600,
    homepage="https://github.com/projectdiscovery/katana",
    install_hint="go install github.com/projectdiscovery/katana/cmd/katana@latest",
))
_add(ToolSpec(
    "naabu", ("naabu",), "Enumerate a conservative set of TCP ports on an authorized target.",
    "port-scan", ("domain", "ip"), "active",
    ("{binary}", "-host", "{target}", "-top-ports", "100", "-rate", "50", "-json", "-silent"),
    output_format="jsonl", emitted_type="OPEN_PORT", timeout=600,
    homepage="https://github.com/projectdiscovery/naabu",
    install_hint="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
))
_add(ToolSpec(
    "nmap", ("nmap",), "Conservative TCP connect scan of common ports on an authorized target.",
    "port-scan", ("domain", "ip"), "active",
    ("{binary}", "-Pn", "-sT", "--top-ports", "100", "--max-rate", "50", "-oX", "-", "{target}"),
    output_format="nmap_xml", emitted_type="OPEN_PORT", timeout=900,
    homepage="https://nmap.org/", install_hint="Install Nmap from https://nmap.org/download.html.",
))
_add(ToolSpec(
    "nuclei", ("nuclei",), "Template-driven checks against an explicitly authorized target.",
    "vulnerability-validation", ("url", "domain"), "active",
    ("{binary}", "-u", "{target}", "-jsonl", "-silent", "-rl", "5",
     "-severity", "info,low,medium,high,critical"), output_format="jsonl",
    emitted_type="NUCLEI_FINDING", timeout=1200,
    homepage="https://github.com/projectdiscovery/nuclei",
    install_hint="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
))
_add(ToolSpec(
    "gobuster", ("gobuster",), "Discover web content using an explicitly supplied wordlist.",
    "content-discovery", ("url",), "active",
    ("{binary}", "dir", "-u", "{target}", "-w", "{wordlist}", "--no-error", "-q"),
    emitted_type="URL_PATH", timeout=900, required_options=("wordlist",),
    homepage="https://github.com/OJ/gobuster",
    install_hint="go install github.com/OJ/gobuster/v3@latest",
))
_add(ToolSpec(
    "ffuf", ("ffuf",), "Fuzz one authorized web path using an explicitly supplied wordlist.",
    "content-discovery", ("url",), "active",
    ("{binary}", "-u", "{target}/FUZZ", "-w", "{wordlist}", "-json", "-rate", "5", "-s"),
    output_format="json", emitted_type="URL_PATH", timeout=900, required_options=("wordlist",),
    homepage="https://github.com/ffuf/ffuf", install_hint="go install github.com/ffuf/ffuf/v2@latest",
))
_add(ToolSpec(
    "dirsearch", ("dirsearch",), "Discover authorized web paths with conservative defaults.",
    "content-discovery", ("url",), "active",
    ("{binary}", "-u", "{target}", "--format", "json", "--output", "{output}",
     "--max-rate", "5"), output_format="json", output_file="dirsearch.json",
    emitted_type="URL_PATH", timeout=900, homepage="https://github.com/maurosoria/dirsearch",
    install_hint="pipx install dirsearch",
))
_add(ToolSpec(
    "nikto", ("nikto",), "Run authorized web-server checks with JSON output.",
    "web-assessment", ("url", "domain"), "active",
    ("{binary}", "-host", "{target}", "-Format", "json", "-output", "{output}"),
    output_format="json", output_file="nikto.json", emitted_type="WEB_FINDING", timeout=1200,
    homepage="https://github.com/sullo/nikto", install_hint="Install Nikto from its official repository.",
))
_add(ToolSpec(
    "dnsrecon", ("dnsrecon",), "Enumerate DNS records for an authorized domain.",
    "dns-enumeration", ("domain",), "active",
    ("{binary}", "-d", "{target}", "-j", "{output}"), output_format="json",
    output_file="dnsrecon.json", emitted_type="DNS_RECORD", timeout=600,
    homepage="https://github.com/darkoperator/dnsrecon", install_hint="pipx install dnsrecon",
))
_add(ToolSpec(
    "fierce", ("fierce",), "Locate likely non-contiguous IP space and hostnames for a domain.",
    "dns-enumeration", ("domain",), "active", ("{binary}", "--domain", "{target}"),
    output_format="mixed", emitted_type="DNS_RECORD", timeout=600,
    homepage="https://github.com/mschwager/fierce", install_hint="pipx install fierce",
))
_add(ToolSpec(
    "spiderfoot", ("sf.py", "spiderfoot"), "Run installed SpiderFoot modules in passive mode.",
    "osint-framework", ("domain", "url", "ip", "email", "username", "text"), "passive",
    ("{binary}", "-s", "{target}", "-u", "passive", "-o", "json"),
    output_format="jsonl", emitted_type="OSINT_INDICATOR", timeout=1800,
    homepage="https://github.com/smicallef/spiderfoot",
    install_hint="Install SpiderFoot and place sf.py on PATH, or use the built-in TraceAtlas spider engine.",
))
_add(ToolSpec(
    "exiftool", ("exiftool",), "Extract metadata from an authorized local file.",
    "local-file", ("file",), "local", ("{binary}", "-json", "{target}"),
    output_format="json", emitted_type="FILE_METADATA", timeout=120,
    homepage="https://exiftool.org/", install_hint="Install ExifTool from its official distribution or OS package.",
))
_add(ToolSpec(
    "trufflehog", ("trufflehog",), "Scan an authorized local directory for potential exposed secrets.",
    "local-code", ("path",), "local",
    ("{binary}", "filesystem", "{target}", "--json", "--no-update"),
    output_format="jsonl", emitted_type="SECRET_CANDIDATE", timeout=1200,
    homepage="https://github.com/trufflesecurity/trufflehog",
    install_hint="Install the official TruffleHog binary.",
))
_add(ToolSpec(
    "gitleaks", ("gitleaks",), "Scan an authorized local repository for potential secrets.",
    "local-code", ("path",), "local",
    ("{binary}", "detect", "--source", "{target}", "--report-format", "json",
     "--report-path", "{output}", "--no-banner"), output_format="json",
    output_file="gitleaks.json", emitted_type="SECRET_CANDIDATE", timeout=1200,
    homepage="https://github.com/gitleaks/gitleaks", install_hint="Install the official Gitleaks release.",
))
_add(ToolSpec(
    "sherlock", ("sherlock",), "Check public sites for unverified username candidates.",
    "identity", ("username",), "identity",
    ("{binary}", "{target}", "--print-found", "--no-color"),
    output_format="mixed", emitted_type="ACCOUNT_CANDIDATE", timeout=900,
    homepage="https://github.com/sherlock-project/sherlock",
    install_hint="pipx install sherlock-project",
))

for name, binary, description, reason, homepage in (
    ("masscan", "masscan", "Internet-scale asynchronous port scanner.",
     "High-scale packet scanning is outside the managed runner's safety envelope.", "https://github.com/robertdavidgraham/masscan"),
    ("zmap", "zmap", "Internet-scale single-packet network scanner.",
     "Internet-scale scanning is outside the managed runner's safety envelope.", "https://github.com/zmap/zmap"),
    ("hydra", "hydra", "Network login testing utility.",
     "Automated credential attacks are not supported.", "https://github.com/vanhauser-thc/thc-hydra"),
    ("sqlmap", "sqlmap", "Automated SQL injection testing tool.",
     "Automated exploitation is not part of this reconnaissance engine.", "https://github.com/sqlmapproject/sqlmap"),
    ("metasploit", "msfconsole", "Exploit development and execution framework.",
     "Exploit execution is not part of this reconnaissance engine.", "https://github.com/rapid7/metasploit-framework"),
):
    _add(ToolSpec(
        name, (binary,), description, "blocked", (), "blocked",
        homepage=homepage, blocked_reason=reason,
    ))


PROFILES: dict[str, tuple[str, ...]] = {
    "passive-domain": (
        "amass", "subfinder", "assetfinder", "findomain", "theharvester",
        "gau", "waybackurls", "whois",
    ),
    "surface-validation": ("dnsx", "httpx", "tlsx", "whatweb"),
    "authorized-web": ("httpx", "katana", "nuclei", "nikto"),
    "authorized-network": ("dnsx", "naabu", "nmap"),
    "local-file": ("exiftool", "trufflehog", "gitleaks"),
}
