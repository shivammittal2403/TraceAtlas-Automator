# Tool dispatch ownership

Existing intelligence source contracts, provider retry client and fixed-host
HTTPS transport are canonical. The pipeline chooses DNS/RDAP/archive for domain
and RDAP/InternetDB for IP; IPv6 omits InternetDB. These anonymous read-only
lookups cannot execute arbitrary endpoints, binaries or active scans.

Before each request, exact scope, authority validity, kill switch, tools/actions,
wall time and aggregate request attempts are checked. Existing ToolFacade adds
recursive secret-field rejection and scope/time checks. No public API or MCP
handler receives permission to change these checks.
