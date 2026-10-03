# MCP interoperability state

The existing `capabilities/mcp.py` is an allowlisted client. Workforce
ToolFacade is transport-neutral and checks task/case/authority/policy, tool/action
permissions, bounds, nested secret fields and target scope.

No new TraceAtlas MCP server is added. Stable future business tools must resolve
user/tenant/case/trace/authorization/scope/purpose server-side and invoke canonical
services, rather than moving policy into prompts or MCP transport. Existing MCP
allowlists are not automatically expanded by new product predicates.
