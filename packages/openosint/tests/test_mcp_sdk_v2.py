"""MCP 2.x registration must preserve schemas and reject input before dispatch."""
from unittest.mock import AsyncMock, patch

from mcp_types import CallToolRequestParams, CallToolResult, ListToolsResult, TextContent

from openosint import mcp_server


async def test_registered_catalog_preserves_tool_input_schema_and_wire_alias():
    handler = mcp_server.app.get_request_handler("tools/list").handler
    result = await handler(None, None)
    assert isinstance(result, ListToolsResult)
    dns = next(tool for tool in result.tools if tool.name == "search_dns")
    assert dns.input_schema["required"] == ["domain"]
    wire = dns.model_dump(by_alias=True)
    assert wire["inputSchema"]["properties"]["domain"]["type"] == "string"


async def test_missing_or_wrong_typed_arguments_do_not_dispatch():
    handler = mcp_server.app.get_request_handler("tools/call").handler
    for arguments in ({}, {"domain": 42}):
        with patch.object(mcp_server, "call_tool", new_callable=AsyncMock) as dispatch:
            result = await handler(None, CallToolRequestParams(name="search_dns", arguments=arguments))
        assert result.is_error
        assert result.model_dump(by_alias=True)["isError"] is True
        dispatch.assert_not_awaited()


async def test_valid_arguments_reach_existing_dispatch_with_structured_result():
    expected = CallToolResult(content=[TextContent(type="text", text="fixture result")], is_error=False)
    handler = mcp_server.app.get_request_handler("tools/call").handler
    with patch.object(mcp_server, "call_tool", new_callable=AsyncMock, return_value=expected) as dispatch:
        result = await handler(None, CallToolRequestParams(name="search_dns", arguments={"domain": "example.org"}))
    assert result == expected
    dispatch.assert_awaited_once_with("search_dns", {"domain": "example.org"})
