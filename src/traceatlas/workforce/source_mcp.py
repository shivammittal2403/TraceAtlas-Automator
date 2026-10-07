"""Stable source capabilities over approved workforce tasks; optional MCP transport."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from ..db import CaseDB
from .pipeline import InvestigationPipeline
from .service import WorkforceService
from .source_registry import SourceRegistry
from .source_state import SourceState
from .tools import _has_secret

OPERATIONS = {
    'sources.list_capabilities': 'List registered intelligence capabilities; does not perform collection.',
    'sources.describe': 'Describe one source, configuration requirements and qualification limits.',
    'sources.health': 'Return observed source health; fixture activity is not production qualification.',
    'sources.estimate_cost': 'Read the approved plan estimates and unknown costs.',
    'sources.search': 'Execute the already approved, bounded source plan for this task, then return its evidence-linked results.',
    'sources.fetch': 'Execute the already approved, bounded source plan for this task; never fetch an arbitrary URL.',
}
INPUT_SCHEMA = {'type': 'object', 'additionalProperties': False,
    'properties': {key: {'type': 'string', 'maxLength': 128} for key in ('case_id', 'task_id', 'authorization_context_id', 'trace_id', 'source_id')},
    'required': ['case_id', 'task_id', 'authorization_context_id', 'trace_id', 'scope']}
INPUT_SCHEMA['properties']['scope'] = {'type': 'array', 'items': {'type': 'string', 'maxLength': 128}, 'minItems': 1, 'maxItems': 8}


class SourceCapabilities:
    def __init__(self, service, workspace, *, pipeline=None):
        self.service, self.workspace = service, workspace
        self.registry = SourceRegistry(); self.state = SourceState(service.store)
        self.pipeline = pipeline or InvestigationPipeline(service, workspace)

    def call(self, operation, arguments):
        if operation not in OPERATIONS or not isinstance(arguments, dict) or _has_secret(arguments):
            raise ValueError('invalid source capability request')
        required = set(INPUT_SCHEMA['required'])
        if not required <= set(arguments) or set(arguments) - set(INPUT_SCHEMA['properties']):
            raise ValueError('source request requires bound case, task, authority, trace and scope')
        if len(json.dumps(arguments).encode()) > 8192:
            raise ValueError('source capability request exceeds byte bound')
        for key in required - {'scope'}:
            if not isinstance(arguments[key], str) or not 1 <= len(arguments[key]) <= 128:
                raise ValueError('invalid source capability identifier')
        if (not isinstance(arguments['scope'], list) or not 1 <= len(arguments['scope']) <= 8 or
                any(not isinstance(s, str) or not 1 <= len(s) <= 128 for s in arguments['scope'])):
            raise ValueError('invalid source capability scope')
        row = self.service.store.task(arguments['task_id']); task = row['envelope']
        authority = self.service.store.authorization(task.authorization_context_id)
        self.service._check_authority(authority, task)
        if (arguments['case_id'] != task.case_id or arguments['trace_id'] != task.trace_id or
                arguments['authorization_context_id'] != task.authorization_context_id or
                arguments['scope'] != list(task.scope) or not self.service._enabled()):
            raise ValueError('source capability authority mismatch')
        plan = self.state.plan(task)
        source = arguments.get('source_id')
        if source and source not in (plan or {}).get('sources', []):
            raise ValueError('source is outside the approved task plan')
        if operation == 'sources.list_capabilities':
            result = self.registry.capabilities()
        elif operation == 'sources.describe':
            if not source: raise ValueError('source_id required')
            result = self.registry.get(source).to_dict()
        elif operation == 'sources.health':
            if not source: raise ValueError('source_id required')
            result = self.state.health(source)
        elif operation == 'sources.estimate_cost':
            result = {'estimated_cost': (plan or {}).get('estimated_cost'), 'currency': 'USD', 'actual_cost': None,
                      'price_ceilings': (plan or {}).get('price_ceilings', {}), 'budget': task.budget.to_dict()}
        else:
            product = self.pipeline.run(task.task_id, live=True, authorized=True)
            result = {'state': product['state'], 'source_results': product.get('source_results', []),
                      'information_gaps': product['analysis']['information_gaps'], 'source_costs': product['source_costs'],
                      'report_status': product['report_status'], 'replay_available': True}
        response = {'case_id': task.case_id, 'task_id': task.task_id, 'trace_id': task.trace_id,
                    'audit_context': task.authorization_context_id, 'instruction_authority': 'none', 'result': result}
        if len(json.dumps(response).encode()) > 2 * 1024 * 1024:
            raise ValueError('source capability output exceeds byte bound')
        return response

    def call_in_worker(self, operation, arguments):
        # SQLite connections belong to their creating thread. Reopen the same
        # canonical store in the worker; all authority is reloaded at dispatch.
        db = CaseDB(self.service.store.db.path)
        try:
            service = WorkforceService(db, enabled=self.service.enabled, registry=self.service.registry)
            return SourceCapabilities(service, self.workspace).call(operation, arguments)
        finally:
            db.close()


def _mcp_wire_types():
    # The MCP SDK bundles its wire models as `mcp.types`; standalone installs of
    # the `mcp-types` package expose the identical schema as top-level
    # `mcp_types`. Prefer whichever matches the installed SDK so tool results
    # validate against the SDK's own pydantic models instead of a shadow class.
    import mcp.types as sdk_types
    try:
        import mcp_types  # noqa: F401
    except ImportError:
        return sdk_types
    sample = sdk_types.Tool(name='probe', inputSchema={'type': 'object'})
    if type(sample).__name__ == 'Tool' and 'inputSchema' in sample.model_dump(by_alias=True):
        return sdk_types
    import mcp_types as standalone
    if {f.alias or n for n, f in standalone.Tool.model_fields.items()} == \
            {f.alias or n for n, f in sdk_types.Tool.model_fields.items()}:
        # Identical wire schema: the SDK's own classes remain authoritative.
        return sdk_types
    return standalone


def build_server(facade):
    # Optional transport dependency; the source gateway and CLI remain stdlib-only.
    from mcp.server import Server
    types = _mcp_wire_types()
    dispatch_lock = asyncio.Lock()

    server = Server('traceatlas-sources')

    @server.list_tools()
    async def list_tools():
        return [types.Tool(name=name, description=description, input_schema=INPUT_SCHEMA)
                for name, description in OPERATIONS.items()]

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        if name not in OPERATIONS:
            raise ValueError('Unknown source capability')
        try:
            async with dispatch_lock:
                result = await asyncio.to_thread(facade.call_in_worker, name, arguments or {})
            return [types.TextContent(type='text', text=json.dumps(result))]
        except (ValueError, TypeError, KeyError):
            # Rejections travel as protocol-level errors, never as fake success.
            return types.CallToolResult(
                content=[types.TextContent(type='text', text='Source capability request rejected')],
                is_error=True)
    return server


def main():
    parser = argparse.ArgumentParser(description='TraceAtlas approved-source MCP stdio server')
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    from mcp.server.stdio import stdio_server
    db = CaseDB(args.workspace / 'traceatlas.db')
    facade = SourceCapabilities(WorkforceService(db), args.workspace)
    server = build_server(facade)
    async def serve():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    try: asyncio.run(serve())
    finally: db.close()


if __name__ == '__main__':
    main()
