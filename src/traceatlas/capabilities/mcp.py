from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from ..policy import PolicyError
from .registry import CAPABILITIES, CapabilitySpec


MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
DENIED_TOOL_PARTS = ("execute_actor", "run_actor", "cancel_run", "delete", "login", "credential", "cookie", "captcha")


class MCPError(ValueError):
    pass


class MCPClient:
    """Minimal bounded MCP stdio client for locally installed allowlisted servers."""

    def __init__(self, spec: CapabilitySpec, binary: str, timeout: int = 30):
        if spec.protocol != "mcp":
            raise PolicyError(f"{spec.id} is not an MCP integration")
        if Path(binary).name not in spec.binaries:
            raise PolicyError("MCP executable does not match the registered integration")
        self.spec = spec
        self.binary = binary
        self.timeout = max(2, min(timeout, 120))

    @staticmethod
    def _reader(stream: Any, output: queue.Queue[Any]) -> None:
        try:
            for line in iter(stream.readline, ""):
                if len(line.encode("utf-8", errors="ignore")) > MAX_RESPONSE_BYTES:
                    output.put(MCPError("MCP response line exceeds size limit"))
                    return
                try:
                    output.put(json.loads(line))
                except json.JSONDecodeError:
                    continue
        finally:
            output.put(EOFError("MCP server closed stdout"))

    def _request(self, proc: subprocess.Popen[str], output: queue.Queue[Any],
                 request_id: int, method: str, params: dict[str, Any] | None = None) -> Any:
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        proc.stdin.flush()
        while True:
            try:
                item = output.get(timeout=self.timeout)
            except queue.Empty as exc:
                raise MCPError(f"MCP {method} timed out") from exc
            if isinstance(item, Exception):
                raise MCPError(str(item))
            if item.get("id") != request_id:
                continue
            if "error" in item:
                raise MCPError(f"MCP {method} failed: {item['error']}")
            encoded = json.dumps(item.get("result"), default=str).encode()
            if len(encoded) > MAX_RESPONSE_BYTES:
                raise MCPError("MCP result exceeds 4 MiB limit")
            return item.get("result")

    def exchange(self, method: str, params: dict[str, Any] | None = None) -> Any:
        with tempfile.TemporaryDirectory(prefix="traceatlas-mcp-") as isolated_home:
            env = {key: value for key, value in os.environ.items() if key in {
                "PATH", "SystemRoot", "COMSPEC", "LANG", "LC_ALL", *self.spec.credential_env
            }}
            env.update({"HOME": isolated_home, "USERPROFILE": isolated_home, "TMPDIR": isolated_home})
            proc = subprocess.Popen(
                [self.binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env, cwd=isolated_home,
                shell=False,
            )
            output: queue.Queue[Any] = queue.Queue()
            assert proc.stdout is not None
            threading.Thread(target=self._reader, args=(proc.stdout, output), daemon=True).start()
            try:
                self._request(proc, output, 1, "initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "traceatlas", "version": "0.8.0"},
                })
                assert proc.stdin is not None
                proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
                proc.stdin.flush()
                return self._request(proc, output, 2, method, params)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                if proc.stdin:
                    proc.stdin.close()
                if proc.stdout:
                    proc.stdout.close()

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.exchange("tools/list", {}) or {}
        tools = result.get("tools", []) if isinstance(result, dict) else []
        return [item for item in tools if isinstance(item, dict) and self.tool_allowed(str(item.get("name", "")))]

    def tool_allowed(self, name: str) -> bool:
        lowered = name.lower()
        return bool(TOOL_NAME.fullmatch(name)) and not any(part in lowered for part in DENIED_TOOL_PARTS) and any(
            lowered.startswith(prefix.lower()) for prefix in self.spec.allowed_tool_prefixes
        )

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if not self.tool_allowed(name):
            raise PolicyError(f"MCP tool is outside the {self.spec.id} allowlist: {name}")
        if len(json.dumps(arguments, default=str).encode()) > 64 * 1024:
            raise PolicyError("MCP arguments exceed 64 KiB")
        return self.exchange("tools/call", {"name": name, "arguments": arguments})
