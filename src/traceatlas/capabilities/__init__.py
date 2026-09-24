"""Governed bridges for optional upstream research engines."""

from .hub import CapabilityHub
from .registry import CAPABILITIES, CapabilitySpec
from .mcp import MCPClient, MCPError
from .workflow import ResearchWorkflow
from .service import ServiceClient
from .training import TrainingStore

__all__ = ["CAPABILITIES", "CapabilityHub", "CapabilitySpec", "MCPClient", "MCPError", "ResearchWorkflow", "ServiceClient", "TrainingStore"]
