"""Governed bridges for optional upstream research engines."""

from .hub import CapabilityHub
from .registry import CAPABILITIES, CapabilitySpec

__all__ = ["CAPABILITIES", "CapabilityHub", "CapabilitySpec"]
