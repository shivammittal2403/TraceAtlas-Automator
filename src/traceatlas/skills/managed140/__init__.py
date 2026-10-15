"""Isolation boundary for 140 offline evidence-interpretation domain adapters."""
from .registry import CATALOG, lookup, load
from .engine import analyze, verify
__all__ = ["CATALOG", "lookup", "load", "analyze", "verify"]
