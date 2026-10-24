"""Optional guard hook interface for plugging MCP-Sentinel later.

MCP-Sentinel itself lives in LLM-tester-tool (``llm_tester.sentinel``).
This module only defines a thin Protocol so simulations/app can run with or
without an external guard dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@dataclass
class GuardDecision:
    """Result of a guard check around a tool call or message."""

    allowed: bool
    reason: str = ""
    sanitized: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(cls, reason: str = "allow") -> "GuardDecision":
        return cls(allowed=True, reason=reason)

    @classmethod
    def deny(cls, reason: str, *, sanitized: Optional[str] = None) -> "GuardDecision":
        return cls(allowed=False, reason=reason, sanitized=sanitized)


@runtime_checkable
class GuardHook(Protocol):
    """Pluggable guard used by attack/defense simulations.

    Implementations (e.g. a future ``mcp-sentinel`` adapter) should expose
    ``name`` and the three check methods below. Simulations treat a missing
    hook as ``NullGuard``.
    """

    name: str

    def before_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardDecision:
        ...

    def after_tool_result(
        self,
        tool_name: str,
        args: Dict[str, Any],
        result: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardDecision:
        ...

    def scan_message(
        self,
        role: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardDecision:
        ...


class NullGuard:
    """Default no-op guard (always allows)."""

    name = "none"

    def before_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardDecision:
        return GuardDecision.allow("null_guard")

    def after_tool_result(
        self,
        tool_name: str,
        args: Dict[str, Any],
        result: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardDecision:
        return GuardDecision.allow("null_guard")

    def scan_message(
        self,
        role: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardDecision:
        return GuardDecision.allow("null_guard")


def load_guard_hook(spec: Optional[str] = None) -> GuardHook:
    """Resolve a guard hook from ``GUARD_HOOK`` / ``MCP_GUARD_HOOK`` env or *spec*.

    Supported values:
    - ``none`` / empty → ``NullGuard``
    - ``module:attr`` → import ``attr`` from ``module`` (factory or instance)

    Example for a future Sentinel adapter::

        GUARD_HOOK=llm_tester.sentinel.adapters:MCPSentinelGuard
    """
    import importlib
    import os

    raw = (spec or os.environ.get("GUARD_HOOK") or os.environ.get("MCP_GUARD_HOOK") or "none").strip()
    if not raw or raw.lower() in ("none", "null", "off", "0"):
        return NullGuard()

    if ":" not in raw:
        raise ValueError(
            f"Invalid GUARD_HOOK '{raw}'. Use 'none' or 'module.path:ClassOrFactory'."
        )
    module_name, attr_name = raw.split(":", 1)
    module = importlib.import_module(module_name)
    obj = getattr(module, attr_name)
    guard = obj() if callable(obj) else obj
    if not isinstance(guard, GuardHook):  # Protocol check at runtime
        # Still accept duck-typed objects that implement the methods.
        for method in ("before_tool_call", "after_tool_result", "scan_message"):
            if not hasattr(guard, method):
                raise TypeError(f"Guard hook '{raw}' missing method '{method}'.")
    return guard


def apply_before_tool(
    guard: Optional[GuardHook],
    tool_name: str,
    args: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
) -> GuardDecision:
    """Helper used by simulations; treats None as NullGuard."""
    g = guard or NullGuard()
    return g.before_tool_call(tool_name, args, context)
