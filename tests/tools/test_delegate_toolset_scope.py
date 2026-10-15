"""Tests for delegate_tool toolset scoping.

Verifies that subagents cannot gain tools that the parent does not have.
The LLM controls the `toolsets` parameter — without intersection with the
parent's enabled_toolsets, it can escalate privileges by requesting
arbitrary toolsets.
"""

from types import SimpleNamespace

from tools.delegate_tool import _strip_blocked_tools, _emit_parent_console
from tools.delegate_tool_toolsets import _resolve_child_toolsets

class TestToolsetIntersection:
    """Subagent toolsets must be a subset of parent's enabled_toolsets."""

    def test_strip_blocked_removes_delegation(self):
        """Blocked toolsets (delegation, clarify, etc.) are always removed."""
        child = _strip_blocked_tools(["terminal", "delegation", "clarify", "memory"])
        assert "delegation" not in child
        assert "clarify" not in child
        assert "memory" not in child
        assert "terminal" in child

    def test_computer_use_is_blocked_even_when_parent_explicitly_has_it(self):
        parent = SimpleNamespace(
            enabled_toolsets=["terminal", "computer_use"],
            disabled_toolsets=[],
        )
        enabled, disabled = _resolve_child_toolsets(parent, None, "leaf")
        assert "computer_use" not in enabled
        assert "computer_use" in disabled
        assert "terminal" in enabled

class TestEmitParentConsole:
    """Progress lines (e.g. ``✓ [N/M] …``) must route through the parent's
    configured ``_safe_print`` in headless stdio hosts (ACP, gateway) so
    they don't land on stdout and corrupt JSON-RPC frames. Regression for a
    bug where delegate_task completion lines pushed to stdout caused
    ``Failed to parse JSON message: ✓ [3/3] …`` errors in the ACP adapter."""

    def test_routes_through_parent_safe_print_when_available(self, capsys):
        captured_lines = []
        parent = SimpleNamespace(_safe_print=lambda line: captured_lines.append(line))

        _emit_parent_console(parent, "  ✓ [1/3] Research done  (11.55s)")

        assert captured_lines == ["  ✓ [1/3] Research done  (11.55s)"]
        stdout_stderr = capsys.readouterr()
        assert stdout_stderr.out == ""
        assert stdout_stderr.err == ""


class TestSec3ChildPrivilegeBoundary:
    def test_role_reserved_and_unclassified_mcp_are_not_inherited(self):
        parent = SimpleNamespace(
            enabled_toolsets=["terminal", "setup", "admin", "privileged", "mcp-admin", "node_repl", "rdc"],
            disabled_toolsets=[],
        )
        enabled, disabled = _resolve_child_toolsets(parent, None, "worker")
        assert enabled == ["terminal"]
        assert {"setup", "admin", "privileged", "node_repl", "rdc"} <= set(disabled)

    def test_mcp_alias_and_composite_cannot_smuggle_transport_tools(self, monkeypatch):
        import model_tools
        import toolsets
        from tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="mcp__hostadmin__read_file",
            toolset="mcp-hostadmin",
            schema={"name": "mcp__hostadmin__read_file", "parameters": {"type": "object", "properties": {}}},
            handler=lambda *_a, **_kw: "{}",
        )
        registry.register_toolset_alias("hostadmin", "mcp-hostadmin")
        monkeypatch.setattr("tools.registry.registry", registry)
        monkeypatch.setattr(model_tools, "registry", registry)
        monkeypatch.setitem(toolsets.TOOLSETS, "_sec3_mixed",
                            {"description": "test", "tools": ["read_file", "mcp__hostadmin__read_file"], "includes": []})
        parent = SimpleNamespace(enabled_toolsets=["_sec3_mixed", "hostadmin"], disabled_toolsets=[])
        enabled, disabled = _resolve_child_toolsets(parent, None, "worker")
        selected = model_tools._select_tool_names(enabled, disabled, True)
        assert "hostadmin" not in enabled
        assert "mcp-hostadmin" in disabled
        assert "mcp__hostadmin__read_file" not in selected
        assert "read_file" in selected
