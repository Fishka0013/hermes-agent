"""Model inline preview callbacks never borrow a local renderer tab's authority."""
import json
from types import SimpleNamespace

import pytest

from agent.inline_tool_executors import INLINE_TOOL_EXECUTORS, InlineToolContext

CTX = InlineToolContext(effective_task_id="preview-confinement")
WEB = {"kind": "url", "url": "https://example.com", "text": "web content"}
LOCAL = {"kind": "file", "url": "file:///outside/private.html", "text": "private sentinel"}


@pytest.mark.parametrize("name,args", [
    ("drive_preview", {"action": "elements"}),
    ("annotate_preview", {"action": "hold"}),
])
@pytest.mark.parametrize("state", ["local", "missing", "malformed", "error"])
def test_local_or_unknown_page_blocks_before_action(name, args, state):
    calls = []
    readers = {
        "local": lambda **kw: json.dumps(LOCAL),
        "missing": None,
        "malformed": lambda **kw: "private sentinel",
        "error": lambda **kw: json.dumps({"error": "unavailable", "text": "private sentinel"}),
    }
    agent = SimpleNamespace(read_preview_callback=readers[state],
                            drive_preview_callback=lambda p: calls.append(p) or json.dumps(WEB))
    result = INLINE_TOOL_EXECUTORS[name](agent, args, CTX)
    assert "error" in json.loads(result)
    assert "private sentinel" not in result
    assert calls == []


@pytest.mark.parametrize("name,args", [
    ("drive_preview", {"action": "back"}),
    ("annotate_preview", {"action": "hold"}),
])
def test_page_changed_to_local_suppresses_action_inventory(name, args):
    pages = iter([WEB, LOCAL])
    calls = []
    agent = SimpleNamespace(read_preview_callback=lambda **kw: json.dumps(next(pages)),
                            drive_preview_callback=lambda p: calls.append(p) or json.dumps({"elements": ["private sentinel"]}))
    result = INLINE_TOOL_EXECUTORS[name](agent, args, CTX)
    assert len(calls) == 1
    assert "error" in json.loads(result) and "private sentinel" not in result


def test_http_page_action_and_window_contract_are_preserved():
    windows = []
    actions = []
    agent = SimpleNamespace(read_preview_callback=lambda **kw: windows.append(kw) or json.dumps(WEB),
                            drive_preview_callback=lambda p: actions.append(p) or json.dumps({"success": True}))
    result = INLINE_TOOL_EXECUTORS["drive_preview"](agent, {"action": "elements", "max": 20}, CTX)
    assert json.loads(result) == {"success": True}
    assert actions == [{"action": "elements", "max": 20}]
    assert windows == [{"count": 1}, {"count": 1}]


def test_desktop_preview_read_blocks_local_and_preserves_web_content():
    agent = SimpleNamespace(read_preview_callback=lambda **kw: json.dumps(LOCAL))
    blocked = INLINE_TOOL_EXECUTORS["desktop_preview"](agent, {"action": "read"}, CTX)
    assert "error" in json.loads(blocked) and "private sentinel" not in blocked
    agent.read_preview_callback = lambda **kw: json.dumps(WEB)
    assert json.loads(INLINE_TOOL_EXECUTORS["desktop_preview"](agent, {"action": "read"}, CTX)) == WEB
