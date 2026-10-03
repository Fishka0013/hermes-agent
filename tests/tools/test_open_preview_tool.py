"""Tests for the GUI-surface ``open_preview`` tool."""

import json

import pytest

from tools import desktop_ui, open_preview_tool as op


@pytest.fixture(autouse=True)
def _reset_emitter():
    """Each test controls the emitter; never leak one across tests."""
    desktop_ui.set_emitter(None)
    yield
    desktop_ui.set_emitter(None)




def test_emitter_failure_is_reported():
    def _boom(*_a):
        raise RuntimeError("no window")

    desktop_ui.set_emitter(_boom)
    assert "no window" in json.loads(op.open_preview_tool("https://x.example"))["error"]


@pytest.mark.parametrize("target", [
    "file:///etc/passwd",
    "file%3A%2F%2F%2Fetc%2Fpasswd",
    "/tmp/index.html",
    "./index.html",
    "../index.html",
    "~/index.html",
    "index.html",
])
def test_local_file_preview_is_blocked_before_emitter(target):
    calls = []
    desktop_ui.set_emitter(lambda *args: calls.append(args))
    payload = json.loads(op.open_preview_tool(target))
    assert "error" in payload
    assert "Local file/path preview is disabled" in payload["error"]
    assert calls == []


@pytest.mark.parametrize("target,expected", [
    ("https://example.com", "https://example.com"),
    ("www.example.com", "https://www.example.com"),
    ("localhost:3000", "http://localhost:3000"),
])
def test_http_targets_still_reach_preview_emitter(target, expected):
    calls = []
    desktop_ui.set_emitter(lambda _sid, event, payload: calls.append((event, payload)))
    payload = json.loads(op.open_preview_tool(target, label="test"))
    assert payload["success"] is True
    assert payload["url"] == expected
    assert calls and calls[0][0] == "preview.open"
    assert calls[0][1]["url"] == expected
