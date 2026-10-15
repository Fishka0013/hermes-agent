"""Tests for the GUI-surface ``read_preview`` tool."""

import json
import pytest

from tools import read_preview_tool as rp




def test_requires_callback():
    """Outside the desktop GUI there is no bridge — a clear error, no crash."""
    result = json.loads(rp.read_preview_tool(callback=None))
    assert "desktop" in result["error"]


def test_empty_answer_means_nothing_open():
    result = json.loads(rp.read_preview_tool(callback=lambda **_: ""))
    assert "error" in result


def test_passes_json_through():
    payload = {"kind": "url", "url": "https://news.ycombinator.com", "title": "HN", "text": "hello"}
    result = json.loads(rp.read_preview_tool(callback=lambda **_: json.dumps(payload)))
    assert result == payload


def test_unverified_non_json_text_is_blocked():
    result = json.loads(rp.read_preview_tool(callback=lambda **_: "plain words"))
    assert "error" in result and "plain words" not in json.dumps(result)


@pytest.mark.parametrize("payload", [
    {"kind": "file", "url": "file:///outside/private.html", "text": "outside sentinel"},
    {"kind": "file", "url": "https://example.com", "path": "/outside/private.html", "text": "outside sentinel"},
    {"kind": "url", "url": "FiLe:///outside/private.html", "text": "outside sentinel"},
    {"kind": "url", "url": "file%3A%2F%2F%2Foutside/private.html", "text": "outside sentinel"},
    {"kind": "url", "url": "data:text/html,outside", "text": "outside sentinel"},
    {"kind": "artifact", "url": "https://example.com", "text": "outside sentinel"},
    {"kind": "url", "text": "outside sentinel"},
])
def test_local_or_unverified_preview_never_returns_page_bytes(payload):
    result = rp.read_preview_tool(callback=lambda **_: json.dumps(payload))
    assert "error" in json.loads(result)
    assert "outside sentinel" not in result


def test_window_forwarded_and_validated():
    seen = {}

    def cb(**kwargs):
        seen.update(kwargs)
        return json.dumps({"kind": "url", "url": "https://example.com"})

    rp.read_preview_tool(start=100, count=500, callback=cb)
    assert seen == {"start": 100, "count": 500}

    # Floors mirror read_terminal: start >= 0, count >= 1.
    seen.clear()
    rp.read_preview_tool(start=-5, count=0, callback=cb)
    assert seen == {"start": 0, "count": 1}

    result = json.loads(rp.read_preview_tool(start="lots", callback=cb))
    assert "integers" in result["error"]


def test_callback_failure_is_reported():
    def _boom(**_kwargs):
        raise RuntimeError("renderer went away")

    result = json.loads(rp.read_preview_tool(callback=_boom))
    assert "renderer went away" in result["error"]


def test_empty_answer_names_both_cases_and_the_remedy():
    """Nothing-open and bridge-timeout arrive as the same empty answer; the
    error must tell them apart (open a page vs update an older app, #94272)."""
    result = json.loads(rp.read_preview_tool(callback=lambda **_: ""))

    assert "call open_preview first" in result["error"]
    assert "timed out" in result["error"]
    assert "older than this backend" in result["error"]
