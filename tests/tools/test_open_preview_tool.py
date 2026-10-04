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


def _capture_emits():
    emitted: list = []

    def _emit(_sid, event, payload):
        emitted.append((event, payload))

    desktop_ui.set_emitter(_emit)
    return emitted


def test_existing_directory_is_an_error_not_success(tmp_path):
    """#95853: a directory must not report success while opening nothing."""
    emitted = _capture_emits()
    folder = tmp_path / "Active"
    folder.mkdir()

    result = json.loads(op.open_preview_tool(str(folder)))

    assert "error" in result
    assert "Local file/path preview is disabled" in result["error"]
    assert result.get("success") is not True
    assert emitted == []


def test_existing_file_is_blocked(tmp_path):
    emitted = _capture_emits()
    path = tmp_path / "notes.md"
    path.write_text("hi", encoding="utf-8")

    result = json.loads(op.open_preview_tool(str(path)))

    assert "Local file/path preview is disabled" in result["error"]
    assert emitted == []


def test_https_url_is_not_treated_as_a_directory():
    emitted = _capture_emits()
    result = json.loads(op.open_preview_tool("https://example.com/docs"))

    assert result["success"] is True
    assert emitted[0][0] == "preview.open"


def test_file_uri_directory_is_an_error(tmp_path):
    emitted = _capture_emits()
    folder = tmp_path / "docs"
    folder.mkdir()
    uri = folder.resolve().as_uri()

    result = json.loads(op.open_preview_tool(uri))

    assert "error" in result
    assert "Local file/path preview is disabled" in result["error"]
    assert emitted == []


def test_missing_path_is_blocked(tmp_path):
    """Path authority is rejected before filesystem or renderer resolution."""
    emitted = _capture_emits()
    missing = tmp_path / "no-such-folder"

    result = json.loads(op.open_preview_tool(str(missing)))

    assert "Local file/path preview is disabled" in result["error"]
    assert emitted == []


@pytest.mark.parametrize("target", [
    "file:///etc/passwd", "FiLe:///etc/passwd", "file%3A%2F%2F%2Fetc%2Fpasswd",
    "/tmp/index.html", "./index.html", "../index.html", "~/index.html", "index.html",
    "data:text/html,local", "javascript:document.body.innerText",
])
def test_registered_preview_blocks_local_targets_before_emitter(target):
    from model_tools import handle_function_call
    emitted = _capture_emits()
    result = json.loads(handle_function_call(
        "desktop_preview", {"action": "open", "url": target}, task_id="sec3-preview"))
    assert "Local file/path preview is disabled" in result["error"]
    assert emitted == []


@pytest.mark.parametrize("target,expected", [
    ("https://example.com", "https://example.com"),
    ("www.example.com", "https://www.example.com"),
    ("localhost:3000", "http://localhost:3000"),
])
def test_registered_preview_preserves_http_targets(target, expected):
    from model_tools import handle_function_call
    emitted = _capture_emits()
    result = json.loads(handle_function_call(
        "desktop_preview", {"action": "open", "url": target, "label": "test"},
        task_id="sec3-preview"))
    assert result["success"] is True and result["url"] == expected
    assert emitted == [("preview.open", {"url": expected, "label": "test"})]
