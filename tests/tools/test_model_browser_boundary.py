"""Ordinary registry dispatch cannot reach unfenced browser execution routes."""
import json

import pytest


@pytest.mark.parametrize("name,args", [
    ("browser_exec", {"code": "print(open('/etc/passwd').read())"}),
    ("browser_cdp", {"method": "Target.createTarget", "params": {"url": "file:///etc/passwd"}}),
])
def test_unfenced_tools_absent_and_forged_dispatch_refused(name, args, monkeypatch):
    from model_tools import get_tool_definitions, handle_function_call
    from tools import browser_use_cli, browser_cdp_tool
    from tools.registry import invalidate_check_fn_cache
    calls = []
    def forbidden(*a, **kw):
        calls.append((a, kw))
        raise AssertionError("Refusal must precede host execution and browser routing")
    monkeypatch.setattr(browser_use_cli, "browser_exec", forbidden)
    monkeypatch.setattr(browser_cdp_tool, "routed_browser_handler", forbidden)
    invalidate_check_fn_cache()
    definitions = get_tool_definitions(enabled_toolsets=["terminal", "browser-use", "browser-cdp"])
    assert name not in {d["function"]["name"] for d in definitions}
    result = json.loads(handle_function_call(name, args, task_id="sec3-browser-boundary"))
    assert "unavailable to ordinary model tools" in result["error"]
    assert calls == []


@pytest.mark.parametrize("action", [
    "browser_snapshot", "browser_get_images", "browser_vision", "browser_console",
    "browser_click", "browser_type", "browser_back",
])
@pytest.mark.parametrize("page", ["file:///outside/sentinel.txt", "file%3A%2F%2F%2Foutside%2Fsentinel.txt", None])
def test_existing_file_page_or_unknown_url_blocked_before_content(action, page, monkeypatch):
    from model_tools import handle_function_call
    from tools import browser_tool
    calls = []
    def route(name, args, **kw):
        calls.append((name, args, kw.get("task_id"), kw.get("session_id")))
        assert name == "browser_console" and args == {"expression": "window.location.href"}
        return json.dumps({"success": True, "result": page})
    monkeypatch.setattr(browser_tool, "routed_browser_handler", route)
    result = json.loads(handle_function_call(action, {"ref": "@e1", "text": "hi", "question": "page"}, task_id="guard-task"))
    assert "error" in result
    assert len(calls) == 1 and calls[0][2] == "guard-task"


def test_safe_page_retains_route_and_computed_script_is_refused(monkeypatch):
    from model_tools import handle_function_call
    from tools import browser_tool
    calls = []
    def route(name, args, **kw):
        calls.append((name, dict(args), kw.get("task_id")))
        if args == {"expression": "window.location.href"}:
            return '{"success": true, "result": "https://example.test"}'
        return '{"success": true, "snapshot": "bounded page result"}'
    monkeypatch.setattr(browser_tool, "routed_browser_handler", route)
    result = json.loads(handle_function_call("browser_snapshot", {"full": True}, task_id="guard-task"))
    assert result["snapshot"] == "bounded page result"
    assert calls == [("browser_console", {"expression": "window.location.href"}, "guard-task"),
                     ("browser_snapshot", {"full": True}, "guard-task"),
                     ("browser_console", {"expression": "window.location.href"}, "guard-task")]
    calls.clear()
    result = json.loads(handle_function_call("browser_console", {"expression": "location.href=['fi','le:', '/outside/sentinel.txt'].join('')"}, task_id="guard-task"))
    assert "unavailable to ordinary model tools" in result["error"]
    assert calls == []


@pytest.mark.parametrize("url", ["file:///etc/passwd", "file%3A%2F%2F%2Fetc%2Fpasswd", "FiLe:///etc/passwd", "file%253A%252F%252F%252Fetc%252Fpasswd", "`file:///etc/passwd`", "/outside/sentinel.txt", "C:\\outside\\sentinel.txt"])
def test_file_navigation_refused_before_extension_route(url, monkeypatch):
    from model_tools import handle_function_call
    from tools import browser_tool
    calls = []
    def forbidden(*a, **kw):
        calls.append((a, kw))
        raise AssertionError("A local target must never reach the extension")
    monkeypatch.setattr(browser_tool, "routed_browser_handler", forbidden)
    result = json.loads(handle_function_call("browser_navigate", {"url": url}, task_id="sec3-browser-boundary"))
    assert "local-file navigation" in result["error"]
    assert calls == []
