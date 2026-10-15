"""Model background jobs keep the foreground envelope; native host grants stay private."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_constants import set_hermes_home_override, reset_hermes_home_override


@pytest.fixture
def profiles(tmp_path, monkeypatch):
    pairs = []
    for label in ("a", "b"):
        home, root = tmp_path / ("profile-" + label), tmp_path / ("workspace-" + label)
        home.mkdir()
        root.mkdir()
        (home / "config.yaml").write_text(json.dumps({
            "security": {"model_workspace_root": str(root)},
            "terminal": {"backend": "local", "cwd": str(root), "temp_dir": str(tmp_path)},
        }))
        pairs.append((home, root))
    monkeypatch.setenv("HERMES_HOME", str(pairs[0][0]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    from tools import terminal_tool
    for home, _ in pairs:
        token = set_hermes_home_override(home)
        try:
            terminal_tool.clear_session_cwd("same-task")
        finally:
            reset_hermes_home_override(token)
    monkeypatch.setattr(terminal_tool, "_check_all_guards", lambda *args, **kwargs: {"approved": True})
    from tools.terminal_scope import install_and_reset_profile_terminal_scope
    with install_and_reset_profile_terminal_scope(pairs[0][0]):
        yield pairs
        from tools.terminal_tool_lifecycle import cleanup_all_environments
        cleanup_all_environments()


@pytest.mark.platforms("not macos")
@pytest.mark.parametrize("kind", ["explicit", "promoted", "forged_host_grant"])
def test_model_background_keeps_env_transport_a_b_a(profiles, monkeypatch, kind):
    from model_tools import handle_function_call
    from tools import process_registry as process_module, terminal_tool
    from tools.terminal_scope import install_and_reset_profile_terminal_scope
    calls = []
    def forbidden(*args, **kwargs):
        raise AssertionError("Model background acquired native host spawn")
    def capture(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(id="owned-process", pid=1234, notify_on_complete=False,
                               watcher_platform="", watcher_interval=0)
    monkeypatch.setattr(process_module.process_registry, "spawn_local", forbidden)
    monkeypatch.setattr(process_module.process_registry, "spawn_via_env", capture)
    for index in (0, 1, 0):
        home, root = profiles[index]
        token = set_hermes_home_override(home)
        try:
            with install_and_reset_profile_terminal_scope(home):
                args = {"command": "printf 'non-sensitive probe'"}
                if kind == "promoted":
                    args["timeout"] = terminal_tool.FOREGROUND_MAX_TIMEOUT + 1
                else:
                    args["background"] = True
                if kind == "forged_host_grant":
                    args["_host_local"] = True
                result = json.loads(handle_function_call("terminal", args, task_id="same-task"))
                assert result["exit_code"] == 0, result
                assert result["session_id"] == "owned-process"
                assert calls[-1]["cwd"] == str(root)
                assert calls[-1]["env"].is_local
                assert calls[-1]["owner_task_id"] == "same-task"
        finally:
            reset_hermes_home_override(token)
    assert len(calls) == 3
    assert calls[0]["env"] is calls[2]["env"]
    assert calls[0]["env"] is not calls[1]["env"]


@pytest.mark.platforms("not macos")
def test_forged_model_native_pty_refuses_before_any_spawn(profiles, monkeypatch):
    from model_tools import handle_function_call
    from tools import process_registry as process_module
    def forbidden(*args, **kwargs):
        raise AssertionError("Unconfined native PTY reached a process launcher")
    monkeypatch.setattr(process_module.process_registry, "spawn_local", forbidden)
    monkeypatch.setattr(process_module.process_registry, "spawn_via_env", forbidden)
    result = json.loads(handle_function_call(
        "terminal", {"command": "python -i", "background": True, "pty": True, "_host_local": True},
        task_id="same-task",
    ))
    assert "Native PTY is unavailable" in result["error"]


def test_private_host_flag_and_native_pty_absent_from_model_schema():
    from tools.terminal_tool import TERMINAL_SCHEMA
    properties = TERMINAL_SCHEMA["parameters"]["properties"]
    assert "_host_local" not in properties and "pty" not in properties


@pytest.mark.platforms("not macos")
def test_failed_env_launch_is_reported_as_failure(profiles, monkeypatch):
    from model_tools import handle_function_call
    from tools import process_registry as process_module
    monkeypatch.setattr(process_module.process_registry, "spawn_via_env", lambda **kwargs:
        SimpleNamespace(id="failed", pid=None, exited=True, completion_reason="failed_start",
                        output_buffer="owned transport refused"))
    result = json.loads(handle_function_call(
        "terminal", {"command": "printf probe", "background": True}, task_id="same-task",
    ))
    assert result["exit_code"] == -1
    assert "Background launch failed" in result["error"]
    assert "session_id" not in result


@pytest.mark.platforms("macos")
@pytest.mark.parametrize("kind", ["explicit", "promoted", "forged_host_grant"])
def test_model_background_keeps_kernel_envelope_a_b_a(profiles, monkeypatch, kind):
    from model_tools import handle_function_call
    from tools import process_registry as process_module, terminal_tool
    from tools.terminal_scope import install_and_reset_profile_terminal_scope
    calls = []

    def capture(**kwargs):
        assert kwargs["confinement"] is not None
        calls.append(kwargs)
        return SimpleNamespace(id="owned-process", pid=1234, notify_on_complete=False,
                               watcher_platform="", watcher_interval=0)

    monkeypatch.setattr(process_module.process_registry, "spawn_local", capture)
    monkeypatch.setattr(process_module.process_registry, "spawn_via_env",
                        lambda **kwargs: pytest.fail("Mac model escaped the kernel envelope"))
    for index in (0, 1, 0):
        home, root = profiles[index]
        token = set_hermes_home_override(home)
        try:
            with install_and_reset_profile_terminal_scope(home):
                args = {"command": "printf 'non-sensitive probe'"}
                if kind == "promoted":
                    args["timeout"] = terminal_tool.FOREGROUND_MAX_TIMEOUT + 1
                else:
                    args["background"] = True
                if kind == "forged_host_grant":
                    args["_host_local"] = True
                result = json.loads(handle_function_call("terminal", args, task_id="same-task"))
                assert result["exit_code"] == 0, result
                assert calls[-1]["cwd"] == str(root)
                assert calls[-1]["confinement"].root == root.resolve()
                assert calls[-1]["owner_task_id"] == "same-task"
        finally:
            reset_hermes_home_override(token)
    assert len(calls) == 3
    assert calls[0]["confinement"] is calls[2]["confinement"]
    assert calls[0]["confinement"] is not calls[1]["confinement"]


@pytest.mark.platforms("macos")
def test_forged_host_flag_cannot_make_model_pty_unconfined(profiles, monkeypatch):
    from model_tools import handle_function_call
    from tools import process_registry as process_module
    calls = []

    def capture(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(id="confined-pty", pid=1234, notify_on_complete=False,
                               watcher_platform="", watcher_interval=0)

    monkeypatch.setattr(process_module.process_registry, "spawn_local", capture)
    result = json.loads(handle_function_call(
        "terminal", {"command": "python -i", "background": True, "pty": True, "_host_local": True},
        task_id="same-task"))
    assert result["exit_code"] == 0, result
    assert calls[0]["use_pty"] is True
    assert calls[0]["confinement"].root == profiles[0][1].resolve()


@pytest.mark.platforms("macos")
def test_confined_native_failure_has_no_transport_fallback(profiles, monkeypatch):
    from model_tools import handle_function_call
    from tools import process_registry as process_module

    def fail(**kwargs):
        assert kwargs["confinement"] is not None
        raise RuntimeError("owned confined transport refused")

    monkeypatch.setattr(process_module.process_registry, "spawn_local", fail)
    monkeypatch.setattr(process_module.process_registry, "spawn_via_env",
                        lambda **kwargs: pytest.fail("unrestricted fallback"))
    result = json.loads(handle_function_call(
        "terminal", {"command": "printf probe", "background": True}, task_id="same-task"))
    assert result["exit_code"] == -1
    assert "owned confined transport refused" in result["error"]
    assert "session_id" not in result
