"""Real Mac Seatbelt acceptance through the registered terminal handler.

All content is generated under tmp_path; no personal-data probes, service
connections or model/provider requests. Requires a Mac context able to apply
Seatbelt (a nested developer sandbox must fail closed, not skip acceptance).
"""

import json
import os
from pathlib import Path
import shlex
import subprocess
from types import SimpleNamespace
import uuid

import pytest

from tools.environments.macos_confinement import MacOSTerminalConfinement, TerminalConfinementError

pytestmark = pytest.mark.platforms("macos")


@pytest.fixture
def terminal(tmp_path, monkeypatch):
    import tools.terminal_tool as tt
    from hermes_constants import get_hermes_home
    from tools.registry import registry
    from tools.terminal_scope import set_terminal_scope, reset_terminal_scope

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = uuid.uuid4().hex
    inside = workspace / "inside.txt"
    other = outside / "outside.txt"
    inside.write_text("INSIDE_" + marker)
    other.write_text("OUTSIDE_" + marker)
    home = get_hermes_home()
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(json.dumps({
        "security": {"model_workspace_root": str(workspace), "allow_lazy_installs": False},
        "terminal": {"backend": "local", "cwd": str(workspace), "home_mode": "profile",
                     "auto_source_bashrc": False, "shell_init_files": []},
    }))
    token = set_terminal_scope({"TERMINAL_ENV": "local", "TERMINAL_CWD": str(workspace)})
    task = "mac-confinement-" + marker
    monkeypatch.setenv("SHELL", "/bin/bash")
    tt._active_environments.clear()

    def call(command, **kwargs):
        result = registry.dispatch("terminal", {"command": command, "timeout": 10, **kwargs}, task_id=task)
        return json.loads(result) if isinstance(result, str) else result

    try:
        yield SimpleNamespace(call=call, root=workspace, inside=inside, outside=other, marker=marker, tt=tt)
    finally:
        from tools.process_registry import process_registry
        for session in list(process_registry._running.values()):
            if session.owner_task_id == task and session.pid and not session.exited:
                process_registry.kill_process(session.id)
        for env in list(tt._active_environments.values()):
            env.cleanup()
        tt._active_environments.clear()
        tt._last_activity.clear()
        reset_terminal_scope(token)


def _quote(path):
    return shlex.quote(str(path))


def _denied(result, marker):
    assert result.get("exit_code") not in (0, None), result
    assert "Operation not permitted" in result.get("output", ""), result
    assert marker not in result.get("output", "")


def test_inside_read(terminal):
    result = terminal.call("/bin/cat " + _quote(terminal.inside))
    assert result.get("exit_code") == 0, result
    assert "INSIDE_" + terminal.marker in result["output"]


def test_inside_write(terminal):
    target = terminal.root / "written.txt"
    result = terminal.call("printf '%s' CANARY_WRITE > " + _quote(target))
    assert result.get("exit_code") == 0, result
    assert target.read_text() == "CANARY_WRITE"


def test_outside_read(terminal):
    _denied(terminal.call("/bin/cat " + _quote(terminal.outside)), terminal.marker)


def test_outside_write(terminal):
    original = terminal.outside.read_text()
    _denied(terminal.call("printf BAD > " + _quote(terminal.outside)), terminal.marker)
    assert terminal.outside.read_text() == original


def _python_command(code):
    import sys
    return _quote(Path(sys._base_executable).resolve()) + " -I -S -B -c " + shlex.quote(code)


def test_child_python_read(terminal):
    code = f"from pathlib import Path; Path({str(terminal.outside)!r}).read_text()"
    _denied(terminal.call(_python_command(code)), terminal.marker)


def test_python_inside_positive_control(terminal):
    code = f"from pathlib import Path; print(Path({str(terminal.inside)!r}).read_text())"
    result = terminal.call(_python_command(code))
    assert result.get("exit_code") == 0, result
    assert "INSIDE_" + terminal.marker in result["output"]


def test_nested_shell(terminal):
    command = "/bin/bash --noprofile --norc -c " + shlex.quote("/bin/cat " + _quote(terminal.outside))
    _denied(terminal.call(command), terminal.marker)


def test_detached_python_descendant(terminal):
    code = ("import subprocess; raise SystemExit(subprocess.run("
            f"['/bin/cat', {str(terminal.outside)!r}], start_new_session=True).returncode)")
    _denied(terminal.call(_python_command(code)), terminal.marker)


def test_traversal(terminal):
    traversal = os.path.relpath(terminal.outside, terminal.root)
    _denied(terminal.call("/bin/cat " + shlex.quote(traversal)), terminal.marker)


def test_symlink(terminal):
    link = terminal.root / "escape.txt"
    link.symlink_to(terminal.outside)
    _denied(terminal.call("/bin/cat " + _quote(link)), terminal.marker)


def test_system_executable(terminal):
    result = terminal.call("/usr/bin/true")
    assert result.get("exit_code") == 0, result


def test_setup_failure_does_not_run_command(terminal, monkeypatch):
    from tools.environments import macos_confinement as mc
    attempted = []

    def fail(_self):
        attempted.append(1)
        raise TerminalConfinementError("Synthetic setup failure")

    monkeypatch.setattr(mc.MacOSTerminalConfinement, "verify_kernel", fail)
    target = terminal.root / "must-not-exist.txt"
    result = terminal.call("printf BAD > " + _quote(target))
    assert result.get("error"), result
    assert "setup failure" in result["error"]
    assert not target.exists()
    assert attempted == [1]


@pytest.mark.parametrize("pty", [False, True], ids=["background-pipe", "background-pty"])
def test_background_and_pty_keep_kernel_boundary(terminal, pty):
    from tools.process_registry import process_registry
    result = terminal.call("/bin/cat " + _quote(terminal.outside), background=True, pty=pty)
    assert result.get("session_id"), result
    session = process_registry._running[result["session_id"]]
    assert session._completion_event.wait(10), "bounded canary did not complete"
    assert session.exit_code != 0
    assert "Operation not permitted" in session.output_buffer
    assert terminal.marker not in session.output_buffer
    if pty:
        assert session._pty is not None, "PTY acceptance must not silently use pipe fallback"


def test_host_environment_and_init_hooks_are_not_inherited(terminal, monkeypatch):
    monkeypatch.setenv("UNKNOWN_TEST_SECRET", "CANARY_SECRET")
    monkeypatch.setenv("SSH_AUTH_SOCK", str(terminal.outside))
    monkeypatch.setenv("BASH_ENV", str(terminal.outside))
    code = "import os; assert 'UNKNOWN_TEST_SECRET' not in os.environ; assert 'SSH_AUTH_SOCK' not in os.environ; assert 'BASH_ENV' not in os.environ; print(os.environ['HOME']); print(os.environ['TMPDIR'])"
    result = terminal.call(_python_command(code))
    assert result.get("exit_code") == 0, result
    assert str(terminal.root / ".tmp" / "hermes-terminal") in result["output"]
    assert "CANARY_SECRET" not in result["output"]


def test_unset_workspace_fails_closed(terminal, monkeypatch):
    monkeypatch.setattr("hermes_cli.config.get_model_file_security_config", lambda: {"model_workspace_root": ""})
    result = terminal.call("/usr/bin/true")
    assert result.get("error"), result
    assert "workspace_root is unset" in result["error"]


def test_cached_workspace_binding_cannot_widen(terminal, monkeypatch):
    assert terminal.call("/usr/bin/true").get("exit_code") == 0
    monkeypatch.setattr("hermes_cli.config.get_model_file_security_config",
                        lambda: {"model_workspace_root": str(terminal.root.parent)})
    result = terminal.call("/bin/cat " + _quote(terminal.outside))
    assert result.get("exit_code") == 126, result
    assert result.get("status") == "blocked"
    assert "binding changed" in result["error"]


def test_script_guard_does_not_read_outside_on_host(terminal, monkeypatch):
    from tools.terminal_tool_guards import _read_script_for_guard
    assert terminal.call("/usr/bin/true").get("exit_code") == 0
    env = next(iter(terminal.tt._active_environments.values()))
    reads = []
    original = Path.read_bytes

    def tracked(path, *args, **kwargs):
        reads.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", tracked)
    assert _read_script_for_guard(env, str(terminal.root), str(terminal.outside), 100) is None
    assert terminal.outside not in reads


def test_script_guard_inside_positive_control(terminal):
    from tools.terminal_tool_guards import _read_script_for_guard
    script = terminal.root / "inside.sh"
    script.write_text("printf 'CANARY_SCRIPT'\n")
    assert terminal.call("/usr/bin/true").get("exit_code") == 0
    env = next(iter(terminal.tt._active_environments.values()))
    assert _read_script_for_guard(env, str(terminal.root), str(script), 100) == script.read_text()


def test_model_arguments_cannot_select_host_authority(terminal):
    result = terminal.call("/bin/cat " + _quote(terminal.outside), _host_local=True,
                           local_config={"model_terminal": False})
    _denied(result, terminal.marker)


def test_trusted_host_builder_keeps_runtime_authority(terminal, monkeypatch):
    from tools import terminal_tool_backends as backends
    received = []
    monkeypatch.setattr(backends, "_LocalEnvironment", lambda **kw: received.append(kw) or SimpleNamespace(**kw))
    # Trusted internal opt-out is not in the model-facing tool schema/handler.
    backends._create_environment("local", "", str(terminal.root), 10,
                                 local_config={"model_terminal": False})
    assert received == [{"cwd": str(terminal.root), "timeout": 10, "persistent": True}]


def test_scratch_symlink_creation_fails_closed(terminal):
    (terminal.root / ".tmp").symlink_to(terminal.outside.parent, target_is_directory=True)
    original_entries = set(terminal.outside.parent.iterdir())
    result = terminal.call("/usr/bin/true")
    assert result.get("error"), result
    assert set(terminal.outside.parent.iterdir()) == original_entries


def test_readonly_component_hardlink_cannot_widen_write_authority(terminal):
    # Generated read-only component, NOT a real interpreter/library target.
    component = terminal.outside.parent / "readonly-component.txt"
    component.write_text("CANARY_RUNTIME")
    confinement = MacOSTerminalConfinement()
    confinement.profile += f"\n(allow file-read* (literal {json.dumps(str(component))}))\n"
    try:
        argv, env, cwd = confinement.launch("/bin/cat " + _quote(component), str(terminal.root))
        read = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True, timeout=10)
        assert read.returncode == 0, read.stderr
        assert read.stdout == "CANARY_RUNTIME"
        link = terminal.root / "component-link.txt"
        argv, env, cwd = confinement.launch("/bin/ln " + _quote(component) + " " + _quote(link), str(terminal.root))
        denied = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True, timeout=10)
        assert denied.returncode != 0
        assert "Operation not permitted" in denied.stderr
        assert not link.exists()
        assert component.read_text() == "CANARY_RUNTIME"
    finally:
        confinement.cleanup()
