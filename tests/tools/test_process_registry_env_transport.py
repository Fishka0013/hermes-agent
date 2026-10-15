"""Real env transport preserves completion status without redundant temp mkdir."""
import os
import subprocess

import pytest


@pytest.fixture
def transport(tmp_path):
    from tools.process_registry import ProcessRegistry
    directory = tmp_path / "existing transport 'directory"
    directory.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    mkdir = bin_dir / "mkdir"
    mkdir.write_text("#!/bin/sh\nexit 97\n")
    mkdir.chmod(0o755)
    child_env = dict(os.environ)
    child_env["PATH"] = str(bin_dir) + os.pathsep + child_env.get("PATH", "")
    class ShellTransport:
        def get_temp_dir(self):
            return str(directory)
        def execute(self, command, timeout=10, **kwargs):
            result = subprocess.run(
                ["/bin/bash", "-c", command], env=child_env, cwd=directory,
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
            )
            return {"output": result.stdout + result.stderr, "returncode": result.returncode}
    registry = ProcessRegistry()
    yield registry, ShellTransport(), directory
    registry.kill_started_since(
        "owned-transport", frozenset(), source="owned_test_fixture_cleanup"
    )


@pytest.mark.platforms("linux", "macos")
@pytest.mark.parametrize("exit_code", [0, 7])
def test_transport_returns_actual_completion_and_output(transport, exit_code):
    registry, env, directory = transport
    session = registry.spawn_via_env(
        env, f"printf 'owned completion output'; exit {exit_code}",
        cwd=str(directory), task_id="owned-transport", owner_task_id="owned-transport",
    )
    result = registry.wait(session.id, timeout=10)
    assert result["status"] == "exited", result
    assert result["exit_code"] == exit_code
    assert "owned completion output" in result["output"]
    assert session.owner_task_id == "owned-transport"
    assert session.pid_scope == "sandbox"
    assert (directory / f"hermes_bg_{session.id}.exit").read_text().strip() == str(exit_code)
