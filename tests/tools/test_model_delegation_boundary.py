"""Current profile and resolved child surface preserve SEC-3 authority boundaries."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_constants import set_hermes_home_override, reset_hermes_home_override


@pytest.fixture
def profiles(tmp_path, monkeypatch):
    homes = []
    terminal = tmp_path / "terminal-outside-model-root"
    terminal.mkdir()
    for label in ("a", "b"):
        home = tmp_path / ("home-" + label)
        home.mkdir()
        root = tmp_path / ("workspace-" + label)
        root.mkdir()
        (root / "image.png").write_bytes(b"test image")
        (home / "config.yaml").write_text(json.dumps({
            "security": {"model_workspace_root": str(root)},
            "terminal": {"env": "local", "cwd": str(terminal)},
        }))
        (home / "profile.yaml").write_text("role: setup\n")
        homes.append((home, root))
    monkeypatch.setenv("HERMES_HOME", str(homes[0][0]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: homes[0][0]))
    return homes


def test_real_profile_images_a_b_a_independent_of_terminal_cwd(profiles):
    from tools.delegate_tool_tasks import _coerce_task_images
    from tools.terminal_scope import install_and_reset_profile_terminal_scope
    for i in (0, 1, 0):
        home, root = profiles[i]
        token = set_hermes_home_override(home)
        try:
            with install_and_reset_profile_terminal_scope(home):
                images, error = _coerce_task_images(
                    [{"goal": "inspect", "images": [str(root / "image.png")]}], None,
                    task_id="same-parent-task")
                assert error is None and images == [[str(root / "image.png")]]
                images, error = _coerce_task_images(
                    [{"goal": "inspect", "images": [str(profiles[1-i][1] / "image.png")]}], None,
                    task_id="same-parent-task")
                assert images == [] and "image path blocked" in error
        finally:
            reset_hermes_home_override(token)


@pytest.mark.parametrize("role", ["worker", "orchestrator"])
@pytest.mark.parametrize("explicit", [False, True])
def test_resolved_child_cannot_gain_admin_vault_or_desktop_from_parent(profiles, role, explicit):
    import model_tools
    from tools.delegate_tool_toolsets import _resolve_child_toolsets
    parent = SimpleNamespace(
        enabled_toolsets=["hermes-cli", "computer_use", "setup", "connections", "discord_admin", "browser_vault", "code_execution"],
        disabled_toolsets=[],
    )
    requested = list(parent.enabled_toolsets) if explicit else None
    enabled, disabled = _resolve_child_toolsets(parent, requested, role)
    selected = model_tools._select_tool_names(enabled, disabled, True)
    assert "read_file" in selected and "terminal" in selected
    denied = {"computer_use", "execute_code", "manage_catalog", "manage_connections", "discord_admin",
              "browser_vault_list", "browser_vault_unlock", "browser_vault_fill",
              "browser_vault_save_login", "browser_vault_enter_code"}
    assert not (selected & denied)
