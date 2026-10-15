"""Unfenced Python is withheld from model schemas and forged dispatch before spawn."""
import json
from pathlib import Path

import pytest

from hermes_constants import set_hermes_home_override, reset_hermes_home_override


@pytest.fixture
def profiles(tmp_path, monkeypatch):
    homes = []
    for label in ("a", "b"):
        home = tmp_path / ("profile-" + label)
        root = tmp_path / ("workspace-" + label)
        home.mkdir()
        root.mkdir()
        (home / "config.yaml").write_text(json.dumps({
            "security": {"model_workspace_root": str(root)},
            "approvals": {"mode": "off"},
        }))
        homes.append(home)
    monkeypatch.setenv("HERMES_HOME", str(homes[0]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: homes[0]))
    return homes


@pytest.mark.parametrize("toolsets", [["code_execution"], ["hermes-cli"], None])
def test_no_python_model_schema_a_b_a(profiles, toolsets):
    from model_tools import get_tool_definitions
    for index in (0, 1, 0):
        token = set_hermes_home_override(profiles[index])
        try:
            definitions = get_tool_definitions(
                enabled_toolsets=toolsets, quiet_mode=True,
                skip_tool_search_assembly=True,
            )
            assert "execute_code" not in {d["function"]["name"] for d in definitions}
        finally:
            reset_hermes_home_override(token)


@pytest.mark.parametrize("route", ["model_dispatch", "registry_dispatch"])
def test_forged_code_rejected_before_execution_a_b_a(profiles, monkeypatch, route):
    from model_tools import handle_function_call
    from tools.registry import registry
    from tools import code_execution_tool
    called = []
    def forbidden(*args, **kwargs):
        called.append(True)
        raise AssertionError("Model code reached a Python executor")
    monkeypatch.setattr(code_execution_tool, "execute_code", forbidden)
    for index in (0, 1, 0):
        token = set_hermes_home_override(profiles[index])
        try:
            dispatch = handle_function_call if route == "model_dispatch" else registry.dispatch
            result = json.loads(dispatch(
                "execute_code", {"code": "import pathlib; print(pathlib.Path.home())", "reset": True},
                task_id="same-model-task", enabled_tools=["execute_code", "terminal", "read_file"],
            ))
            assert "not confined by MODEL_WORKSPACE_ROOT" in result["error"]
        finally:
            reset_hermes_home_override(token)
    assert not called
