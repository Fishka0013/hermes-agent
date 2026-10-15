"""Actual file-tool dispatch obeys the active profile's ordinary file perimeter."""
import json
from pathlib import Path

import pytest

from hermes_constants import set_hermes_home_override, reset_hermes_home_override


@pytest.fixture
def file_profiles(tmp_path, monkeypatch):
    profiles = []
    for label in ("a", "b"):
        home = tmp_path / ("profile-" + label)
        home.mkdir()
        root = tmp_path / ("workspace-" + label)
        root.mkdir()
        (root / "source.txt").write_text(label)
        (home / "config.yaml").write_text(json.dumps({
            "security": {"model_workspace_root": str(root)},
            "terminal": {"env": "local", "cwd": str(root)},
        }))
        profiles.append((home, root))
    monkeypatch.setenv("HERMES_HOME", str(profiles[0][0]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: profiles[0][0]))
    outside = tmp_path / "outside.txt"
    outside.write_text("outside sentinel")
    return profiles, outside


@pytest.mark.parametrize("operation", ["read", "write", "replace", "move", "search"])
def test_registered_files_block_before_backend(file_profiles, monkeypatch, operation):
    from model_tools import handle_function_call
    from tools import file_tools
    profiles, outside = file_profiles
    root = profiles[0][1]
    calls = []
    def forbidden_backend(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("A rejected source must never reach file I/O")
    monkeypatch.setattr(file_tools, "_get_file_ops", forbidden_backend)
    cases = {
        "read": ("read_file", {"path": str(outside)}),
        "write": ("write_file", {"path": str(outside), "content": "changed"}),
        "replace": ("patch", {"mode": "replace", "path": str(outside), "old_string": "outside", "new_string": "changed"}),
        "move": ("patch", {"mode": "patch", "patch": f"*** Begin Patch\n*** Move File: {root / 'source.txt'} -> {outside}\n*** End Patch"}),
        "search": ("search_files", {"pattern": "sentinel", "path": str(outside.parent)}),
    }
    token = set_hermes_home_override(profiles[0][0])
    try:
        name, args = cases[operation]
        result = json.loads(handle_function_call(name, args, task_id="sec3-file-boundary"))
    finally:
        reset_hermes_home_override(token)
    assert "error" in result and "MODEL_WORKSPACE_ROOT" in result["error"]
    assert calls == []
    assert outside.read_text() == "outside sentinel"
    assert (root / "source.txt").read_text() == "a"


def test_registered_file_profile_scope_a_b_a(file_profiles):
    from model_tools import handle_function_call
    from tools.terminal_scope import install_and_reset_profile_terminal_scope
    profiles, outside = file_profiles
    for i in (0, 1, 0):
        home, root = profiles[i]
        token = set_hermes_home_override(home)
        try:
            args = {"path": str(root / "result.txt"), "content": "a" if i == 0 else "b"}
            with install_and_reset_profile_terminal_scope(home):
                result = json.loads(handle_function_call("write_file", args, task_id="sec3-file-profile"))
            assert "error" not in result, result
            assert (root / "result.txt").read_text() == args["content"]
            with install_and_reset_profile_terminal_scope(home):
                result = json.loads(handle_function_call("read_file", {"path": str(root / "result.txt")}, task_id="sec3-file-profile"))
            assert "error" not in result and args["content"] in result["content"], result
            result = json.loads(handle_function_call("read_file", {"path": str(profiles[1-i][1] / "source.txt")}, task_id="sec3-file-profile"))
            assert "error" in result and "MODEL_WORKSPACE_ROOT" in result["error"]
        finally:
            reset_hermes_home_override(token)
    assert outside.read_text() == "outside sentinel"


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("shape", ["inside_link_to_outside", "outside_link_to_inside", "traversal_header"])
@pytest.mark.parametrize("operation", ["Delete", "Move"])
def test_v4a_entry_and_target_are_confined_before_backend(file_profiles, monkeypatch, shape, operation):
    from model_tools import handle_function_call
    from tools import file_tools
    profiles, outside = file_profiles
    root = profiles[0][1]
    if shape == "inside_link_to_outside":
        entry = root / "escape.txt"
        entry.symlink_to(outside)
    elif shape == "outside_link_to_inside":
        entry = outside.parent / "outside-link.txt"
        entry.symlink_to(root / "source.txt")
    else:
        entry = root / ".." / root.name / "source.txt"
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("forbidden patch reached backend")
    monkeypatch.setattr(file_tools, "_get_file_ops", forbidden)
    header = f"*** {operation} File: {entry}"
    if operation == "Move":
        header += f" -> {root / 'destination.txt'}"
    result = json.loads(handle_function_call("patch", {"mode": "patch", "patch": f"*** Begin Patch\n{header}\n*** End Patch"}))
    assert "error" in result and not calls
    assert outside.read_text() == "outside sentinel"
    assert (root / "source.txt").read_text() == "a"
    if shape != "traversal_header":
        assert entry.is_symlink()
    assert not (root / "destination.txt").exists()

@pytest.mark.platforms("macos")
def test_registered_filename_search_inside_authorized_workspace(file_profiles, monkeypatch):
    """R1: registered target=files works through the real confined local backend."""
    from model_tools import handle_function_call
    from tools import file_tools
    from tools.environments.local import LocalEnvironment
    from tools.environments.macos_confinement import MacOSTerminalConfinement
    from tools.file_operations import ShellFileOperations

    profiles, _outside = file_profiles
    home, root = profiles[0]
    wanted = root / "r1-existing-name.txt"
    wanted.write_text("R1_CONTENT_SENTINEL", encoding="utf-8")

    token = set_hermes_home_override(home)
    env = None
    try:
        confinement = MacOSTerminalConfinement()
        env = LocalEnvironment(cwd=str(root), confinement=confinement)
        ops = ShellFileOperations(env)
        monkeypatch.setattr(file_tools, "_get_file_ops", lambda task_id="default": ops)

        result = json.loads(handle_function_call(
            "search_files",
            {"pattern": wanted.name, "target": "files", "path": str(root)},
            task_id="r1-filename-search",
        ))
        content = json.loads(handle_function_call(
            "search_files",
            {"pattern": "R1_CONTENT_SENTINEL", "target": "content", "path": str(root)},
            task_id="r1-content-search",
        ))
    finally:
        if env is not None:
            env.cleanup()
        reset_hermes_home_override(token)

    assert "error" not in result, result
    assert str(wanted) in json.dumps(result), result
    assert "error" not in content, content
    assert "R1_CONTENT_SENTINEL" in json.dumps(content), content


@pytest.mark.platforms("macos")
def test_registered_filename_search_cannot_escape_authorized_workspace(file_profiles, monkeypatch):
    from model_tools import handle_function_call
    from tools import file_tools

    profiles, outside = file_profiles
    calls = []

    def forbidden_backend(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("escaped filename search reached backend")

    monkeypatch.setattr(file_tools, "_get_file_ops", forbidden_backend)
    result = json.loads(handle_function_call(
        "search_files",
        {"pattern": outside.name, "target": "files", "path": str(outside.parent)},
        task_id="r1-filename-escape",
    ))
    assert "error" in result and "MODEL_WORKSPACE_ROOT" in result["error"]
    assert calls == []
