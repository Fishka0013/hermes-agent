"""SEC-3 integration acceptance uses real policy/config and producer publication boundaries."""
import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from agent import model_file_policy as policy


@pytest.fixture
def profile(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.yaml").write_text(json.dumps({
        "security": {
            "model_workspace_root": str(root),
            "model_staging_max_file_bytes": 1048576,
            "model_staging_session_quota_bytes": 4194304,
            "model_staging_profile_quota_bytes": 8388608,
            "model_staging_ttl_seconds": 60,
        },
        "terminal": {"cwd": str(tmp_path / "outside-cwd")},
    }))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    cache = home / "cache"
    cache.mkdir()
    source = cache / "artifact.png"
    source.write_bytes(b"non-sensitive artifact")
    return root, home, source


@pytest.mark.parametrize("raw", [r"\\?\UNC\attacker\share\secret", r"\\attacker\share\secret", r"\??\UNC\attacker\share\secret"])
@pytest.mark.parametrize("resolver", [policy.resolve_model_read_path, policy.resolve_model_write_path])
def test_namespace_rejected_before_target_resolution(profile, monkeypatch, raw, resolver):
    from urllib.parse import quote
    original = Path.resolve
    def no_remote_resolution(path, *args, **kwargs):
        assert "attacker" not in str(path), "untrusted namespace reached filesystem resolution"
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "resolve", no_remote_resolution)
    for value in (raw, quote(raw, safe="")):
        with pytest.raises(policy.ModelFilePolicyError, match="namespace"):
            resolver(value)


@pytest.mark.parametrize("producer", ["image", "tts", "browser", "inbound"])
def test_producer_publication_is_inside_profile_root(profile, monkeypatch, producer):
    root, home, source = profile
    assert policy.get_model_workspace_root() == root
    with pytest.raises(policy.ModelFilePolicyError):
        policy.resolve_model_read_path(source)
    if producer == "image":
        from tools import image_generation_tool as image
        monkeypatch.setattr(image, "_active_terminal_env", lambda task_id: None)
        payload = json.loads(image._postprocess_image_generate_result(
            json.dumps({"success": True, "image": str(source)}), task_id="acceptance"))
        published = Path(payload["image"])
    elif producer == "tts":
        from tools.tts_tool import _publish_tts_paths_for_model
        published = Path(_publish_tts_paths_for_model([str(source)], "acceptance")[0])
    elif producer == "browser":
        from tools.browser_tool_vision import _publish_screenshot_for_model
        published = _publish_screenshot_for_model(source)
    else:
        from gateway.run_inbound import GatewayInboundMixin
        event = SimpleNamespace(media_urls=[str(source)], media_types=["image/png"],
                                media_text_inlined=[], message_id="acceptance")
        GatewayInboundMixin._stage_inbound_media_for_model(
            event, SimpleNamespace(platform="test"), "acceptance")
        published = Path(event.media_urls[0])
        published.relative_to(root / ".tmp" / "inbound")
    published.relative_to(root / ".tmp")
    assert published.read_bytes() == source.read_bytes()
    assert published.with_name(published.name + ".receipt.json").is_file()
    assert not list(root.rglob(".*.tmp"))


def test_outbound_legacy_permissive_roots_do_not_grant_authority(profile, monkeypatch):
    root, home, outside = profile
    from gateway.platforms import base
    monkeypatch.setattr(base, "_media_delivery_allowed_roots", lambda: [home / "cache", root])
    monkeypatch.setattr("gateway.media_policy.media_delivery_strict", lambda: False)
    assert base.validate_media_delivery_path(str(outside)) is None
    assert base.validate_media_delivery_path("file://" + str(outside)) is None
    staged = policy.publish_internal_artifact_for_model(
        policy.make_internal_artifact_source(outside, source_class="runtime-test"))
    assert base.validate_media_delivery_path(str(staged.path)) == str(staged.path)


def test_resolution_and_profile_switch_do_not_widen_root(tmp_path, monkeypatch):
    from hermes_cli.config import get_model_file_security_config
    homes = []
    for label in ("a", "b"):
        home = tmp_path / label
        home.mkdir()
        root = home / "workspace"
        root.mkdir()
        project = root / "project"
        project.mkdir()
        (project / "inside.txt").write_text(label)
        (home / "config.yaml").write_text(json.dumps({
            "security": {"model_workspace_root": str(root)},
            "terminal": {"cwd": str(tmp_path)},
        }))
        homes.append((home, root, project))
    for home, root, project in (homes[0], homes[1], homes[0]):
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        assert get_model_file_security_config()["model_workspace_root"] == str(root)
        assert policy.get_model_workspace_root() == root
        assert policy.resolve_model_read_path("inside.txt", resolution_base=project) == project / "inside.txt"
        with pytest.raises(policy.ModelFilePolicyError):
            policy.validate_resolution_base(tmp_path)
        with pytest.raises(policy.ModelFilePolicyError):
            policy.resolve_model_read_path(homes[1 if home == homes[0][0] else 0][2] / "inside.txt")
        for value in ("../outside", str(root) + "-evil/file"):
            with pytest.raises(policy.ModelFilePolicyError):
                policy.resolve_model_write_path(value)


@pytest.mark.parametrize("case", ["outside-read", "outside-write", "traversal", "prefix",
                                  "symlink-read", "symlink-write", "encoded", "null"])
def test_model_read_write_escape_is_blocked(profile, case):
    from urllib.parse import quote
    root, home, outside = profile
    original = outside.read_bytes()
    candidate = outside
    resolver = policy.resolve_model_read_path
    if case == "outside-write":
        resolver = policy.resolve_model_write_path
    if case == "traversal":
        candidate = root / ".." / "home" / "cache" / "artifact.png"
    if case == "prefix":
        sibling = root.with_name(root.name + "-evil")
        sibling.mkdir()
        candidate = sibling / "artifact.png"
        candidate.write_bytes(b"prefix sentinel")
    if case in ("symlink-read", "symlink-write"):
        candidate = root / "escape"
        candidate.symlink_to(outside)
        if case == "symlink-write":
            resolver = policy.resolve_model_write_path
    if case == "encoded":
        candidate = quote(str(outside), safe="")
    if case == "null":
        candidate = "\x00"
    with pytest.raises(policy.ModelFilePolicyError):
        resolver(candidate)
    assert outside.read_bytes() == original


@pytest.mark.parametrize("configured_root", ["unset", "relative", "missing", "file"])
def test_invalid_profile_root_fails_closed(profile, configured_root):
    root, home, source = profile
    values = {"unset": "", "relative": "workspace", "missing": str(home / "missing"),
              "file": str(source)}
    (home / "config.yaml").write_text(json.dumps({
        "security": {"model_workspace_root": values[configured_root]}}))
    with pytest.raises(policy.ModelFilePolicyError):
        policy.resolve_model_read_path(source)
    with pytest.raises(policy.ModelFilePolicyError):
        policy.resolve_model_write_path(root / "new.txt")


def test_native_image_conversion_blocks_before_read(profile, monkeypatch):
    root, home, source = profile
    from agent.image_routing import _file_to_data_url
    real_read = Path.read_bytes
    attempts = []
    def tracked_read(path):
        if path == source:
            attempts.append(path)
        return real_read(path)
    monkeypatch.setattr(Path, "read_bytes", tracked_read)
    assert _file_to_data_url(source) is None
    assert attempts == []


def test_profile_context_perimeter_a_b_a(tmp_path, monkeypatch):
    """A served profile overrides launch env without borrowing another root."""
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override
    from hermes_cli.config import get_model_file_security_config
    homes = []
    for label in ("launch", "served"):
        home = tmp_path / label
        home.mkdir()
        root = home / "workspace"
        root.mkdir()
        (root / "source.txt").write_text(label)
        (home / "config.yaml").write_text(json.dumps({
            "security": {"model_workspace_root": str(root)},
            "terminal": {"cwd": str(tmp_path)},
        }))
        homes.append((home, root))
    monkeypatch.setenv("HERMES_HOME", str(homes[0][0]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: homes[0][0]))
    monkeypatch.setenv("MODEL_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
    for i in (0, 1, 0):
        home, root = homes[i]
        token = set_hermes_home_override(home)
        try:
            assert get_model_file_security_config()["model_workspace_root"] == str(root)
            assert policy.resolve_model_read_path(root / "source.txt").read_text() == ("launch" if i == 0 else "served")
            with pytest.raises(policy.ModelFilePolicyError):
                policy.resolve_model_read_path(homes[1 - i][1] / "source.txt")
            with pytest.raises(policy.ModelFilePolicyError):
                policy.resolve_model_write_path(tmp_path / "outside.txt")
        finally:
            reset_hermes_home_override(token)


def test_unreadable_config_cannot_reuse_old_file_authority(profile):
    root, home, source = profile
    assert policy.get_model_workspace_root() == root
    (home / "config.yaml").write_text("security: [")
    with pytest.raises(policy.ModelFilePolicyError):
        policy.resolve_model_write_path(root / "target.txt")
    assert not (root / "target.txt").exists()
