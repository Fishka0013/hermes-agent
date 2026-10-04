"""Desktop runtime uploads reach model consumers through the owning profile's Root."""
import json
from pathlib import Path

import pytest

from tui_gateway import server
from agent import model_file_policy as policy
from agent.image_routing import build_native_content_parts


@pytest.fixture
def profiles(tmp_path, monkeypatch):
    rows = []
    for name in ("launch", "secondary"):
        home = tmp_path / name
        cache = home / "images"
        cache.mkdir(parents=True)
        root = tmp_path / (name + "-workspace")
        root.mkdir()
        (home / "config.yaml").write_text(json.dumps({"security": {"model_workspace_root": str(root)},
            "terminal": {"backend": "local", "cwd": str(tmp_path)}}))
        source = cache / "tiny.png"
        source.write_bytes(bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000002000100ffff03000006000557bfabd40000000049454e44ae426082"))
        rows.append((home, root, source))
    monkeypatch.setenv("HERMES_HOME", str(rows[0][0]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: rows[0][0]))
    monkeypatch.setattr(server, "_hermes_home", rows[0][0])
    return rows


def test_desktop_image_a_b_a_publishes_before_native_model_bytes(profiles):
    for home, root, source in (profiles[0], profiles[1], profiles[0]):
        session = {"profile_home": str(home), "session_key": home.name}
        images = server._publish_turn_image_attachments(session, [str(source)])
        assert len(images) == 1
        path = Path(images[0])
        path.relative_to(root / ".tmp" / "inbound")
        receipt = json.loads(path.with_name(path.name + ".receipt.json").read_text())
        assert receipt["source_class"] == "desktop-user-attachment"
        assert receipt["session_id"] == home.name
        assert path.read_bytes() == source.read_bytes()
        with server._session_profile_runtime_scope(session):
            with pytest.raises(policy.ModelFilePolicyError):
                policy.resolve_model_read_path(source)
            parts, skipped = build_native_content_parts("inspect", images)
            assert not skipped and any(p.get("type") == "image_url" for p in parts)
            other = profiles[1 if home == profiles[0][0] else 0][1]
            with pytest.raises(policy.ModelFilePolicyError):
                policy.resolve_model_write_path(other / "cross-profile.txt")


def test_missing_root_or_unsafe_staging_never_falls_back_to_cache(profiles, tmp_path):
    home, root, source = profiles[0]
    session = {"profile_home": str(home), "session_key": "unsafe"}
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / ".tmp").symlink_to(outside, target_is_directory=True)
    assert server._publish_turn_image_attachments(session, [str(source)]) == []
    assert not list(outside.iterdir())
    (root / ".tmp").unlink()
    (home / "config.yaml").write_text(json.dumps({"security": {"model_workspace_root": ""}}))
    assert server._publish_turn_image_attachments(session, [str(source)]) == []


def test_file_runtime_storage_and_model_reference_have_separate_authority(profiles):
    home, root, source = profiles[1]
    session = {"profile_home": str(home), "session_key": "file"}
    staged = server._publish_session_attachment_for_model(session, source)
    assert source.is_file() and staged != source
    staged.relative_to(root)
    with server._session_profile_runtime_scope(session):
        assert policy.resolve_model_read_path(staged) == staged
        with pytest.raises(policy.ModelFilePolicyError):
            policy.resolve_model_read_path(source)
