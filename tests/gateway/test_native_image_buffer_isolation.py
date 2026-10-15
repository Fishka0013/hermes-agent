from pathlib import Path
import json

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.event import MessageEvent, MessageType
from gateway.run import GatewayRunner
from gateway.session import SessionSource, build_session_key



def _set_model_root(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setattr(
        "hermes_cli.config.get_model_file_security_config",
        lambda: {
            "model_workspace_root": str(root),
            "model_staging_max_file_bytes": 50 * 1024 * 1024,
            "model_staging_session_quota_bytes": 256 * 1024 * 1024,
            "model_staging_profile_quota_bytes": 1024 * 1024 * 1024,
            "model_staging_ttl_seconds": 86400,
        },
    )
    return root


def _raw_image(tmp_path, name):
    p = tmp_path / "cache" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(b"png")
    return p

def _make_runner() -> GatewayRunner:
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = GatewayConfig(
        platforms={Platform.TELEGRAM: PlatformConfig(enabled=True, token="fake")},
    )
    runner.adapters = {}
    runner._model = "openai/gpt-4.1-mini"
    runner._base_url = None
    runner._decide_image_input_mode = lambda **_: "native"
    return runner


def _source(chat_id: str) -> SessionSource:
    return SessionSource(
        platform=Platform.TELEGRAM,
        chat_id=chat_id,
        chat_type="private",
        user_name=f"user-{chat_id}",
    )


def _image_event(source: SessionSource, path: str) -> MessageEvent:
    return MessageEvent(
        text="see image",
        message_type=MessageType.PHOTO,
        source=source,
        media_urls=[path],
        media_types=["image/png"],
    )


@pytest.mark.asyncio
async def test_real_profile_scoped_inbound_publication_a_b_a(tmp_path, monkeypatch):
    """Owning profile survives the gateway's thread boundary; launch A cannot leak into B."""
    from agent.model_file_policy import resolve_model_read_path, ModelFilePolicyError
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override
    homes = []
    for label in ("a", "b"):
        home = tmp_path / ("profile-" + label)
        home.mkdir()
        root = tmp_path / ("workspace-" + label)
        root.mkdir()
        (home / "config.yaml").write_text(json.dumps({"security": {"model_workspace_root": str(root)}}))
        homes.append((home, root))
    monkeypatch.setenv("HERMES_HOME", str(homes[0][0]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: homes[0][0]))
    runner = _make_runner()
    runner.config.multiplex_profiles = True
    runner._resolve_profile_home_for_source = lambda source: homes[int(source.chat_id)][0]
    published = []
    for i in (0, 1, 0):
        source = _source(str(i))
        raw = _raw_image(tmp_path, "profile-" + str(i) + "-" + str(len(published)) + ".png")
        event = _image_event(source, str(raw))
        await runner._prepare_profile_scoped_inbound_message_text(event=event, source=source, history=[])
        path = Path(event.media_urls[0])
        assert path.is_relative_to(homes[i][1] / ".tmp" / "inbound")
        assert path.read_bytes() == raw.read_bytes()
        assert Path(str(path) + ".receipt.json").is_file()
        token = set_hermes_home_override(homes[1-i][0])
        try:
            with pytest.raises(ModelFilePolicyError):
                resolve_model_read_path(path)
        finally:
            reset_hermes_home_override(token)
        published.append(path)


@pytest.mark.asyncio
async def test_native_image_buffer_isolated_per_session(tmp_path, monkeypatch):
    root = _set_model_root(tmp_path, monkeypatch)
    runner = _make_runner()
    source_a = _source("chat-a")
    source_b = _source("chat-b")
    event_a = _image_event(source_a, str(_raw_image(tmp_path, "a.png")))
    event_b = _image_event(source_b, str(_raw_image(tmp_path, "b.png")))

    await runner._prepare_inbound_message_text(event=event_a, source=source_a, history=[])
    await runner._prepare_inbound_message_text(event=event_b, source=source_b, history=[])

    staged_a = event_a.media_urls[0]
    staged_b = event_b.media_urls[0]
    assert Path(staged_a).is_relative_to(root) and Path(staged_a).is_file()
    assert Path(staged_b).is_relative_to(root) and Path(staged_b).is_file()
    assert runner._consume_pending_native_image_paths(build_session_key(source_a)) == [staged_a]
    assert runner._consume_pending_native_image_paths(build_session_key(source_b)) == [staged_b]


@pytest.mark.asyncio
async def test_native_image_buffer_not_cleared_by_other_sessions_without_images(tmp_path, monkeypatch):
    root = _set_model_root(tmp_path, monkeypatch)
    runner = _make_runner()
    source_a = _source("chat-a")
    source_b = _source("chat-b")
    event_a = _image_event(source_a, str(_raw_image(tmp_path, "a.png")))

    await runner._prepare_inbound_message_text(event=event_a, source=source_a, history=[])
    await runner._prepare_inbound_message_text(
        event=MessageEvent(text="plain text", source=source_b), source=source_b, history=[])

    staged_a = event_a.media_urls[0]
    assert Path(staged_a).is_relative_to(root) and Path(staged_a).is_file()
    assert runner._consume_pending_native_image_paths(build_session_key(source_a)) == [staged_a]
    assert runner._consume_pending_native_image_paths(build_session_key(source_b)) == []


@pytest.mark.asyncio
async def test_native_image_buffer_uses_resolved_session_key_when_provided(tmp_path, monkeypatch):
    root = _set_model_root(tmp_path, monkeypatch)
    runner = _make_runner()
    source = _source("chat-a")
    runner._session_key_for_source = lambda _source: "source-derived-key"
    event = _image_event(source, str(_raw_image(tmp_path, "a.png")))

    await runner._prepare_inbound_message_text(
        event=event, source=source, history=[], session_key="canonical-session-key")

    staged = event.media_urls[0]
    assert Path(staged).is_relative_to(root) and Path(staged).is_file()
    assert runner._consume_pending_native_image_paths("source-derived-key") == []
    assert runner._consume_pending_native_image_paths("canonical-session-key") == [staged]
