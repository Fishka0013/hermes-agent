"""Tests for video attachment context notes in gateway turns."""

from pathlib import Path
from unittest.mock import patch

import pytest

from gateway.config import GatewayConfig, Platform
from gateway.platforms.event import MessageEvent, MessageType
from gateway.run import GatewayRunner
from gateway.session import SessionSource


def _make_runner() -> GatewayRunner:
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = GatewayConfig()
    runner.adapters = {}
    runner._has_setup_skill = lambda: False
    return runner


@pytest.mark.asyncio
async def test_video_attachment_adds_path_note_not_document_note(tmp_path, monkeypatch):
    from gateway.run import _build_media_placeholder

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
    raw = tmp_path / "cache" / "video_clip.mp4"
    raw.parent.mkdir()
    raw.write_bytes(b"video")

    runner = _make_runner()
    source = SessionSource(platform=Platform.SLACK, chat_id="D123", chat_type="dm")
    event = MessageEvent(
        text="what happens here?",
        message_type=MessageType.VIDEO,
        source=source,
        media_urls=[str(raw)],
        media_types=["video/mp4"],
    )

    with patch(
        "tools.credential_files.to_agent_visible_cache_path",
        side_effect=lambda path: path,
    ):
        result = await runner._prepare_inbound_message_text(
            event=event,
            source=source,
            history=[],
        )

    staged = event.media_urls[0]
    assert Path(staged).is_relative_to(root) and Path(staged).is_file()
    assert staged in result
    assert str(raw) not in result
    assert "The user sent a document" not in result
    assert staged in _build_media_placeholder(event)
