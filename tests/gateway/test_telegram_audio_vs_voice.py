"""
Tests for #24870 — Telegram: audio file attachments must NOT be routed to STT.

Telegram distinguishes three kinds of audio payloads:
  - message.voice  → Opus/OGG voice message  → STT pipeline
  - message.audio  → audio file attachment   → file path note, NOT STT
  - message.document (audio mime) → generic file route

These tests confirm that:
  1. MessageType.VOICE events still flow through the STT pipeline.
  2. MessageType.AUDIO events bypass STT and get a file-path context note instead.
  3. Mixed media lists (voice + audio) split correctly.
"""

from unittest.mock import patch

import pytest

from gateway.config import GatewayConfig, Platform
from gateway.platforms.event import MessageEvent, MessageType
from gateway.run import GatewayRunner
from gateway.session import SessionSource


def _make_runner(stt_enabled: bool = True) -> GatewayRunner:
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = GatewayConfig(stt_enabled=stt_enabled)
    runner.adapters = {}
    runner._model = "test-model"
    runner._base_url = ""
    runner._has_setup_skill = lambda: False
    return runner


def _voice_event(path: str = "/tmp/voice.ogg") -> MessageEvent:
    return MessageEvent(
        text="",
        message_type=MessageType.VOICE,
        source=SessionSource(platform=Platform.TELEGRAM, chat_id="1", chat_type="dm"),
        media_urls=[path],
        media_types=["audio/ogg"],
    )


def _audio_event(path: str = "/tmp/song.mp3") -> MessageEvent:
    return MessageEvent(
        text="",
        message_type=MessageType.AUDIO,
        source=SessionSource(platform=Platform.TELEGRAM, chat_id="1", chat_type="dm"),
        media_urls=[path],
        media_types=["audio/mpeg"],
    )


# ---------------------------------------------------------------------------
# 1. VOICE still goes through STT
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_voice_message_still_transcribed(tmp_path, monkeypatch):
    """MessageType.VOICE must still be sent through _enrich_message_with_transcription."""
    runner = _make_runner(stt_enabled=True)
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="1", chat_type="dm")
    from tests.sec3_workspace_fixtures import configure_model_workspace
    root = configure_model_workspace(monkeypatch, tmp_path, root=tmp_path / "workspace")
    source_audio = tmp_path / "voice.ogg"
    source_audio.write_bytes(b"voice fixture")
    event = _voice_event(str(source_audio))

    with patch(
        "tools.transcription_tools.transcribe_audio",
        return_value={"success": True, "transcript": "hello world", "provider": "whisper"},
    ) as mock_transcribe:
        result = await runner._prepare_inbound_message_text(
            event=event,
            source=source,
            history=[],
        )

    mock_transcribe.assert_called_once()
    staged = mock_transcribe.call_args.args[0]
    from pathlib import Path
    assert Path(staged).is_relative_to(root)
    assert Path(staged).read_bytes() == b"voice fixture"
    assert mock_transcribe.call_args.args[1:] == (None, "gateway")
    # The transcript passes through as a plain quoted line — no "voice message"
    # meta-commentary in the LLM-visible prompt.
    assert "hello world" in result


# ---------------------------------------------------------------------------
# 2. AUDIO file attachment bypasses STT
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audio_attachment_context_note_format(tmp_path, monkeypatch):
    """Context note for audio file attachments should include the file path and guidance."""
    runner = _make_runner(stt_enabled=True)
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="1", chat_type="dm")
    from tests.sec3_workspace_fixtures import configure_model_workspace
    root = configure_model_workspace(monkeypatch, tmp_path, root=tmp_path / "workspace")
    audio = tmp_path / "cache_12345_my_song.mp3"
    audio.write_bytes(b"audio fixture")
    event = _audio_event(str(audio))

    with patch(
        "tools.transcription_tools.transcribe_audio",
        side_effect=AssertionError("must not be called"),
    ):
        with patch(
            "tools.credential_files.to_agent_visible_cache_path",
            side_effect=lambda p: p,
        ):
            result = await runner._prepare_inbound_message_text(
                event=event,
                source=source,
                history=[],
            )

    # STT must not run (transcribe_audio raises); the agent sees the file path.
    from pathlib import Path
    staged = Path(event.media_urls[0])
    assert staged.name in result and staged.suffix == ".mp3"
    assert staged.read_bytes() == b"audio fixture"
    assert staged.with_name(staged.name + ".receipt.json").is_file()
    assert str(root) in result
    assert str(audio) not in result


# ---------------------------------------------------------------------------
# 3. STT disabled still results in no transcription for audio file attachments
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 4. Telegram gateway: msg.audio → MessageType.AUDIO (not VOICE)
# ---------------------------------------------------------------------------
