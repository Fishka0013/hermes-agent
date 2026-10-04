"""Published runtime artifacts retain delivery semantics without cache authority."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, SendResult


@pytest.mark.parametrize("candidate", [
    "//sec3-owned-namespace.invalid/share/artifact.png",
    r"\\sec3-owned-namespace.invalid\share\artifact.png",
    r"\\?\UNC\sec3-owned-namespace.invalid\share\artifact.png",
    r"\??\UNC\sec3-owned-namespace.invalid\share\artifact.png",
    r"\\.\device\artifact.png",
    "%2F%2Fsec3-owned-namespace.invalid/share/artifact.png",
    "%5C%5Csec3-owned-namespace.invalid%5Cshare%5Cartifact.png",
    "%5C%5C%3F%5CUNC%5Csec3-owned-namespace.invalid%5Cshare%5Cartifact.png",
    "file:///outside/artifact.png",
    "file://sec3-owned-namespace.invalid/share/artifact.png",
])
def test_outbound_unsafe_namespace_refused_before_filesystem_lookup(monkeypatch, candidate):
    from gateway.platforms import base
    def unexpected_lookup(*args, **kwargs):
        pytest.fail("unsafe namespace reached filesystem/container lookup")
    monkeypatch.setattr(base, "_translate_docker_container_media_path", unexpected_lookup)
    monkeypatch.setattr(base, "_resolve_path", unexpected_lookup)
    assert base.validate_media_delivery_path(candidate) is None


def test_outbound_syntax_guard_unavailable_fails_closed(monkeypatch):
    from gateway.platforms import base
    from agent import model_file_policy
    def unavailable(value):
        raise RuntimeError("policy parser unavailable")
    def unexpected_lookup(*args, **kwargs):
        pytest.fail("unavailable policy reached filesystem/container lookup")
    monkeypatch.setattr(model_file_policy, "validate_model_local_path_syntax", unavailable)
    monkeypatch.setattr(base, "_translate_docker_container_media_path", unexpected_lookup)
    monkeypatch.setattr(base, "_resolve_path", unexpected_lookup)
    assert base.validate_media_delivery_path("/workspace/owned.png") is None


class _Adapter(BasePlatformAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(enabled=True), Platform.TELEGRAM)

    async def connect(self):
        return True

    async def disconnect(self):
        return None

    async def get_chat_info(self, chat_id):
        return {"name": chat_id, "type": "dm"}

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        return SendResult(success=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("producer,suffix,method,voice", [
    ("image", ".png", "send_multiple_images", False),
    ("tts", ".mp3", "send_voice", False),
    ("tts", ".ogg", "send_voice", True),
    ("video", ".mp4", "send_video", False),
    ("inbound", ".mp4", "send_video", False),
    ("inbound", ".pdf", "send_document", False),
])
async def test_publication_to_real_delivery_route_a_b_a(
    tmp_path, monkeypatch, producer, suffix, method, voice
):
    homes = []
    for label in ("a", "b"):
        home = tmp_path / label
        home.mkdir()
        root = home / "workspace"
        root.mkdir()
        cache = home / "cache"
        cache.mkdir()
        (home / "config.yaml").write_text(json.dumps({
            "security": {"model_workspace_root": str(root)},
        }))
        source = cache / ("untrusted-original-name" + suffix)
        source.write_bytes(b"non-sensitive runtime artifact")
        homes.append((home, root, source))

    published_by_home = {}
    for index in (0, 1, 0):
        home, root, source = homes[index]
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
        assert BasePlatformAdapter.validate_media_delivery_path(str(source)) is None
        if producer == "image":
            from tools import image_generation_tool as generation
            monkeypatch.setattr(generation, "_active_terminal_env", lambda task_id: None)
            result = json.loads(generation._postprocess_image_generate_result(
                json.dumps({"success": True, "image": str(source)}), task_id="delivery-test"))
            published = Path(result["image"])
        elif producer == "tts":
            from tools.tts_tool import _publish_tts_paths_for_model
            published = Path(_publish_tts_paths_for_model([str(source)], "delivery-test")[0])
        elif producer == "video":
            from tools import video_generation_tool as generation
            class Provider:
                name = "fake-video"
                def default_model(self):
                    return "fake-video-model"
                def generate(self, prompt, **kwargs):
                    return {"success": True, "video": str(source), "provider": self.name,
                            "job_id": "preserved-job-id"}
            monkeypatch.setattr(generation, "_resolve_active_provider", lambda: Provider())
            monkeypatch.setattr(generation, "_read_configured_video_provider", lambda: "fake-video")
            monkeypatch.setattr(generation, "_read_configured_video_model", lambda: None)
            result = json.loads(generation._handle_video_generate({"prompt": "generate"}, task_id="delivery-test"))
            assert result["success"] and result["job_id"] == "preserved-job-id"
            published = Path(result["video"])
        else:
            from gateway.run_inbound import GatewayInboundMixin
            event = SimpleNamespace(media_urls=[str(source)], media_types=[],
                                    media_text_inlined=[], message_id="delivery-test")
            GatewayInboundMixin._stage_inbound_media_for_model(
                event, SimpleNamespace(platform="test"), "delivery-test")
            published = Path(event.media_urls[0])

        assert published.is_relative_to(root / ".tmp")
        assert "untrusted-original-name" not in published.name
        assert published.read_bytes() == source.read_bytes()
        assert published.stat().st_mode & 0o111 == 0
        assert published.with_name(published.name + ".receipt.json").is_file()
        other = published_by_home.get(1 - index)
        if other:
            assert BasePlatformAdapter.validate_media_delivery_path(str(other)) is None
        published_by_home[index] = published

        content = ("[[audio_as_voice]]\n" if voice else "") + "MEDIA:" + str(published)
        extracted, cleaned = BasePlatformAdapter.extract_media(content)
        filtered = BasePlatformAdapter.filter_media_delivery_paths(extracted)
        assert filtered == [(str(published), voice)]
        assert "MEDIA:" not in cleaned
        adapter = _Adapter()
        senders = ("send_multiple_images", "send_voice", "send_video", "send_document")
        for name in senders:
            setattr(adapter, name, AsyncMock(return_value=SendResult(success=True)))
        outcomes = []
        await adapter._deliver_media_attachments(
            SimpleNamespace(source=SimpleNamespace(chat_id="test-chat")), filtered, [],
            force_document_attachments=False, human_delay=0, metadata={},
            record_delivery=outcomes.append)
        getattr(adapter, method).assert_awaited_once()
        for name in senders:
            if name != method:
                getattr(adapter, name).assert_not_awaited()
        assert len(outcomes) == 1 and outcomes[0].success
