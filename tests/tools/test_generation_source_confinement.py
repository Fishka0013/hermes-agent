"""Tests for the generation-tool source-image confinement chokepoint.

Model-supplied local paths passed to image_generate / video_generate resolve
through MODEL_WORKSPACE_ROOT and reach providers as data: URLs. Remote/inline
payloads retain their current route; terminal backend/cwd never adds authority.
"""

import base64
import json

import pytest

import tools.image_generation_tool as igt

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


@pytest.fixture(autouse=True)
def _no_real_sandbox(monkeypatch, tmp_path):
    import tools.terminal_tool as tt

    monkeypatch.setattr(tt, "ensure_task_env", lambda *a, **k: None)
    monkeypatch.setattr(
        "hermes_cli.config.get_model_file_security_config",
        lambda: {
            "model_workspace_root": str(tmp_path),
            "model_staging_max_file_bytes": 50 * 1024 * 1024,
            "model_staging_session_quota_bytes": 256 * 1024 * 1024,
            "model_staging_profile_quota_bytes": 1024 * 1024 * 1024,
            "model_staging_ttl_seconds": 86400,
        },
    )


class TestConfineSourceImages:
    def test_local_backend_confines_to_data_urls(self, monkeypatch, tmp_path):
        monkeypatch.setenv("TERMINAL_ENV", "local")
        pic, ref = tmp_path / "pic.png", tmp_path / "ref.png"
        pic.write_bytes(PNG)
        ref.write_bytes(PNG)
        url, refs, err = igt._confine_source_images(
            str(pic), [str(ref)], "t1")
        assert err is None
        assert url.startswith("data:image/png;base64,")
        assert refs and refs[0].startswith("data:image/png;base64,")

    def test_urls_pass_through_under_sandbox(self, monkeypatch, tmp_path):
        monkeypatch.setenv("TERMINAL_ENV", "docker")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
        url, refs, err = igt._confine_source_images(
            "https://x/y.png", ["data:image/png;base64,AAAA"], "t1")
        assert url == "https://x/y.png"
        assert refs == ["data:image/png;base64,AAAA"]
        assert err is None

    def test_path_resolves_to_data_url_under_sandbox(self, monkeypatch, tmp_path):
        """An approved local path is inlined before any provider dispatch."""
        monkeypatch.setenv("TERMINAL_ENV", "docker")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
        pic = tmp_path / "pic.png"
        pic.write_bytes(PNG)

        url, refs, err = igt._confine_source_images(
            str(pic), None, "t1")
        assert err is None
        assert url.startswith("data:image/png;base64,")
        assert base64.b64decode(url.split(",", 1)[1]) == PNG
        assert refs is None

    def test_unreadable_path_returns_error_payload(self, monkeypatch, tmp_path):
        """No sandbox env + non-cache path -> structured error, not a host read."""
        monkeypatch.setenv("TERMINAL_ENV", "docker")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))

        import tools.image_source as isrc

        monkeypatch.setattr(isrc, "_get_active_env", lambda tid: None)

        secret = tmp_path.parent / f"{tmp_path.name}-outside-secret"
        secret.write_bytes(b"HOST-PRIVATE-KEY")
        try:
            url, refs, err = igt._confine_source_images(str(secret), None, "t1")
        finally:
            secret.unlink(missing_ok=True)
        assert err is not None
        payload = json.loads(err)
        assert payload["success"] is False
        assert "Could not read source image" in payload["error"]
        # The host secret's bytes never left the chokepoint.
        assert "HOST-PRIVATE-KEY" not in err

    def test_handler_rejects_before_provider_dispatch(self, monkeypatch, tmp_path):
        """_handle_image_generate returns the confinement error without ever
        reaching plugin/FAL dispatch."""
        monkeypatch.setenv("TERMINAL_ENV", "ssh")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))

        import tools.image_source as isrc

        monkeypatch.setattr(isrc, "_get_active_env", lambda tid: None)

        dispatched = []
        monkeypatch.setattr(
            igt, "_dispatch_to_plugin_provider",
            lambda *a, **k: dispatched.append(1) or None)

        outside = tmp_path.parent / f"{tmp_path.name}-outside.png"
        out = igt._handle_image_generate(
            {"prompt": "edit it", "image_url": str(outside)},
            task_id="t1",
        )
        payload = json.loads(out)
        assert payload["success"] is False
        assert dispatched == []

    def test_video_generate_uses_same_chokepoint(self, monkeypatch, tmp_path):
        """video_generate's handler routes its image sources through the
        shared confinement helper too."""
        import tools.video_generation_tool as vgt

        monkeypatch.setenv("TERMINAL_ENV", "docker")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))

        import tools.image_source as isrc

        monkeypatch.setattr(isrc, "_get_active_env", lambda tid: None)

        outside = tmp_path.parent / f"{tmp_path.name}-outside-video.png"
        out = vgt._handle_video_generate(
            {"prompt": "animate", "image_url": str(outside)},
            task_id="t1",
        )
        payload = json.loads(out)
        assert payload["success"] is False
        assert "Could not read source image" in payload["error"]

    def test_video_provider_receives_data_url_not_local_path(self, monkeypatch, tmp_path):
        import tools.video_generation_tool as vgt

        pic = tmp_path / "xai-input.png"
        pic.write_bytes(PNG)
        seen = {}

        class FakeProvider:
            name = "xai"
            def default_model(self):
                return "grok-imagine-video"
            def generate(self, prompt, **kwargs):
                seen.update(kwargs)
                return {"success": True, "video": "https://example.invalid/video.mp4"}

        monkeypatch.setattr(vgt, "_resolve_active_provider", lambda: FakeProvider())
        monkeypatch.setattr(vgt, "_read_configured_video_provider", lambda: "xai")
        monkeypatch.setattr(vgt, "_read_configured_video_model", lambda: None)

        payload = json.loads(vgt._handle_video_generate(
            {"prompt": "animate", "image_url": str(pic)}, task_id="t1"))
        assert payload["success"] is True
        assert seen["image_url"].startswith("data:image/png;base64,")
        assert str(pic) not in seen["image_url"]
