"""Actual generation dispatch confines sources and publishes current video outputs."""
import json
from pathlib import Path

import pytest


@pytest.fixture
def homes(tmp_path, monkeypatch):
    pairs = []
    for label in ("a", "b"):
        home, root = tmp_path / ("home-" + label), tmp_path / ("workspace-" + label)
        home.mkdir()
        root.mkdir()
        (home / "config.yaml").write_text(json.dumps({"security": {"model_workspace_root": str(root)}}))
        cache = home / "cache"
        cache.mkdir()
        outside = cache / "outside.mp4"
        outside.write_bytes(b"NON-SENSITIVE OUTSIDE BYTES")
        pairs.append((home, root, outside))
    monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
    return pairs


@pytest.mark.parametrize("tool", ["image_generate", "video_generate"])
@pytest.mark.parametrize("path_form", ["absolute", "uri", pytest.param("symlink", marks=pytest.mark.require_symlinks)])
def test_source_blocks_before_provider_a_b_a(homes, monkeypatch, tool, path_form):
    from model_tools import handle_function_call
    from tools import image_generation_tool as image, video_generation_tool as video
    invocations = []
    def forbidden(*args, **kwargs):
        invocations.append(True)
        raise AssertionError("Blocked source reached provider")
    monkeypatch.setattr(image, "_dispatch_to_plugin_provider", forbidden)
    monkeypatch.setattr(video, "_resolve_active_provider", forbidden)
    original_read = Path.read_bytes
    reads = []
    def track(path):
        if path in [p[2] for p in homes]:
            reads.append(path)
        return original_read(path)
    monkeypatch.setattr(Path, "read_bytes", track)
    for index in (0, 1, 0):
        home, root, outside = homes[index]
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        if path_form == "symlink":
            source = root / "escape.png"
            if not source.is_symlink():
                source.symlink_to(outside)
        else:
            source = outside.as_uri() if path_form == "uri" else str(outside)
        result = json.loads(handle_function_call(tool, {"prompt": "edit", "image_url": str(source)}, task_id="same-task"))
        assert result["success"] is False
        assert "outside MODEL_WORKSPACE_ROOT" in result["error"]
    assert invocations == [] and reads == []


@pytest.mark.parametrize("tool", ["xai_video_edit", "xai_video_extend"])
@pytest.mark.parametrize("path_form", ["absolute", "uri"])
def test_xai_current_public_url_contract_blocks_local_before_provider(homes, monkeypatch, tool, path_form):
    from model_tools import handle_function_call
    from tools import xai_video_tools
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Local video reached xAI provider")
    monkeypatch.setattr(xai_video_tools, "run_xai_video_edit", forbidden)
    monkeypatch.setattr(xai_video_tools, "run_xai_video_extend", forbidden)
    home, root, outside = homes[0]
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    source = outside.as_uri() if path_form == "uri" else str(outside)
    result = json.loads(handle_function_call(tool, {"prompt": "edit", "video_url": source}))
    assert "public HTTPS MP4 URL" in result["error"]
    assert calls == []


@pytest.mark.require_symlinks
@pytest.mark.parametrize("escape", ["source", "stage"])
def test_video_publication_symlink_escape_fails_closed(homes, monkeypatch, escape):
    from model_tools import handle_function_call
    from tools import video_generation_tool as video
    home, root, outside = homes[0]
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    source = outside
    if escape == "source":
        source = home / "cache" / "alias.mp4"
        source.symlink_to(outside)
    else:
        (root / ".tmp").symlink_to(home / "cache", target_is_directory=True)
    class Provider:
        name = "fake-video"
        def default_model(self):
            return "fake-model"
        def generate(self, **kwargs):
            return {"success": True, "video": str(source)}
    monkeypatch.setattr(video, "_resolve_active_provider", lambda: Provider())
    monkeypatch.setattr(video, "_read_configured_video_provider", lambda: "fake-video")
    monkeypatch.setattr(video, "_read_configured_video_model", lambda: None)
    before = {p.name: p.read_bytes() for p in (home / "cache").iterdir() if p.is_file()}
    result = json.loads(handle_function_call("video_generate", {"prompt": "generate"}))
    assert result["success"] is False and result["error_type"] == "artifact_publish_failed"
    assert {p.name: p.read_bytes() for p in (home / "cache").iterdir() if p.is_file()} == before
    assert not list(root.rglob("*.receipt.json"))


def test_video_publication_preserves_remote_result_contract():
    from tools.video_generation_tool import _publish_generated_video_result
    result = {"success": True, "video": "https://example.invalid/video.mp4", "job_id": "job", "cost": 0.1}
    assert _publish_generated_video_result(result, "task") == result


@pytest.mark.require_symlinks
@pytest.mark.parametrize("chunks", [1, 2])
def test_tts_provider_and_wav_sidecars_never_use_caller_siblings(homes, monkeypatch, chunks):
    """The registered tool uses private paths even when caller chunk/sidecar names escape."""
    from model_tools import handle_function_call
    from tools import tts_tool as tts
    home, root, outside = homes[0]
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    for name in ("chosen.chunk001.mp3", "chosen.chunk001.wav", "chosen.wav", "chosen.ogg"):
        (root / name).symlink_to(outside)
    calls = []
    def synthesize(engine, text, file_str, config, instructions):
        path = Path(file_str)
        assert path.parent.name.startswith(".hermes-tts-")
        assert path.resolve().is_relative_to(root)
        path.with_suffix(".wav").write_bytes(b"PRIVATE_WAV")
        path.write_bytes(b"PRIVATE_AUDIO")
        calls.append(path)
    monkeypatch.setattr(tts, "_load_tts_config", lambda: {"provider": "edge"})
    monkeypatch.setattr(tts, "_select_builtin_engine", lambda provider: (provider, None))
    monkeypatch.setattr(tts, "_split_text_for_tts", lambda text, cap: ["hello"] * chunks)
    monkeypatch.setattr(tts, "_session_platform", lambda: ("", False))
    monkeypatch.setattr(tts, "_synthesize_builtin", synthesize)
    monkeypatch.setattr("tools.tts_tool_delivery.shutil.which", lambda name: None)
    before = outside.read_bytes()
    result = json.loads(handle_function_call("text_to_speech", {
        "text": "hello", "output_path": str(root / "chosen.mp3")
    }))
    assert result["success"] is True, result
    assert len(calls) == chunks and all(not p.parent.exists() for p in calls)
    assert outside.read_bytes() == before
    expected = [root / "chosen.mp3"] if chunks == 1 else [root / "chosen.part01.mp3", root / "chosen.part02.mp3"]
    assert result["file_paths"] == list(map(str, expected))
    assert all(path.read_bytes() == b"PRIVATE_AUDIO" for path in expected)
    assert all((root / name).is_symlink() for name in ("chosen.chunk001.mp3", "chosen.chunk001.wav", "chosen.wav", "chosen.ogg"))


@pytest.mark.require_symlinks
@pytest.mark.parametrize("escape", ["part", "format", "source"])
def test_tts_final_delivery_escape_fails_closed(homes, monkeypatch, escape):
    from model_tools import handle_function_call
    from tools import tts_tool as tts
    home, root, outside = homes[0]
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    if escape == "part":
        (root / "chosen.part01.mp3").symlink_to(outside)
    elif escape == "format":
        (root / "chosen.ogg").symlink_to(outside)
    calls = []
    def synthesize(engine, text, file_str, config, instructions):
        path = Path(file_str)
        if escape == "source":
            path.symlink_to(outside)
        else:
            path.write_bytes(b"PRIVATE_AUDIO")
        calls.append(path)
    monkeypatch.setattr(tts, "_load_tts_config", lambda: {"provider": "edge"})
    monkeypatch.setattr(tts, "_select_builtin_engine", lambda provider: (provider, None))
    monkeypatch.setattr(tts, "_split_text_for_tts", lambda text, cap: ["hello"] * (2 if escape == "part" else 1))
    monkeypatch.setattr(tts, "_session_platform", lambda: ("telegram", True) if escape == "format" else ("", False))
    monkeypatch.setattr(tts, "_synthesize_builtin", synthesize)
    def convert(path):
        target = Path(path).with_suffix(".ogg")
        target.write_bytes(b"PRIVATE_OPUS")
        return str(target)
    monkeypatch.setattr(tts, "_convert_to_opus", convert)
    monkeypatch.setattr("tools.tts_tool_delivery.shutil.which", lambda name: None)
    before = outside.read_bytes()
    result = json.loads(handle_function_call("text_to_speech", {
        "text": "hello", "output_path": str(root / "chosen.mp3")
    }))
    assert result["success"] is False
    assert calls, result
    assert "outside MODEL_WORKSPACE_ROOT" in result["error"] or "not a regular file" in result["error"]
    assert outside.read_bytes() == before
    assert all(not p.parent.exists() for p in calls)
    assert not (root / "chosen.mp3").exists()
    assert not (root / "chosen.part02.mp3").exists()


@pytest.mark.parametrize("cache_inside_root", [True, False])
def test_default_tts_survives_private_cleanup_with_receipts_a_b_a(homes, monkeypatch, cache_inside_root):
    from model_tools import handle_function_call
    from tools import tts_tool as tts
    import hashlib
    calls, published = [], []
    def synthesize(engine, text, file_str, config, instructions):
        path = Path(file_str)
        assert path.parent.name.startswith(".hermes-tts-")
        path.write_bytes(b"PRIVATE_DEFAULT_AUDIO")
        calls.append(path)
    monkeypatch.setattr(tts, "_load_tts_config", lambda: {"provider": "edge"})
    monkeypatch.setattr(tts, "_select_builtin_engine", lambda provider: (provider, None))
    monkeypatch.setattr(tts, "_session_platform", lambda: ("", False))
    monkeypatch.setattr(tts, "_synthesize_builtin", synthesize)
    for index in (0, 1, 0):
        home, root, _ = homes[index]
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        cache = root / "runtime-cache" if cache_inside_root else home / "cache"
        monkeypatch.setattr(tts, "DEFAULT_OUTPUT_DIR", str(cache))
        result = json.loads(handle_function_call("text_to_speech", {"text": "hello"}, task_id="same-task"))
        assert result["success"] is True, result
        path = Path(result["file_path"])
        assert path.is_relative_to(root / ".tmp" / "model-artifacts" / "tts")
        assert path.read_bytes() == b"PRIVATE_DEFAULT_AUDIO"
        receipt = json.loads(path.with_name(path.name + ".receipt.json").read_text())
        assert receipt["staged_path"] == str(path)
        assert receipt["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert receipt["source_class"] == "tts-generated"
        assert not calls[-1].parent.exists()
        published.append(path)
    assert len(set(published)) == 3 and all(p.exists() for p in published)
