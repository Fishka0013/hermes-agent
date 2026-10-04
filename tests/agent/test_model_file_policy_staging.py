"""SEC-3 staging destinations obey the same workspace gate for artifacts and receipts."""
import hashlib
import json
from pathlib import Path

import pytest

from agent import model_file_policy as policy


@pytest.fixture
def staging(tmp_path, monkeypatch):
    root = (tmp_path / "model-root")
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    source = tmp_path / "source.bin"
    source.write_bytes(b"non-sensitive artifact")
    settings = {
        "model_workspace_root": str(root),
        "model_staging_max_file_bytes": 1024,
        "model_staging_session_quota_bytes": 2048,
        "model_staging_profile_quota_bytes": 4096,
        "model_staging_ttl_seconds": 60,
    }
    monkeypatch.setattr(policy, "_security_config", lambda: settings)
    return root, outside, source, settings


@pytest.mark.parametrize("namespace", ["artifact", "inbound", "generated-images"])
def test_trusted_publication_and_receipt(staging, namespace):
    root, outside, source, _ = staging
    trusted = policy.make_internal_artifact_source(source, source_class="runtime-test")
    result = policy.publish_internal_artifact_for_model(
        trusted, namespace=namespace, session_id="session")
    assert result.path.resolve().is_relative_to(root)
    assert result.receipt_path.resolve().is_relative_to(root / ".tmp")
    assert result.path.read_bytes() == source.read_bytes()
    receipt = json.loads(result.receipt_path.read_text())
    assert receipt["staged_path"] == str(result.path)
    assert receipt["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert result.path.stat().st_mode & 0o777 == 0o600
    assert list(outside.iterdir()) == []
    assert not list((root / ".tmp").rglob(".*.tmp"))


@pytest.mark.parametrize("route", [
    "staging-root", "inbound", "intermediate", "scope",
    "artifact-existing", "artifact-dangling",
    "receipt-existing", "receipt-dangling", "prefix-trick",
])
@pytest.mark.parametrize("source_suffix", [".bin", ".png"])
def test_static_symlink_escape_is_blocked(staging, monkeypatch, route, source_suffix):
    root, outside, source, _ = staging
    source = source.with_suffix(source_suffix)
    source.write_bytes(b"non-sensitive artifact")
    scope = hashlib.sha256(b"session").hexdigest()[:16]
    opaque = "a" * 40
    monkeypatch.setattr(policy.secrets, "token_hex", lambda n: opaque if n == 20 else "b" * 16)
    namespace = "inbound" if route == "inbound" else "generated-images"
    scope_dir = root / ".tmp" / "model-artifacts" / namespace / scope
    directories = {
        "staging-root": root / ".tmp",
        "inbound": root / ".tmp" / "inbound",
        "intermediate": root / ".tmp" / "model-artifacts",
        "scope": scope_dir,
        "prefix-trick": root / ".tmp",
    }
    if route in directories:
        link = directories[route]
        target = outside
        if route == "prefix-trick":
            target = root.with_name(root.name + "-evil")
            target.mkdir()
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target, target_is_directory=True)
        before = {p.name: p.read_bytes() for p in target.iterdir() if p.is_file()}
    else:
        scope_dir.mkdir(parents=True)
        suffix = ".receipt.json" if route.startswith("receipt") else ""
        link = scope_dir / (opaque + source_suffix + suffix)
        target = outside / "target.bin"
        if route.endswith("existing"):
            target.write_bytes(b"outside unchanged")
        link.symlink_to(target)
        before = {p.name: p.read_bytes() for p in outside.iterdir() if p.is_file()}
    trusted = policy.make_internal_artifact_source(source, source_class="runtime-test")
    with pytest.raises(policy.ModelFilePolicyError):
        policy.publish_internal_artifact_for_model(trusted, namespace=namespace, session_id="session")
    parent = target if target.is_dir() else outside
    assert {p.name: p.read_bytes() for p in parent.iterdir() if p.is_file()} == before
    assert not [p for p in parent.rglob("*") if p.name.endswith(".receipt.json")]
    assert not [p for p in root.rglob("*") if p.name.endswith(".tmp") and p.is_file()]


def test_model_forged_provenance_and_raw_cache_denied(staging):
    root, outside, source, _ = staging
    forged = policy.InternalArtifactSource(source, "model-forged", None, object())
    with pytest.raises(policy.ModelFilePolicyError):
        policy.publish_internal_artifact_for_model(forged)
    with pytest.raises(policy.ModelFilePolicyError):
        policy.publish_internal_artifact_for_model({"path": str(source), "source_class": "runtime"})
    with pytest.raises(policy.ModelFilePolicyError):
        policy.resolve_model_read_path(source)
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("limit", [
    "model_staging_max_file_bytes",
    "model_staging_session_quota_bytes",
    "model_staging_profile_quota_bytes",
])
def test_staging_quota_fails_without_partial_files(staging, limit):
    root, outside, source, settings = staging
    settings[limit] = 1
    trusted = policy.make_internal_artifact_source(source, source_class="runtime-test")
    with pytest.raises(policy.ModelFilePolicyError):
        policy.publish_internal_artifact_for_model(trusted)
    assert not [p for p in root.rglob("*") if p.is_file()]
    assert list(outside.iterdir()) == []


def test_ttl_cleanup_and_escaping_directory(staging):
    root, outside, source, _ = staging
    trusted = policy.make_internal_artifact_source(source, source_class="runtime-test")
    published = policy.publish_internal_artifact_for_model(trusted)
    outside_artifact = outside / "keep.bin"
    outside_artifact.write_bytes(b"untouched")
    outside_receipt = outside / "keep.bin.receipt.json"
    outside_receipt.write_text(json.dumps({"expires_at": 1, "staged_path": str(outside_artifact)}))
    (root / ".tmp" / "escape").symlink_to(outside, target_is_directory=True)
    assert policy.cleanup_expired_model_artifacts(now=published.expires_at + 1) == 1
    assert not published.path.exists()
    assert not published.receipt_path.exists()
    assert outside_artifact.read_bytes() == b"untouched"
    assert outside_receipt.exists()
    # A forged receipt in the staging tree must not delete unrelated workspace content.
    unrelated = root / "keep.txt"
    unrelated.write_text("keep")
    forged = root / ".tmp" / "forged.receipt.json"
    forged.write_text(json.dumps({"expires_at": 1, "staged_path": str(unrelated)}))
    assert policy.cleanup_expired_model_artifacts(now=published.expires_at + 2) == 0
    assert unrelated.read_text() == "keep"
