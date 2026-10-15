"""SEC-3 staging destinations obey the same workspace gate for artifacts and receipts."""
import hashlib
import json
import multiprocessing
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from agent import model_file_policy as policy


def _q1_process_publish(source_path, task_id, barrier, queue):
    """Child helper: force both processes to observe the same pre-fix quota window."""
    from agent import model_file_policy as child_policy

    root = child_policy.get_model_workspace_root()
    original = child_policy._safe_tree_bytes
    seen_profile_check = False

    def synchronized_tree_bytes(path):
        nonlocal seen_profile_check
        value = original(path)
        if Path(path).resolve(strict=False) == (root / ".tmp").resolve(strict=False) and not seen_profile_check:
            seen_profile_check = True
            try:
                barrier.wait(timeout=0.5)
            except threading.BrokenBarrierError:
                pass
        return value

    child_policy._safe_tree_bytes = synchronized_tree_bytes
    try:
        staged = child_policy.publish_internal_artifact_for_model(
            child_policy.make_internal_artifact_source(source_path, source_class="q1-process"),
            task_id=task_id,
        )
        queue.put(("ok", staged.size))
    except Exception as exc:
        queue.put(("err", type(exc).__name__, str(exc)))


def _staged_payload_bytes(root: Path) -> int:
    return sum(
        p.stat().st_size
        for p in (root / ".tmp").rglob("*")
        if p.is_file()
        and not p.name.endswith(".receipt.json")
        and p.name != policy._PROFILE_QUOTA_LOCK_NAME
    ) if (root / ".tmp").exists() else 0


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

def test_concurrent_profile_quota_is_atomic_across_threads(staging, monkeypatch):
    root, _outside, source, settings = staging
    settings.update({
        "model_staging_max_file_bytes": 900,
        "model_staging_session_quota_bytes": 900,
        "model_staging_profile_quota_bytes": 1024,
    })
    first = source.with_name("q1-thread-one.bin")
    second = source.with_name("q1-thread-two.bin")
    first.write_bytes(b"a" * 800)
    second.write_bytes(b"b" * 800)
    original = policy._safe_tree_bytes
    barrier = threading.Barrier(2)
    local = threading.local()

    def synchronized_tree_bytes(path):
        value = original(path)
        if Path(path).resolve(strict=False) == (root / ".tmp").resolve(strict=False) \
                and not getattr(local, "profile_check", False):
            local.profile_check = True
            try:
                barrier.wait(timeout=0.25)
            except threading.BrokenBarrierError:
                pass
        return value

    monkeypatch.setattr(policy, "_safe_tree_bytes", synchronized_tree_bytes)
    trusted = [policy.make_internal_artifact_source(p, source_class="q1-thread") for p in (first, second)]

    def publish(index):
        try:
            return policy.publish_internal_artifact_for_model(trusted[index], task_id=f"thread-{index}")
        except policy.ModelFilePolicyError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, (0, 1)))

    successes = [r for r in results if isinstance(r, policy.StagedArtifact)]
    failures = [r for r in results if isinstance(r, policy.ModelFilePolicyError)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert str(failures[0]) == "profile staging quota exceeded"
    assert _staged_payload_bytes(root) == 800


def test_concurrent_profile_quota_is_process_safe(tmp_path, monkeypatch):
    home = tmp_path / "q1-process-home"
    root = tmp_path / "q1-process-root"
    cache = home / "cache"
    home.mkdir(); root.mkdir(); cache.mkdir()
    settings = {
        "model_workspace_root": str(root),
        "model_staging_max_file_bytes": 900,
        "model_staging_session_quota_bytes": 900,
        "model_staging_profile_quota_bytes": 1024,
        "model_staging_ttl_seconds": 60,
    }
    (home / "config.yaml").write_text(json.dumps({"security": settings}), encoding="utf-8")
    one = cache / "one.bin"; two = cache / "two.bin"
    one.write_bytes(b"a" * 800); two.write_bytes(b"b" * 800)
    monkeypatch.setenv("HERMES_HOME", str(home))

    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2)
    queue = ctx.Queue()
    processes = [
        ctx.Process(target=_q1_process_publish, args=(str(path), f"process-{index}", barrier, queue))
        for index, path in enumerate((one, two))
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(15)
        assert process.exitcode == 0
    results = [queue.get(timeout=2) for _ in processes]
    assert sum(result[0] == "ok" for result in results) == 1
    errors = [result for result in results if result[0] == "err"]
    assert len(errors) == 1 and errors[0][2] == "profile staging quota exceeded"
    assert _staged_payload_bytes(root) == 800


def test_sequential_profile_and_session_aggregate_quotas(staging):
    root, _outside, source, settings = staging
    first = source.with_name("q1-sequential-one.bin")
    second = source.with_name("q1-sequential-two.bin")
    first.write_bytes(b"a" * 600)
    second.write_bytes(b"b" * 600)
    trusted_first = policy.make_internal_artifact_source(first, source_class="q1-sequential")
    trusted_second = policy.make_internal_artifact_source(second, source_class="q1-sequential")

    settings["model_staging_profile_quota_bytes"] = 1024
    policy.publish_internal_artifact_for_model(trusted_first, task_id="profile-a")
    with pytest.raises(policy.ModelFilePolicyError, match="profile staging quota exceeded"):
        policy.publish_internal_artifact_for_model(trusted_second, task_id="profile-b")
    assert _staged_payload_bytes(root) == 600

    for p in (root / ".tmp").rglob("*"):
        if p.is_file():
            p.unlink()
    settings["model_staging_profile_quota_bytes"] = 4096
    settings["model_staging_session_quota_bytes"] = 1024
    policy.publish_internal_artifact_for_model(trusted_first, session_id="same-session")
    with pytest.raises(policy.ModelFilePolicyError, match="task/session staging quota exceeded"):
        policy.publish_internal_artifact_for_model(trusted_second, session_id="same-session")
    assert _staged_payload_bytes(root) == 600


def test_failed_publication_releases_quota_capacity(staging, monkeypatch):
    root, _outside, source, settings = staging
    source.write_bytes(b"x" * 800)
    settings.update({
        "model_staging_max_file_bytes": 900,
        "model_staging_session_quota_bytes": 900,
        "model_staging_profile_quota_bytes": 900,
    })
    trusted = policy.make_internal_artifact_source(source, source_class="q1-rollback")
    original_atomic_json = policy._atomic_json

    def fail_receipt(*_args, **_kwargs):
        raise OSError("forced receipt failure")

    monkeypatch.setattr(policy, "_atomic_json", fail_receipt)
    with pytest.raises(OSError, match="forced receipt failure"):
        policy.publish_internal_artifact_for_model(trusted, task_id="failed")
    assert _staged_payload_bytes(root) == 0
    monkeypatch.setattr(policy, "_atomic_json", original_atomic_json)
    published = policy.publish_internal_artifact_for_model(trusted, task_id="retry")
    assert published.size == 800
    assert _staged_payload_bytes(root) == 800


def test_profile_staging_locks_are_isolated_by_workspace(tmp_path):
    first = tmp_path / "profile-a"
    second = tmp_path / "profile-b"
    first.mkdir(); second.mkdir()
    entered = threading.Event()
    release = threading.Event()

    def hold_first():
        with policy._profile_staging_lock(first):
            entered.set()
            assert release.wait(2)

    worker = threading.Thread(target=hold_first)
    worker.start()
    assert entered.wait(2)
    started = time.monotonic()
    with policy._profile_staging_lock(second):
        elapsed = time.monotonic() - started
    release.set()
    worker.join(2)
    assert not worker.is_alive()
    assert elapsed < 0.5
