"""Strict model-facing filesystem policy for ordinary Hermes.

MODEL_PATH values are untrusted. MODEL_WORKSPACE_ROOT is the sole security
boundary. A validated resolution_base may preserve project-relative UX but
can never widen that boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


class ModelFilePolicyError(PermissionError):
    """A model-facing local path failed the workspace security policy."""


_TRUST_TOKEN = object()
_PROFILE_STAGING_LOCKS_GUARD = threading.Lock()
_PROFILE_STAGING_LOCKS: dict[str, threading.RLock] = {}
_PROFILE_QUOTA_LOCK_NAME = ".profile-quota.lock"


def _security_config() -> dict[str, Any]:
    try:
        from hermes_cli.config import get_model_file_security_config
        security = get_model_file_security_config()
    except Exception as exc:
        raise ModelFilePolicyError("model file policy unavailable") from exc
    if not isinstance(security, dict) or not security:
        raise ModelFilePolicyError("security config missing")
    return security
def get_model_workspace_root() -> Path:
    raw = _security_config().get("model_workspace_root")
    if not isinstance(raw, str) or not raw.strip():
        raise ModelFilePolicyError("security.model_workspace_root is unset")
    candidate = Path(raw.strip()).expanduser()
    if not candidate.is_absolute():
        raise ModelFilePolicyError("security.model_workspace_root must be absolute")
    try:
        root = candidate.resolve(strict=True)
    except OSError as exc:
        raise ModelFilePolicyError("security.model_workspace_root is invalid") from exc
    if not root.is_dir():
        raise ModelFilePolicyError("security.model_workspace_root is not a directory")
    return root


def _inside(target: Path, root: Path) -> bool:
    try:
        target.relative_to(root)
        return True
    except ValueError:
        return False


def validate_resolution_base(
    base: str | os.PathLike[str] | None,
    *,
    root: Path | None = None,
) -> Path:
    root = root or get_model_workspace_root()
    if base is None:
        return root
    try:
        candidate = Path(os.fspath(base)).expanduser().resolve(strict=True)
    except (OSError, TypeError, ValueError) as exc:
        raise ModelFilePolicyError("resolution base is invalid") from exc
    if not candidate.is_dir() or not _inside(candidate, root):
        raise ModelFilePolicyError("resolution base is outside MODEL_WORKSPACE_ROOT")
    return candidate
def _parse_model_path(value: str | os.PathLike[str], *, allow_file_uri: bool) -> str:
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ModelFilePolicyError("invalid local path")
    decoded = unquote(value.strip())
    # Windows namespace/UNC resolution can authenticate to a remote share
    # before a canonical containment check. Refuse the raw shape first.
    from agent.file_safety import get_nt_namespace_error
    if get_nt_namespace_error(decoded) or decoded.startswith(("\\\\", "//")):
        raise ModelFilePolicyError("Windows NT/device/UNC namespace paths are not allowed")
    parsed = urlparse(decoded)
    if parsed.scheme:
        if parsed.scheme.lower() != "file" or not allow_file_uri:
            raise ModelFilePolicyError("unsupported local-path scheme")
        if parsed.netloc not in ("", "localhost"):
            raise ModelFilePolicyError("remote file URI is not allowed")
        decoded = parsed.path
    return decoded


def validate_model_local_path_syntax(value: str | os.PathLike[str]) -> None:
    """Reject unsafe namespaces before I/O; this alone never grants path authority.

    Runtime namespace translation may follow this check, but its resulting
    target must still pass the full model read/write resolver.
    """
    _parse_model_path(value, allow_file_uri=False)


def _canonical_model_path(
    value: str | os.PathLike[str],
    *,
    must_exist: bool,
    allow_file_uri: bool,
    resolution_base: str | os.PathLike[str] | None = None,
    scope_base: str | os.PathLike[str] | None = None,
) -> tuple[Path, Path]:
    root = get_model_workspace_root()
    base = validate_resolution_base(resolution_base, root=root)
    scope = validate_resolution_base(scope_base, root=root) if scope_base is not None else None
    raw = _parse_model_path(value, allow_file_uri=allow_file_uri)
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        target = candidate.resolve(strict=must_exist)
    except OSError as exc:
        raise ModelFilePolicyError("local path could not be resolved") from exc
    if not _inside(target, root):
        raise ModelFilePolicyError("local path is outside MODEL_WORKSPACE_ROOT")
    if scope is not None and not _inside(target, scope):
        raise ModelFilePolicyError("local path is outside the approved task/project base")
    return root, target
def resolve_model_read_path(
    value: str | os.PathLike[str],
    *,
    allow_file_uri: bool = False,
    allow_directory: bool = False,
    resolution_base: str | os.PathLike[str] | None = None,
    scope_base: str | os.PathLike[str] | None = None,
) -> Path:
    _, target = _canonical_model_path(
        value, must_exist=True, allow_file_uri=allow_file_uri,
        resolution_base=resolution_base, scope_base=scope_base)
    if allow_directory:
        if not (target.is_file() or target.is_dir()):
            raise ModelFilePolicyError("local path is not a regular file or directory")
    elif not target.is_file():
        raise ModelFilePolicyError("local path is not a regular file")
    return target


def resolve_model_write_path(
    value: str | os.PathLike[str],
    *,
    allow_file_uri: bool = False,
    resolution_base: str | os.PathLike[str] | None = None,
    scope_base: str | os.PathLike[str] | None = None,
) -> Path:
    _, target = _canonical_model_path(
        value, must_exist=False, allow_file_uri=allow_file_uri,
        resolution_base=resolution_base, scope_base=scope_base)
    if target.exists() and target.is_dir():
        raise ModelFilePolicyError("output path is a directory")
    return target


def resolve_model_entry_path(
    value: str | os.PathLike[str],
    *,
    resolution_base: str | os.PathLike[str] | None = None,
    scope_base: str | os.PathLike[str] | None = None,
) -> Path:
    """Validate both the target and its entry, preserving the final symlink for Delete/Move."""
    root, target = _canonical_model_path(
        value, must_exist=False, allow_file_uri=False,
        resolution_base=resolution_base, scope_base=scope_base)
    if target.exists() and target.is_dir():
        raise ModelFilePolicyError("output path is a directory")
    raw = Path(_parse_model_path(value, allow_file_uri=False)).expanduser()
    if not raw.is_absolute():
        raw = validate_resolution_base(resolution_base, root=root) / raw
    entry = Path(os.path.normpath(str(raw)))
    _, parent = _canonical_model_path(
        entry.parent, must_exist=False, allow_file_uri=False,
        scope_base=scope_base)
    return parent / entry.name


def resolve_model_directory(
    value: str | os.PathLike[str],
    *,
    allow_file_uri: bool = False,
    resolution_base: str | os.PathLike[str] | None = None,
    scope_base: str | os.PathLike[str] | None = None,
) -> Path:
    _, target = _canonical_model_path(
        value, must_exist=True, allow_file_uri=allow_file_uri,
        resolution_base=resolution_base, scope_base=scope_base)
    if not target.is_dir():
        raise ModelFilePolicyError("local path is not a directory")
    return target


def resolve_model_candidate_path(
    value: str | os.PathLike[str],
    *,
    allow_file_uri: bool = False,
    resolution_base: str | os.PathLike[str] | None = None,
    scope_base: str | os.PathLike[str] | None = None,
) -> Path:
    """Canonicalize a candidate without requiring existence; still enforces all boundaries."""
    _, target = _canonical_model_path(
        value, must_exist=False, allow_file_uri=allow_file_uri,
        resolution_base=resolution_base, scope_base=scope_base)
    return target
@dataclass(frozen=True)
class InternalArtifactSource:
    path: Path
    source_class: str
    source_id: str | None
    _trust_token: object


@dataclass(frozen=True)
class StagedArtifact:
    path: Path
    receipt_path: Path
    size: int
    sha256: str
    created_at: float
    expires_at: float


def make_internal_artifact_source(
    path: str | os.PathLike[str], *, source_class: str, source_id: str | None = None
) -> InternalArtifactSource:
    if not isinstance(source_class, str) or not source_class.strip():
        raise ValueError("source_class is required")
    return InternalArtifactSource(Path(path), source_class.strip(), source_id, _TRUST_TOKEN)


def _staging_limits() -> tuple[int, int, int, int]:
    sec = _security_config()
    keys = (
        ("model_staging_max_file_bytes", 50 * 1024 * 1024),
        ("model_staging_session_quota_bytes", 256 * 1024 * 1024),
        ("model_staging_profile_quota_bytes", 1024 * 1024 * 1024),
        ("model_staging_ttl_seconds", 24 * 60 * 60),
    )
    values: list[int] = []
    for key, default in keys:
        try:
            value = int(sec.get(key, default))
        except (TypeError, ValueError) as exc:
            raise ModelFilePolicyError(f"invalid security.{key}") from exc
        if value <= 0:
            raise ModelFilePolicyError(f"invalid security.{key}")
        values.append(value)
    return values[0], values[1], values[2], values[3]

def _validated_staging_path(path: Path, *, root: Path | None = None) -> Path:
    """Reject symlinks anywhere below the canonical workspace, before staging I/O."""
    root = root or get_model_workspace_root()
    path = Path(path)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ModelFilePolicyError("staging path is outside MODEL_WORKSPACE_ROOT") from exc
    if not relative.parts or relative.parts[0] != ".tmp" or ".." in relative.parts:
        raise ModelFilePolicyError("invalid trusted staging path")
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ModelFilePolicyError("staging path could not be validated") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ModelFilePolicyError("staging path may not traverse a symlink")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ModelFilePolicyError("staging parent is not a directory")
    try:
        canonical = path.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise ModelFilePolicyError("staging path could not be resolved") from exc
    if not _inside(canonical, root / ".tmp"):
        raise ModelFilePolicyError("staging path escapes the trusted staging tree")
    return canonical


@contextmanager
def _staging_parent(path: Path):
    """Pin the validated parent for artifact and receipt I/O where POSIX supports it."""
    path = _validated_staging_path(path)
    parent_fd = None
    if (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd and os.rename in os.supports_dir_fd):
        try:
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ModelFilePolicyError("unsafe staging parent") from exc
    try:
        yield path, parent_fd
    finally:
        if parent_fd is not None:
            os.close(parent_fd)

def _safe_tree_bytes(root: Path) -> int:
    root = _validated_staging_path(root)
    total = 0
    if not root.exists():
        return 0
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        dirs[:] = [d for d in dirs if not (base_path / d).is_symlink()]
        for name in files:
            if name == _PROFILE_QUOTA_LOCK_NAME:
                continue
            p = base_path / name
            try:
                st = p.lstat()
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and not name.endswith(".receipt.json"):
                total += st.st_size
    return total


@contextmanager
def _profile_staging_lock(root: Path):
    """Serialize quota check + publication for one canonical model workspace.

    The in-process lock covers threads. POSIX additionally locks the staging
    directory itself, so no model-writable sidecar inode can be replaced while
    another process is publishing. Windows uses a one-byte lock sidecar; an
    open CRT handle plus ``msvcrt.locking`` supplies the cross-process fence.
    Different workspace roots use different locks.
    """
    root = Path(root).resolve(strict=True)
    lock_dir = _validated_staging_path(root / ".tmp", root=root)
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_dir = _validated_staging_path(lock_dir, root=root)
    key = os.path.normcase(str(root))
    with _PROFILE_STAGING_LOCKS_GUARD:
        thread_lock = _PROFILE_STAGING_LOCKS.setdefault(key, threading.RLock())
    with thread_lock:
        if os.name == "nt":  # pragma: no cover - exercised on Windows CI
            lock_path = _validated_staging_path(lock_dir / _PROFILE_QUOTA_LOCK_NAME, root=root)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
            fd = os.open(lock_path, flags, 0o600)
            try:
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                    os.fsync(fd)
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)
        else:
            import fcntl
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(lock_dir, flags)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path = _validated_staging_path(path)
    if path.exists():
        raise ModelFilePolicyError("staging receipt destination already exists")
    tmp = _validated_staging_path(
        path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp"))
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    with _staging_parent(path) as (path, parent_fd):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp.name if parent_fd is not None else tmp, flags, 0o600,
                     **({"dir_fd": parent_fd} if parent_fd is not None else {}))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            _validated_staging_path(path)
            if parent_fd is None:
                os.replace(tmp, path)
            else:
                os.replace(tmp.name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        finally:
            try:
                if parent_fd is None:
                    tmp.unlink()
                else:
                    os.unlink(tmp.name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def cleanup_expired_model_artifacts(*, now: float | None = None) -> int:
    root = _validated_staging_path(get_model_workspace_root() / ".tmp")
    now = time.time() if now is None else now
    removed = 0
    if not root.exists():
        return 0
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        dirs[:] = [name for name in dirs if not (base_path / name).is_symlink()]
        for name in files:
            if not name.endswith(".receipt.json"):
                continue
            receipt = base_path / name
            try:
                receipt = _validated_staging_path(receipt)
                data = json.loads(receipt.read_text("utf-8"))
                expires = float(data.get("expires_at", 0))
                # A receipt can describe only its sibling artifact, never an arbitrary path.
                staged = _validated_staging_path(
                    receipt.with_name(name[:-len(".receipt.json")]))
                recorded = _validated_staging_path(Path(str(data.get("staged_path", ""))))
                if recorded != staged:
                    continue
            except (OSError, ValueError, TypeError):
                continue
            if expires and expires <= now:
                try:
                    staged = _validated_staging_path(staged)
                    if staged.is_file():
                        staged.unlink()
                    _validated_staging_path(receipt).unlink(missing_ok=True)
                    removed += 1
                except OSError:
                    continue
    return removed

def publish_internal_artifact_for_model(
    source: InternalArtifactSource,
    *,
    namespace: str = "artifact",
    task_id: str | None = None,
    session_id: str | None = None,
) -> StagedArtifact:
    if not isinstance(source, InternalArtifactSource) or source._trust_token is not _TRUST_TOKEN:
        raise ModelFilePolicyError("untrusted internal artifact provenance")
    if not namespace.replace("-", "").replace("_", "").isalnum():
        raise ModelFilePolicyError("invalid staging namespace")
    src = source.path.expanduser()
    try:
        lst = src.lstat()
        if stat.S_ISLNK(lst.st_mode):
            raise ModelFilePolicyError("internal artifact source may not be a symlink")
        src = src.resolve(strict=True)
    except OSError as exc:
        raise ModelFilePolicyError("internal artifact source is unavailable") from exc
    if not src.is_file():
        raise ModelFilePolicyError("internal artifact source is not a regular file")

    max_file, session_quota, profile_quota, ttl = _staging_limits()
    size = src.stat().st_size
    if size > max_file:
        raise ModelFilePolicyError("internal artifact exceeds per-file staging limit")

    root = get_model_workspace_root()
    stage_base = (
        root / ".tmp" / "inbound"
        if namespace == "inbound"
        else root / ".tmp" / "model-artifacts" / namespace
    )
    scope_raw = session_id or task_id or "default"
    scope = hashlib.sha256(str(scope_raw).encode("utf-8")).hexdigest()[:16]

    with _profile_staging_lock(root):
        scope_dir = _validated_staging_path(stage_base / scope, root=root)
        scope_dir.mkdir(parents=True, exist_ok=True)
        scope_dir = _validated_staging_path(scope_dir, root=root)
        cleanup_expired_model_artifacts()
        if _safe_tree_bytes(root / ".tmp") + size > profile_quota:
            raise ModelFilePolicyError("profile staging quota exceeded")
        if _safe_tree_bytes(scope_dir) + size > session_quota:
            raise ModelFilePolicyError("task/session staging quota exceeded")

        # The random basename supplies the identity. A bounded ASCII extension is
        # only a delivery hint for existing image/audio/video/document consumers;
        # no source basename or path authority is inherited, and mode stays 0600.
        suffix = src.suffix.lower()
        if not (1 < len(suffix) <= 9 and suffix.isascii() and suffix[1:].isalnum()):
            suffix = ""
        opaque = secrets.token_hex(20) + suffix
        final = _validated_staging_path(scope_dir / opaque, root=root)
        receipt_path = _validated_staging_path(final.with_name(final.name + ".receipt.json"), root=root)
        if final.exists() or receipt_path.exists():
            raise ModelFilePolicyError("staging destination already exists")
        tmp = _validated_staging_path(scope_dir / f".{opaque}.{secrets.token_hex(8)}.tmp", root=root)
        digest = hashlib.sha256()
        copied = 0
        with _staging_parent(final) as (final, parent_fd):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(tmp.name if parent_fd is not None else tmp, flags, 0o600,
                         **({"dir_fd": parent_fd} if parent_fd is not None else {}))
            try:
                with src.open("rb") as rf, os.fdopen(fd, "wb") as wf:
                    while True:
                        chunk = rf.read(1024 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > max_file:
                            raise ModelFilePolicyError("internal artifact exceeds per-file staging limit")
                        digest.update(chunk)
                        wf.write(chunk)
                    wf.flush()
                    os.fsync(wf.fileno())
                # Count the completed temp file before publication. This closes the
                # source-size drift gap while the same profile lock is still held.
                if _safe_tree_bytes(root / ".tmp") > profile_quota:
                    raise ModelFilePolicyError("profile staging quota exceeded")
                if _safe_tree_bytes(scope_dir) > session_quota:
                    raise ModelFilePolicyError("task/session staging quota exceeded")
                _validated_staging_path(final)
                if parent_fd is None:
                    os.replace(tmp, final)
                else:
                    os.replace(tmp.name, final.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            finally:
                try:
                    if parent_fd is None:
                        tmp.unlink()
                    else:
                        os.unlink(tmp.name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass

        created = time.time()
        expires = created + ttl
        receipt = {
            "source_class": source.source_class,
            "source_id": source.source_id,
            "source_path_hash": hashlib.sha256(str(src).encode("utf-8")).hexdigest(),
            "staged_path": str(final),
            "size": copied,
            "sha256": digest.hexdigest(),
            "created_at": created,
            "expires_at": expires,
            "task_id": task_id,
            "session_id": session_id,
            "namespace": namespace,
            "extension_hint": suffix,
        }
        try:
            _atomic_json(receipt_path, receipt)
        except Exception:
            _validated_staging_path(final).unlink(missing_ok=True)
            raise
        return StagedArtifact(
            path=final, receipt_path=receipt_path, size=copied,
            sha256=digest.hexdigest(), created_at=created, expires_at=expires)
