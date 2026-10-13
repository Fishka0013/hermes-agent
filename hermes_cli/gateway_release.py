"""Rollback-first macOS release selection; atomic disk publication, verified process transition.

Preparation is read-only against the service. Activation never builds a release
or regenerates service semantics. An unaccepted transition owns a durable slot
until accepted or rolled back, even when its CLI process exits unexpectedly.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import time

from hermes_cli.gateway_release_errors import ReleaseError


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ReleaseError("release metadata is not a regular file")
        return stream.read()


def atomic_publish(path: Path, data: bytes, *, mode: int = 0o600, metadata_source: Path | None = None) -> None:
    """Same-filesystem temporary file, file fsync, replace, directory fsync."""
    if path.is_symlink() or path.parent != path.parent.resolve():
        raise ReleaseError("selector/receipt path is symlinked")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)  # New file retains the previous selector's mode.
            stream.write(data)
            stream.flush()
            if metadata_source is not None:
                from hermes_cli.gateway_release_metadata import copy_metadata
                copy_metadata(metadata_source, Path(temporary))
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _json(path: Path, value: dict):
    atomic_publish(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def candidate_identity(root: Path) -> dict:
    root = Path(root).absolute()
    if root != root.resolve():
        raise ReleaseError("candidate release path is not canonical")
    manifest_bytes = _file(root / "manifest.json")
    manifest = json.loads(manifest_bytes)
    source = manifest.get("source", {})
    if not re.fullmatch(r"[a-f0-9]{40}", source.get("commit", "")):
        raise ReleaseError("candidate has no exact source identity")
    runtime = manifest["runtime"]
    paths = {"repo": root / runtime["repoDir"], "executable": root / runtime["storePython"],
             "launcher": root / runtime["commands"]["hermes"], "site": root / runtime["sitePackages"]}
    for name, path in paths.items():
        if not path.exists() or not path.resolve().is_relative_to(root):
            raise ReleaseError("candidate runtime escapes its release: " + name)
    # A completed builder receipt covers source, interpreter, dependencies and
    # launchers. Rehash on every admission; never silently repair changed bytes.
    from hermes_cli.release_inventory import verify_inventory
    inventory = verify_inventory(root)
    if inventory["commit"] != source["commit"]:
        raise ReleaseError("candidate inventory/manifest commit mismatch")
    return {"release": str(root), "commit": source["commit"], "tree": source["tree"],
            "manifest_hash": _hash(manifest_bytes), "inventory_hash": _hash(_file(root / "release-inventory.json")),
            **{name: str(path.resolve()) for name, path in paths.items()}}


def previous_identity(root: Path, launcher: Path) -> dict:
    root = root.resolve(strict=True)
    manifest = json.loads(_file(root / "manifest.json"))
    repo = root / manifest["repo"]
    runtime = manifest.get("runtime", {})
    executable = root / runtime.get("storePython", "tools/python-3.14.7+20260901-darwin-arm64/bin/python3")
    if not launcher.resolve().is_relative_to(root) or not executable.resolve().is_relative_to(root):
        raise ReleaseError("previous release paths escape their retained payload")
    names = ["manifest.json", str(launcher.relative_to(root)), str(executable.resolve().relative_to(root)),
             str((repo / "install-stamp.json").relative_to(root))]
    names += [str((repo / name).relative_to(root)) for name in (
        "gateway/run.py", "tools/terminal_tool.py", "tools/process_registry.py", "tools/environments/local.py",
        "tools/terminal_tool_backends.py", "tools/terminal_tool_background.py", "tools/terminal_tool_guards.py",
        "agent/model_file_policy.py")]
    return {"release": str(root), "launcher": str(launcher.resolve()), "executable": str(executable.resolve()),
            "commit": manifest.get("commit") or manifest["source"]["commit"],
            "file_hashes": {name: _hash(_file(root / name)) for name in names}}


def _candidate_plist(previous: bytes, old_launcher: str, candidate: dict) -> bytes:
    plist = plistlib.loads(previous)
    arguments = plist.get("ProgramArguments")
    if not isinstance(arguments, list):
        raise ReleaseError("supported selection requires ProgramArguments")
    found = 0
    replacement = []
    for value in arguments:
        if not isinstance(value, str):
            raise ReleaseError("unsupported LaunchAgent argument")
        found += value.count(old_launcher)
        replacement.append(value.replace(old_launcher, candidate["launcher"]))
    if found < 1:
        raise ReleaseError("previous launcher binding absent")
    plist["ProgramArguments"] = replacement
    result = plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=False)
    # No stale release references in unrelated keys may be silently inherited.
    if old_launcher.encode() in result:
        raise ReleaseError("unresolved previous launcher reference")
    return result


class MacLaunchService:
    """Bounded native backend. Tests inject a fake service, never live launchctl mutations."""
    def __init__(self, home: Path, label: str, domain: str):
        self.home, self.label, self.domain = home, label, domain

    def capture(self, expected: dict) -> dict:
        result = subprocess.run(["launchctl", "print", f"{self.domain}/{self.label}"],
                                capture_output=True, text=True, timeout=5, check=True)
        pid_match = re.search(r"^\s*pid = (\d+)\s*$", result.stdout, re.M)
        runs_match = re.search(r"^\s*runs = (\d+)\s*$", result.stdout, re.M)
        if not pid_match or "state = running" not in result.stdout:
            raise ReleaseError("LaunchAgent is not running")
        service_pid = int(pid_match[1])
        rows = subprocess.check_output(["ps", "-axo", "pid=,ppid=,uid=,comm="], text=True, timeout=5)
        processes = {}
        for row in rows.splitlines():
            fields = row.strip().split(None, 3)
            if len(fields) == 4:
                processes[int(fields[0])] = (int(fields[1]), int(fields[2]), fields[3])
        descendants = {service_pid}
        for _ in range(8):
            descendants |= {pid for pid, (parent, _, _) in processes.items() if parent in descendants}
        matches = []
        for pid in descendants:
            if pid not in processes:
                continue
            parent, uid, executable = processes[pid]
            if uid != os.getuid() or str(Path(executable).resolve()) != expected["executable"]:
                continue
            argv = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True, timeout=5)
            if "gateway run" in argv and "--run-module hermes_cli.stderr_timestamp" not in argv:
                start = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True, timeout=5).strip()
                matches.append({"pid": pid, "parent": parent, "uid": uid, "executable": expected["executable"],
                                "invoked_executable": executable,
                                "start": start, "argv_hash": _hash(argv.encode())})
        if len(matches) != 1:
            raise ReleaseError("running Gateway release/process chain cannot be uniquely proven")
        return {**matches[0], "service_pid": service_pid, "runs": int(runs_match[1]) if runs_match else None,
                "release": expected["release"], "launch_state": "running"}

    def stop(self):
        result = subprocess.run(["launchctl", "bootout", f"{self.domain}/{self.label}"],
                                capture_output=True, text=True, timeout=45)
        if result.returncode not in (0, 3, 113):
            raise ReleaseError("controlled launchd bootout failed")

    def start(self, plist: Path):
        subprocess.run(["launchctl", "bootstrap", self.domain, str(plist)],
                       capture_output=True, timeout=30, check=True)

    def verify(self, expected: dict) -> dict:
        from gateway.control_socket import query_gateway_control
        deadline = time.monotonic() + 75
        stable, previous = 0, None
        while time.monotonic() < deadline:
            try:
                identity = self.capture(expected)
                live = query_gateway_control(self.home, "identify")
                status = query_gateway_control(self.home, "status")
                okay = (live and live.get("pid") == identity["pid"] and live.get("code_sha") == expected["commit"]
                        and status and status.get("answering_pid") == identity["pid"]
                        and status.get("gateway_state") == "running")
                if okay:
                    fingerprint = (identity["pid"], identity["start"], identity["runs"])
                    stable = stable + 1 if fingerprint == previous else 1
                    previous = fingerprint
                    if stable >= 3:
                        return {**identity, "healthy": True}
                else:
                    stable, previous = 0, None
            except (OSError, subprocess.SubprocessError, ReleaseError):
                stable, previous = 0, None
            time.sleep(1)
        raise ReleaseError("Gateway identity/health did not stabilize")


class ReleaseTransaction:
    def __init__(self, receipt: Path, *, service=None, publisher=atomic_publish):
        self.receipt = Path(receipt).resolve()
        self.data = json.loads(_file(self.receipt))
        self.publisher = publisher
        self.service = service or MacLaunchService(Path(self.data["home"]), self.data["label"], self.data["domain"])

    @classmethod
    def prepare(cls, receipt: Path, *, plist: Path, config: Path, candidate: Path, previous: dict,
                home: Path, domain: str, service=None):
        receipt, plist, config, home = map(lambda p: Path(p).absolute(), (receipt, plist, config, home))
        if receipt.exists() or plist != plist.resolve() or config != config.resolve():
            raise ReleaseError("preparation requires a new receipt and canonical selector/config")
        before = _file(plist)
        metadata = plist.stat()
        if metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
            raise ReleaseError("selector ownership/link count is unsafe")
        from hermes_cli.gateway_release_metadata import metadata_hash, copy_metadata
        metadata_identity = metadata_hash(plist)
        candidate_data = candidate_identity(candidate)
        label = plistlib.loads(before)["Label"]
        backend = service or MacLaunchService(home, label, domain)
        process = backend.capture(previous)
        selected = _candidate_plist(before, previous["launcher"], candidate_data)
        if _file(plist) != before:
            raise ReleaseError("selector drifted during preparation")
        from hermes_cli.gateway_release_config import prepare_config_contract
        config_contract = prepare_config_contract(config, candidate_data, previous, home)
        config_hash = _hash(_file(config))
        if config_contract is not None and config_hash != config_contract["pre_sha256"]:
            raise ReleaseError("config drifted during preparation")
        receipt.parent.mkdir(parents=True, exist_ok=True)
        template = receipt.with_name(receipt.name + ".previous-selector.plist")
        descriptor = os.open(template, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(before)
            stream.flush()
            copy_metadata(plist, template)
            os.fsync(stream.fileno())
        if metadata_hash(template) != metadata_identity:
            raise ReleaseError("selector metadata drifted during preparation")
        data = {"schema": 1, "state": "PREPARED", "home": str(home), "label": label, "domain": domain,
                "plist": str(plist), "config": str(config), "config_hash": config_hash,
                "previous": previous, "candidate": candidate_data, "previous_process": process,
                "previous_plist": base64.b64encode(before).decode(), "previous_plist_hash": _hash(before),
                "candidate_plist": base64.b64encode(selected).decode(), "candidate_plist_hash": _hash(selected),
                "plist_mode": stat.S_IMODE(metadata.st_mode), "owner_uid": os.getuid(),
                "metadata_template": str(template), "plist_metadata_hash": metadata_identity}
        if config_contract is not None:
            data["config_contract"] = config_contract
        _json(receipt, data)
        return cls(receipt, service=backend)

    def _save(self, state: str, **details):
        self.data.update(state=state, **details)
        _json(self.receipt, self.data)

    @contextmanager
    def _owner(self):
        import fcntl
        key = _hash(self.data["plist"].encode())[:24]
        root = Path(self.data["home"]) / "deployment-locks"
        if root.is_symlink():
            raise ReleaseError("deployment lock path is symlinked")
        root.mkdir(exist_ok=True)
        lock_path, pending = root / (key + ".lock"), root / (key + ".pending.json")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ReleaseError("another release transaction is active") from exc
            if pending.exists():
                owner = json.loads(_file(pending)).get("receipt")
                if owner != str(self.receipt):
                    raise ReleaseError("an unaccepted/stale transaction owns this selector; rollback it first")
            self.data = json.loads(_file(self.receipt))  # State is admitted under the OS owner lock.
            yield pending
        finally:
            os.close(fd)

    def check(self, *, process=True):
        from hermes_cli.gateway_release_config import check_config_contract
        self._check_metadata()
        if _hash(_file(Path(self.data["config"]))) != self.data["config_hash"]:
            raise ReleaseError("configuration baseline drift")
        check_config_contract(self.data)
        if candidate_identity(Path(self.data["candidate"]["release"])) != self.data["candidate"]:
            raise ReleaseError("candidate identity drift")
        current = _hash(_file(Path(self.data["plist"])))
        if current != self.data["previous_plist_hash"]:
            raise ReleaseError("selector CAS mismatch")
        if process and self.service.capture(self.data["previous"]) != self.data["previous_process"]:
            raise ReleaseError("Gateway process baseline drift")
        if not Path(self.data["previous"]["launcher"]).is_file() or not Path(self.data["previous"]["executable"]).is_file():
            raise ReleaseError("previous release is unavailable; rollback would require rebuilding")
        for name, expected_hash in self.data["previous"].get("file_hashes", {}).items():
            if _hash(_file(Path(self.data["previous"]["release"]) / name)) != expected_hash:
                raise ReleaseError("retained rollback release changed")
        return {"ready": True, "state": self.data["state"], "rollback_ready": True}

    def _check_metadata(self):
        from hermes_cli.gateway_release_metadata import metadata_hash
        template = Path(self.data["metadata_template"])
        if (_hash(_file(template)) != self.data["previous_plist_hash"]
                or metadata_hash(template) != self.data["plist_metadata_hash"]
                or metadata_hash(Path(self.data["plist"])) != self.data["plist_metadata_hash"]):
            raise ReleaseError("selector/rollback metadata drift")

    def _publish(self, value: bytes, *, expected_hash: str):
        self._check_metadata()
        if _hash(_file(Path(self.data["plist"]))) != expected_hash:
            raise ReleaseError("selector CAS mismatch immediately before publication")
        self.publisher(Path(self.data["plist"]), value, mode=self.data["plist_mode"],
                       metadata_source=Path(self.data["metadata_template"]))

    def _certify_config(self, *, process=None):
        from hermes_cli.gateway_release_config import validate_config_transition, guard_config_baseline
        state = validate_config_transition(self.data, candidate_process=process)
        if self.data.get("config_state") is None:
            # Embed the bounded bootstrap evidence into our own fsynced receipt.
            # Mere existence of the producer's record is not a durability claim.
            self._save(self.data["state"], config_state=state)
            if json.loads(_file(self.receipt)) != self.data:
                raise ReleaseError("certified config baseline durable read-back failed")
        guard_config_baseline(self.data)

    def _guard_config(self):
        from hermes_cli.gateway_release_config import guard_config_baseline
        guard_config_baseline(self.data)

    def activate(self):
        with self._owner() as pending:
            if self.data["state"] != "PREPARED":
                raise ReleaseError("transaction is not PREPARED; do not replay activation")
            _json(pending, {"receipt": str(self.receipt)})
            try:
                self.check()
            except Exception:
                pending.unlink()
                raise
            self._save("PUBLISHING")  # Durable before selector publication: interruption is recoverable.
            try:
                self._publish(base64.b64decode(self.data["candidate_plist"]), expected_hash=self.data["previous_plist_hash"])
                self._save("SELECTED")
                self.service.stop()
                self._save("BOOTSTRAP_REQUESTED", startup_attempt={
                    "not_before": time.time(), "candidate_commit": self.data["candidate"]["commit"]})
                self.service.start(Path(self.data["plist"]))
                live = self.service.verify(self.data["candidate"])
                self._save("CANDIDATE_VERIFIED", candidate_process=live)
                if live["executable"] != self.data["candidate"]["executable"]:
                    raise ReleaseError("wrong candidate executable")
                self._certify_config(process=live)
                self._save("ACTIVE_UNACCEPTED", candidate_process=live)
                return {"activated": True, "accepted": False, "process": live}
            except Exception as exc:
                self._save("ACTIVATION_FAILED", failure_kind=type(exc).__name__, failure_error=str(exc))
                self._rollback(pending)
                raise ReleaseError("candidate activation failed; previous release restored") from exc

    def _rollback(self, pending: Path):
        plist = Path(self.data["plist"])
        current = _hash(_file(plist))
        if current not in {self.data["previous_plist_hash"], self.data["candidate_plist_hash"]}:
            self._save("ROLLBACK_FAILED", rollback_error="unexpected selector; refused to overwrite")
            raise ReleaseError("rollback failed: unexpected selector; STOP")
        try:
            # Restore the service even when certification fails. Retain the
            # owner and fail verification if config is unreviewed. A crashed
            # candidate can still have produced exact, fresh bootstrap evidence.
            config_error = None
            try:
                self._certify_config(process=self.data.get("candidate_process"))
            except Exception as exc:
                config_error = str(exc)
            self._save("ROLLING_BACK")
            self.service.stop()
            self._publish(base64.b64decode(self.data["previous_plist"]), expected_hash=current)
            self.service.start(plist)
            live = self.service.verify(self.data["previous"])
            if live["executable"] != self.data["previous"]["executable"]:
                raise ReleaseError("wrong rollback executable")
            if config_error is not None:
                raise ReleaseError("service restored, but config certification failed: " + config_error)
            self._guard_config()
            self._save("ROLLED_BACK", rollback_process=live, service_rollback="RESTORED",
                       config_rollback=("NOT_PERFORMED_FORWARD_COMPATIBLE_NORMALIZATION"
                                        if self.data["config_state"]["kind"] == "EXPECTED_CONFIG_MIGRATION"
                                        else "UNCHANGED"))
            pending.unlink(missing_ok=True)
            return {"rolled_back": True, "process": live}
        except Exception as exc:
            self._save("ROLLBACK_FAILED", rollback_error=type(exc).__name__, rollback_exact_error=str(exc))
            raise ReleaseError("rollback failed; STOP production work") from exc

    def rollback(self):
        with self._owner() as pending:
            if self.data["state"] in {"ROLLED_BACK", "ROLLBACK_FAILED"}:
                raise ReleaseError("rollback already completed/failed; STOP production work")
            if self.data["state"] == "PREPARED":
                pending.unlink(missing_ok=True)
                raise ReleaseError("no activation occurred; rollback is unnecessary")
            _json(pending, {"receipt": str(self.receipt)})
            return self._rollback(pending)

    def accept(self):
        from hermes_cli.gateway_canary import run_canaries
        with self._owner() as pending:
            if self.data["state"] != "ACTIVE_UNACCEPTED":
                raise ReleaseError("candidate is not awaiting acceptance")
            _json(pending, {"receipt": str(self.receipt)})
            try:
                if candidate_identity(Path(self.data["candidate"]["release"])) != self.data["candidate"]:
                    raise ReleaseError("candidate contents changed before acceptance")
                if _hash(_file(Path(self.data["plist"]))) != self.data["candidate_plist_hash"]:
                    raise ReleaseError("candidate selector drift")
                live = self.service.verify(self.data["candidate"])
                self._certify_config(process=live)
                evidence = run_canaries(Path(self.data["home"]), expected_pid=live["pid"],
                                       expected_handler=Path(self.data["candidate"]["repo"]) / "tools/terminal_tool.py")
                final = self.service.verify(self.data["candidate"])
                if final["pid"] != live["pid"] or final["start"] != live["start"]:
                    raise ReleaseError("Gateway restarted during live acceptance")
                if candidate_identity(Path(self.data["candidate"]["release"])) != self.data["candidate"]:
                    raise ReleaseError("candidate contents changed during acceptance")
                self._guard_config()
                self._save("ACCEPTED", acceptance=evidence, candidate_process=final)
                pending.unlink(missing_ok=True)
                return {"accepted": True, "process": final, "evidence": evidence}
            except Exception as exc:
                self._save("ACCEPTANCE_FAILED", failure_kind=type(exc).__name__, failure_error=str(exc))
                self._rollback(pending)
                raise ReleaseError("candidate acceptance failed; previous release restored") from exc

    def execute(self):
        """Macro B: one owner command, activate then accept or restore previous."""
        try:
            self.activate()
            return self.accept()
        except BaseException:
            self.data = json.loads(_file(self.receipt))
            if self.data["state"] not in {"PREPARED", "ROLLED_BACK", "ROLLBACK_FAILED", "ACCEPTED"}:
                self.rollback()
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "activate", "rollback", "accept", "execute"))
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    transaction = ReleaseTransaction(args.receipt)
    try:
        result = getattr(transaction, args.action)()
    except ReleaseError as exc:
        print(json.dumps({"ok": False, "error": str(exc), "state": transaction.data["state"]}))
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
