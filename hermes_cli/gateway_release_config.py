"""Admission of a pinned startup normalization, never permission for config drift.

The original byte identity remains in the transaction. A second, certified byte
identity is admitted only after the complete typed YAML state matches a pure
projection of the reviewed migrations and a fresh candidate bootstrap record.
No configuration, selector, service or bootstrap record is written here.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

from hermes_cli.gateway_release import ReleaseError


SOURCES = (
    "hermes_cli/config.py", "hermes_cli/config_migrations.py",
    "hermes_cli/config_defaults.py", "hermes_cli/post_update.py",
    "hermes_cli/boot_bootstrap.py", "hermes_cli/gateway_release_config.py",
)
COMPATIBILITY_SOURCES = (
    "hermes_cli/config.py", "hermes_cli/config_migrations.py",
    "hermes_cli/config_defaults.py", "hermes_cli/config_effective.py", "gateway/config.py",
)
MODEL = "HERMES_STARTUP_NORMALIZATION_46_49_V1"
ROOT = Path(__file__).resolve().parents[1]


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ReleaseError("duplicate migration evidence key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def _fingerprint(value):
    return {"dev": value.st_dev, "ino": value.st_ino,
            "mtime_ns": value.st_mtime_ns, "size": value.st_size}


def _snapshot(path, *, limit=2 * 1024 * 1024):
    path = Path(path)
    if path != path.resolve():
        raise ReleaseError("config evidence path is not canonical")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ReleaseError("config evidence requires a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        initial = _fingerprint(before)
        if (len(raw) > limit or initial != _fingerprint(os.fstat(fd))
                or initial != _fingerprint(path.stat())):
            raise ReleaseError("config evidence changed while being read")
        return raw, initial
    finally:
        os.close(fd)


def _typed(value, seen=None):
    """Do not equate bool/int/float or permit duplicate/recursive YAML state."""
    seen = set() if seen is None else seen
    kind = type(value)
    if kind in (dict, list):
        if id(value) in seen:
            raise ReleaseError("shared or recursive config containers are not supported")
        seen.add(id(value))
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise ReleaseError("config mapping keys must be strings")
            return ["map", [[key, _typed(value[key], seen)] for key in sorted(value)]]
        return ["list", [_typed(item, seen) for item in value]]
    if value is None:
        return ["null"]
    if kind is bool:
        return ["bool", value]
    if kind is int:
        return ["int", str(value)]
    if kind is float and math.isfinite(value):
        return ["float", value.hex()]
    if kind is str:
        return ["str", value]
    raise ReleaseError("unsupported config value type")


def semantic_sha256(value):
    return _sha(json.dumps(_typed(value), ensure_ascii=False, separators=(",", ":")).encode())


def _yaml(raw):
    from ruamel.yaml import YAML
    from ruamel.yaml.constructor import SafeConstructor
    from ruamel.yaml.error import YAMLError
    class StrictConstructor(SafeConstructor):
        def flatten_mapping(self, node):
            # Merged mappings conceal duplicate/overridden state: fail closed.
            if any(key.tag == "tag:yaml.org,2002:merge" for key, _ in node.value):
                raise ReleaseError("config YAML merge keys are not supported")
            return super().flatten_mapping(node)
    parser = YAML(typ="safe", pure=True)
    parser.version = (1, 1)  # Same schema as Hermes' existing config reader.
    parser.Constructor = StrictConstructor
    parser.allow_duplicate_keys = False
    try:
        value = parser.load(raw)
        if type(value) is not dict:
            raise ReleaseError("config must be a mapping")
        semantic_sha256(value)
        return value
    except (ValueError, UnicodeError, YAMLError, RecursionError) as exc:
        raise ReleaseError("config cannot be semantically admitted") from exc


def expected_normalization(value):
    """Exactly the seeded-default removals in migrations 47, 48 and 49."""
    version = value.get("_config_version")
    if type(version) is not int or version not in (46, 47, 48, 49):
        raise ReleaseError("no reviewed startup migration path for this config version")
    result, changes = copy.deepcopy(value), []
    compression, terminal = result.get("compression"), result.get("terminal")
    if version < 47 and type(compression) is dict:
        threshold = compression.get("threshold_tokens")
        if type(threshold) is int and threshold == 256000:
            del compression["threshold_tokens"]
            changes.append("compression.threshold_tokens:REMOVE_SEEDED_DEFAULT")
    if version < 48 and type(terminal) is dict:
        legacy = ("nikolaik/python-nodejs:python3.11-nodejs20",
                  "nikolaik/python-nodejs:python3.14-nodejs22")
        for key in ("docker_image", "modal_image", "daytona_image", "singularity_image"):
            defaults = tuple("docker://" + item for item in legacy) if key == "singularity_image" else legacy
            if type(terminal.get(key)) is str and terminal[key] in defaults:
                del terminal[key]
                changes.append("terminal." + key + ":REMOVE_SEEDED_DEFAULT")
    if version < 49 and type(terminal) is dict and terminal.get("vercel_runtime") == "node24":
        del terminal["vercel_runtime"]
        changes.append("terminal.vercel_runtime:REMOVE_SEEDED_DEFAULT")
    if version < 49:
        result["_config_version"] = 49
        changes.append("_config_version:ADVANCE_TO_49")
    return result, changes


def _source_hashes(repo, names):
    repo = Path(repo)
    return {name: _sha(_snapshot(repo / name)[0]) for name in names}


def _supported_target():
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    if type(DEFAULT_CONFIG.get("_config_version")) is not int or DEFAULT_CONFIG["_config_version"] != 49:
        raise ReleaseError("startup migration contract has no reviewed target schema")


def _previous_repo(previous):
    root = Path(previous["release"])
    if root != root.resolve():
        raise ReleaseError("previous config release is not canonical")
    manifest = json.loads(_snapshot(root / "manifest.json")[0])
    repo = root / manifest["repo"]
    if (repo != repo.resolve() or not repo.is_dir() or not repo.is_relative_to(root)
            or (previous.get("repo") is not None and previous["repo"] != str(repo))):
        raise ReleaseError("previous config implementation escapes its release")
    return repo


def prepare_config_contract(config, candidate, previous, home):
    """Legacy releases retain strict byte guards; only the new pinned producer admits migration."""
    repo = Path(candidate["repo"])
    if not (repo / "hermes_cli/gateway_release_config.py").exists():
        return None
    _supported_target()
    config, home = Path(config), Path(home)
    if config != home / "config.yaml":
        raise ReleaseError("startup migration contract requires the default bound config path")
    sources = _source_hashes(repo, SOURCES)
    if sources != _source_hashes(ROOT, SOURCES):
        raise ReleaseError("candidate migration implementation is not the reviewed contract")
    raw, fingerprint = _snapshot(config)
    value = _yaml(raw)
    projected, changes = expected_normalization(value)
    previous_repo = _previous_repo(previous)
    previous_sources = _source_hashes(previous_repo, COMPATIBILITY_SOURCES)
    if previous_sources != _source_hashes(repo, COMPATIBILITY_SOURCES):
        raise ReleaseError("previous service has no proven forward-compatible config implementation")
    key = _sha(str(repo.resolve()).encode())[:16]
    record = home / "installs" / key / "bootstrap" / "default.json"
    old_record = _sha(_snapshot(record)[0]) if record.exists() else None
    return {"schema": 1, "model": MODEL, "pre_sha256": _sha(raw),
            "pre_fingerprint": fingerprint, "pre_semantic_sha256": semantic_sha256(value),
            "from_version": value["_config_version"], "to_version": 49,
            "expected_semantic_sha256": semantic_sha256(projected), "permitted_changes": changes,
            "source_hashes": sources, "bootstrap_record": str(record),
            "bootstrap_before_sha256": old_record,
            "previous_compatibility": {"kind": "IDENTICAL_CONFIG_IMPLEMENTATION",
                                       "repo": str(previous_repo), "sources": previous_sources}}


def check_config_contract(data):
    contract = data.get("config_contract")
    if contract is None:
        return
    _supported_target()
    if type(contract.get("schema")) is not int or contract["schema"] != 1 or contract.get("model") != MODEL:
        raise ReleaseError("unknown config migration contract")
    if contract["pre_sha256"] != data["config_hash"]:
        raise ReleaseError("config contract baseline differs from original receipt")
    if _source_hashes(data["candidate"]["repo"], SOURCES) != contract["source_hashes"]:
        raise ReleaseError("candidate migration implementation drift")
    _check_previous_compatibility(contract)
    raw, fingerprint = _snapshot(data["config"])
    if (_sha(raw) != contract["pre_sha256"] or fingerprint != contract["pre_fingerprint"]
            or semantic_sha256(_yaml(raw)) != contract["pre_semantic_sha256"]):
        raise ReleaseError("configuration baseline drift")
    value = _yaml(raw)
    projected, changes = expected_normalization(value)
    if (type(contract.get("from_version")) is not int or contract["from_version"] != value["_config_version"]
            or type(contract.get("to_version")) is not int or contract["to_version"] != 49
            or contract["permitted_changes"] != changes
            or contract["expected_semantic_sha256"] != semantic_sha256(projected)
            or contract["source_hashes"] != _source_hashes(ROOT, SOURCES)):
        raise ReleaseError("prepared config contract does not match the reviewed projection")


def _check_previous_compatibility(contract):
    proof = contract["previous_compatibility"]
    if (proof.get("kind") != "IDENTICAL_CONFIG_IMPLEMENTATION"
            or _source_hashes(proof["repo"], COMPATIBILITY_SOURCES) != proof["sources"]):
        raise ReleaseError("retained service config compatibility drift")


def validate_config_transition(data, *, candidate_process=None):
    """Read-only certification. Caller must fsync/read back this entire state before proceeding."""
    if data.get("config_state") is not None:
        guard_config_baseline(data)
        return data["config_state"]
    raw, fingerprint = _snapshot(data["config"])
    digest = _sha(raw)
    contract = data.get("config_contract")
    if digest == data["config_hash"]:
        if contract and fingerprint != contract["pre_fingerprint"]:
            raise ReleaseError("unexpected config rewrite without migration")
        return {"schema": 1, "kind": "NO_CONFIG_CHANGE", "accepted_sha256": digest,
                "fingerprint": fingerprint}
    if not contract or contract["from_version"] >= contract["to_version"]:
        raise ReleaseError("unexpected config drift; no reviewed migration is authorized")
    attempt = data.get("startup_attempt") or {}
    not_before = attempt.get("not_before")
    if (type(not_before) not in (float, int) or not math.isfinite(not_before)
            or attempt.get("candidate_commit") != data["candidate"]["commit"]):
        raise ReleaseError("startup migration has no durable candidate launch boundary")
    if (_source_hashes(data["candidate"]["repo"], SOURCES) != contract["source_hashes"]
            or contract["source_hashes"] != _source_hashes(ROOT, SOURCES)):
        raise ReleaseError("startup migration code identity mismatch")
    value = _yaml(raw)
    if (type(value.get("_config_version")) is not int or value["_config_version"] != contract["to_version"]
            or semantic_sha256(value) != contract["expected_semantic_sha256"]):
        raise ReleaseError("unexpected semantic config drift outside the migration contract")
    try:
        record_raw, record_fingerprint = _snapshot(contract["bootstrap_record"])
        record = _strict_json(record_raw)
        result = record["results"]["migrate_config"]
        evidence = result["migration_evidence"]
        if (type(record.get("schemaVersion")) is not int or record["schemaVersion"] != 1
                or record.get("identity") != data["candidate"]["commit"]
                or result.get("ok") is not True
                or result.get("migrated") != f"{contract['from_version']}->{contract['to_version']}"
                or type(evidence) is not dict or type(evidence.get("schema")) is not int or evidence["schema"] != 1
                or _sha(record_raw) == contract.get("bootstrap_before_sha256")):
            raise ReleaseError("startup migration evidence is malformed/stale")
        expected = {"pre_sha256": data["config_hash"], "post_sha256": digest,
                    "config_path": data["config"], "from_version": contract["from_version"],
                    "to_version": contract["to_version"], "source_hashes": contract["source_hashes"],
                    "pre_fingerprint": contract["pre_fingerprint"], "post_fingerprint": fingerprint,
                    "producer_uid": data["owner_uid"]}
        fields = set(expected) | {"schema", "producer_pid", "started_at", "finished_at"}
        if set(evidence) != fields:
            raise ReleaseError("unreviewed migration evidence fields")
        if any(_typed(evidence.get(key)) != _typed(value) for key, value in expected.items()):
            raise ReleaseError("startup migration evidence does not match exact config/code identity")
        started, finished = evidence.get("started_at"), evidence.get("finished_at")
        if (type(started) not in (float, int) or type(finished) not in (float, int)
                or not math.isfinite(started) or not math.isfinite(finished)
                or not not_before <= started <= finished <= time.time() + 1
                or type(evidence.get("producer_pid")) is not int or evidence["producer_pid"] <= 0):
            raise ReleaseError("startup migration evidence is not from this candidate launch")
        if candidate_process is not None and (
                candidate_process.get("uid") != data["owner_uid"]
                or candidate_process.get("executable") != data["candidate"]["executable"]
                or candidate_process.get("release") != data["candidate"]["release"]
                or candidate_process.get("healthy") is not True
                or candidate_process.get("pid") != evidence["producer_pid"]):
            raise ReleaseError("startup migration producer/process identity mismatch")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ReleaseError("durable startup migration evidence is unavailable/malformed") from exc
    _check_previous_compatibility(contract)
    return {"schema": 1, "kind": "EXPECTED_CONFIG_MIGRATION", "accepted_sha256": digest,
            "fingerprint": fingerprint, "model": MODEL,
            "migration_evidence": evidence, "bootstrap_record_sha256": _sha(record_raw),
            "bootstrap_record_fingerprint": record_fingerprint,
            "previous_compatibility": contract["previous_compatibility"],
            "service_rollback": "FORWARD_COMPATIBLE_CONFIG_NO_DOWNGRADE"}


def guard_config_baseline(data):
    state = data.get("config_state")
    raw, fingerprint = _snapshot(data["config"])
    if state is None:
        if _sha(raw) != data["config_hash"]:
            raise ReleaseError("configuration baseline drift")
        return
    if (type(state.get("schema")) is not int or state["schema"] != 1
            or state.get("kind") not in ("NO_CONFIG_CHANGE", "EXPECTED_CONFIG_MIGRATION")):
        raise ReleaseError("config baseline is not a certified transition")
    if _sha(raw) != state["accepted_sha256"] or fingerprint != state["fingerprint"]:
        raise ReleaseError("config changed after the validated startup baseline")
    if state["kind"] == "EXPECTED_CONFIG_MIGRATION":
        _check_previous_compatibility(data["config_contract"])
