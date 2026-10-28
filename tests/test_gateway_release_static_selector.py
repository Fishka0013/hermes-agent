from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import plistlib

import pytest

from hermes_cli.gateway_release import SelectorReleaseTransaction, candidate_identity
from hermes_cli.gateway_release_errors import ReleaseError
from hermes_cli import gateway_release
from hermes_cli import gateway_launchd
from hermes_cli import gateway_release_config
from hermes_cli import gateway_release_selector as selector
from hermes_cli import release_inventory


def _selected(seed: str = "a") -> dict:
    h40 = (seed * 40)[:40]
    h64 = (seed * 64)[:64]
    root = f"/tmp/release-{seed}"
    return {
        "release": root,
        "commit": h40,
        "tree": h40,
        "manifest_hash": h64,
        "inventory_hash": h64,
        "repo": root + "/hermes-agent",
        "executable": root + "/tools/python/bin/python3",
        "launcher": root + "/bin/hermes",
        "site": root + "/venv/site-packages",
    }


def _line(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _security(provenance: str = "1" * 64) -> dict:
    return {"uid": 501, "gid": 20, "mode": 0o600, "flags": 4, "acl": "", "xattrs": {"com.apple.provenance": provenance}}


def _metadata_reader(value):
    return lambda _path: copy.deepcopy(value)


def _metadata_hasher(value):
    digest = selector.security_snapshot_hash(value)
    return lambda _path: digest


def _make_release(releases: Path, name: str, commit_char: str) -> tuple[Path, dict]:
    root = releases / name
    (root / "hermes-agent/tools").mkdir(parents=True)
    (root / "tools/python-3.14.7+20260901-darwin-arm64/bin").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "venv/lib/python3.14/site-packages").mkdir(parents=True)
    (root / "bin/hermes").write_text("#!/bin/sh\nexit 0\n")
    (root / "tools/python-3.14.7+20260901-darwin-arm64/bin/python3").write_text("python\n")
    (root / "hermes-agent/tools/terminal_tool.py").write_text("# test fixture\n")
    commit = commit_char * 40
    tree = chr(ord(commit_char) + 1) * 40
    manifest = {
        "schema": 1,
        "target": "darwin-arm64",
        "repo": "hermes-agent",
        "source": {"commit": commit, "tree": tree},
        "runtime": {
            "repoDir": "hermes-agent",
            "storePython": "tools/python-3.14.7+20260901-darwin-arm64/bin/python3",
            "commands": {"hermes": "bin/hermes"},
            "sitePackages": "venv/lib/python3.14/site-packages",
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    release_inventory.seal_inventory(root, commit)
    return root, candidate_identity(root)


@pytest.fixture
def release_pair(tmp_path):
    releases = tmp_path / "releases"
    releases.mkdir()
    a_root, a = _make_release(releases, "A", "a")
    b_root, b = _make_release(releases, "B", "c")
    return releases, (a_root, a), (b_root, b)


def test_runtime_origin_is_built_candidate():
    expected = os.environ["HNF_EXPECTED_RUNTIME_ROOT"]
    assert Path(selector.__file__).resolve().is_relative_to(Path(expected).resolve())
    assert Path(gateway_launchd.__file__).resolve().is_relative_to(Path(expected).resolve())


def test_generation_1_and_deterministic_hash():
    record = selector.make_record(1, None, _selected())
    same = selector.make_record(1, None, _selected())
    assert record == same
    assert record["record_hash"] == selector.record_hash(record)
    assert selector.parse_journal_bytes(selector.serialize_record(record))["head"] == record


def test_sequential_generations():
    a = selector.make_record(1, None, _selected("a"))
    b = selector.make_record(2, a["record_hash"], _selected("b"))
    parsed = selector.parse_journal_bytes(_line(a) + _line(b))
    assert [r["generation"] for r in parsed["records"]] == [1, 2]


def test_generation_gap_fails_closed():
    a = selector.make_record(1, None, _selected("a"))
    b = {"schema": 1, "generation": 3, "previous_record_hash": a["record_hash"], "selected": _selected("b")}
    b["record_hash"] = selector.record_hash(b)
    with pytest.raises(ReleaseError):
        selector.parse_journal_bytes(_line(a) + _line(b))


def test_broken_previous_hash_fails_closed():
    a = selector.make_record(1, None, _selected("a"))
    b = {"schema": 1, "generation": 2, "previous_record_hash": "0" * 64, "selected": _selected("b")}
    b["record_hash"] = selector.record_hash(b)
    with pytest.raises(ReleaseError):
        selector.parse_journal_bytes(_line(a) + _line(b))


def test_broken_record_hash_fails_closed():
    a = selector.make_record(1, None, _selected("a"))
    a["record_hash"] = "0" * 64
    with pytest.raises(ReleaseError):
        selector.parse_journal_bytes(_line(a))


def test_duplicate_keys_fail_closed():
    raw = b'{"schema":1,"schema":1,"generation":1,"previous_record_hash":null,"selected":{},"record_hash":"' + b"0" * 64 + b'"}\n'
    with pytest.raises(ReleaseError, match="duplicate"):
        selector.parse_journal_bytes(raw)


def test_unknown_fields_fail_closed():
    a = selector.make_record(1, None, _selected())
    a["extra"] = 1
    with pytest.raises(ReleaseError):
        selector.parse_journal_bytes(_line(a))


@pytest.mark.parametrize("field,value", [("schema", "1"), ("generation", True), ("selected", "x")])
def test_wrong_types_fail_closed(field, value):
    a = selector.make_record(1, None, _selected())
    a[field] = value
    with pytest.raises(ReleaseError):
        selector.parse_journal_bytes(_line(a))


def test_oversize_record_fails_closed():
    with pytest.raises(ReleaseError, match="64 KiB"):
        selector.parse_journal_bytes(b"x" * (selector.MAX_RECORD_BYTES + 1) + b"\n")


def test_oversize_journal_fails_closed():
    with pytest.raises(ReleaseError, match="16 MiB"):
        selector.parse_journal_bytes(b"x" * (selector.MAX_JOURNAL_BYTES + 1))


def test_incomplete_tail_is_uncommitted():
    a = selector.make_record(1, None, _selected())
    parsed = selector.parse_journal_bytes(_line(a) + b'{"schema":1')
    assert parsed["head"] == a
    assert parsed["incomplete_tail_ignored"] is True


def test_complete_invalid_tail_fails_closed():
    a = selector.make_record(1, None, _selected())
    with pytest.raises(ReleaseError):
        selector.parse_journal_bytes(_line(a) + b'{"schema":1}\n')


def test_exact_admitted_metadata_and_provenance_pass(tmp_path):
    baseline = _security()
    assert selector.validate_security_baseline(tmp_path / "selector", baseline,
        metadata_reader=_metadata_reader(baseline), metadata_hasher=_metadata_hasher(baseline)) == selector.security_snapshot_hash(baseline)


@pytest.mark.parametrize("mutator", [
    lambda v: v["xattrs"].pop("com.apple.provenance"),
    lambda v: v["xattrs"].__setitem__("com.apple.provenance", "2" * 64),
    lambda v: v["xattrs"].__setitem__("user.unrelated", "3" * 64),
    lambda v: v.__setitem__("acl", "changed"),
    lambda v: v.__setitem__("flags", 0),
    lambda v: v.__setitem__("uid", 502),
    lambda v: v.__setitem__("gid", 21),
    lambda v: v.__setitem__("mode", 0o644),
])
def test_metadata_drift_is_never_ignored_or_rebaselined(tmp_path, mutator):
    baseline = _security()
    observed = copy.deepcopy(baseline)
    mutator(observed)
    with pytest.raises(ReleaseError, match="metadata drift"):
        selector.validate_security_baseline(tmp_path / "selector", baseline,
            metadata_reader=_metadata_reader(observed), metadata_hasher=_metadata_hasher(observed))
    assert baseline == _security()


def test_valid_release_identity_passes(release_pair):
    releases, (_, a), _ = release_pair
    assert selector.validate_selected_identity(a, releases) == a


def test_release_outside_root_fails(tmp_path, release_pair):
    releases, _, _ = release_pair
    other = tmp_path / "other"
    other.mkdir()
    _, identity = _make_release(other, "X", "e")
    with pytest.raises(ReleaseError, match="direct child"):
        selector.validate_selected_identity(identity, releases)


def test_release_traversal_fails(release_pair):
    releases, (a_root, a), _ = release_pair
    bad = dict(a)
    bad["release"] = str(a_root.parent / "A" / ".." / "A")
    with pytest.raises(ReleaseError, match="canonical direct child"):
        selector.validate_selected_identity(bad, releases)


def test_release_symlink_substitution_fails(release_pair):
    releases, (a_root, a), _ = release_pair
    link = releases / "LINK"
    link.symlink_to(a_root, target_is_directory=True)
    bad = dict(a)
    bad["release"] = str(link)
    with pytest.raises(ReleaseError, match="canonical direct child"):
        selector.validate_selected_identity(bad, releases)


def test_manifest_inventory_mismatch_fails(release_pair):
    releases, (a_root, a), _ = release_pair
    manifest = json.loads((a_root / "manifest.json").read_text())
    manifest["extra"] = "drift"
    (a_root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    with pytest.raises(Exception):
        selector.validate_selected_identity(a, releases)


@pytest.mark.parametrize("field", ["commit", "tree"])
def test_commit_tree_mismatch_fails(release_pair, field):
    releases, (_, a), _ = release_pair
    bad = dict(a)
    bad[field] = "f" * 40
    with pytest.raises(ReleaseError):
        selector.validate_selected_identity(bad, releases)


def test_selected_execution_path_escape_fails(tmp_path, release_pair):
    releases, (_, a), _ = release_pair
    outside = tmp_path / "outside"
    outside.write_text("x")
    bad = dict(a)
    bad["launcher"] = str(outside.resolve())
    with pytest.raises(ReleaseError, match="escapes"):
        selector.verify_execution_paths(bad, releases)


def test_startup_unchanged_head_handoff_passes(release_pair, tmp_path):
    releases, (_, a), _ = release_pair
    journal = tmp_path / "selection.log"
    journal.write_bytes(b"")
    selector.append_generation(journal, a, expected_generation=None, expected_hash=None)
    baseline = selector.security_metadata(journal)
    captured = []
    target = selector.startup_target(journal, releases, baseline, handoff=captured.append)
    assert captured == [target]
    assert target["release"] == a["release"]


def test_startup_head_change_before_handoff_fails(release_pair, tmp_path):
    releases, (_, a), (_, b) = release_pair
    journal = tmp_path / "selection.log"
    journal.write_bytes(b"")
    first = selector.append_generation(journal, a, expected_generation=None, expected_hash=None)
    baseline = selector.security_metadata(journal)
    def mutate():
        selector.append_generation(journal, b, expected_generation=first["generation"], expected_hash=first["record_hash"])
    with pytest.raises(ReleaseError, match="changed before execution handoff"):
        selector.startup_target(journal, releases, baseline, before_head_recheck=mutate)


class _FakeService:
    def __init__(self):
        self.pid = 7001
        self.started = 0
        self.stopped = 0
    def _process(self, expected):
        return {"pid": self.pid, "start": "fixed", "executable": expected["executable"], "release": expected["release"], "healthy": True}
    def capture(self, expected):
        return self._process(expected)
    def stop(self):
        self.stopped += 1
    def start(self, _plist):
        self.started += 1
    def verify(self, expected):
        return self._process(expected)


def _patch_config_contract(monkeypatch):
    monkeypatch.setattr(gateway_release_config, "prepare_config_contract", lambda *a, **k: None)
    monkeypatch.setattr(gateway_release_config, "check_config_contract", lambda *a, **k: None)
    monkeypatch.setattr(gateway_release_config, "validate_config_transition", lambda *a, **k: {"kind": "UNCHANGED"})
    monkeypatch.setattr(gateway_release_config, "guard_config_baseline", lambda *a, **k: None)


def _prepare_transaction(tmp_path, release_pair, monkeypatch):
    _patch_config_contract(monkeypatch)
    releases, (_, a), (_, b) = release_pair
    journal = tmp_path / "selection.log"
    journal.write_bytes(b"")
    selector.append_generation(journal, a, expected_generation=None, expected_hash=None)
    baseline = selector.security_metadata(journal)
    plist = tmp_path / "selector.plist"
    plist.write_text(gateway_launchd.generate_static_selector_launchd_plist(["/Users/yura/.hermes/foundation/bin/hermes-gateway-selector"]))
    config = tmp_path / "config.yaml"
    config.write_text("test: true\n")
    home = tmp_path / "home"
    home.mkdir()
    service = _FakeService()
    receipt = tmp_path / "receipt.json"
    tx = SelectorReleaseTransaction.prepare(
        receipt, journal=journal, selector_plist=plist, selector_security=baseline,
        releases_root=releases, config=config, candidate=Path(b["release"]), home=home,
        domain="gui/501", service=service,
        canary_runner=lambda *a, **k: {"canary": "fake-pass"},
    )
    return tx, journal, a, b, service


def test_selector_transaction_prepare_activate_accept_and_forward_rollback(tmp_path, release_pair, monkeypatch):
    tx, journal, a, b, service = _prepare_transaction(tmp_path, release_pair, monkeypatch)
    assert tx.check() == {"ready": True, "state": "PREPARED", "rollback_ready": True}
    activated = tx.activate()
    assert activated["generation"] == 2
    assert selector.read_journal(journal)["head"]["selected"] == b
    accepted = tx.accept()
    assert accepted["accepted"] is True
    rolled = tx.rollback()
    assert rolled["generation"] == 3
    parsed = selector.read_journal(journal)
    assert [r["selected"]["release"] for r in parsed["records"]] == [a["release"], b["release"], a["release"]]
    assert service.started == 2 and service.stopped == 2


def test_selector_transaction_unexpected_third_state_fails(tmp_path, release_pair, monkeypatch):
    tx, journal, a, b, _ = _prepare_transaction(tmp_path, release_pair, monkeypatch)
    releases = Path(tx.data["releases_root"])
    _, c = _make_release(releases, "C", "e")
    head = selector.read_journal(journal)["head"]
    selector.append_generation(journal, c, expected_generation=head["generation"], expected_hash=head["record_hash"])
    with pytest.raises(ReleaseError):
        tx.activate()


def test_selector_transaction_missing_rollback_identity_not_ready(tmp_path, release_pair, monkeypatch):
    tx, _, a, _, _ = _prepare_transaction(tmp_path, release_pair, monkeypatch)
    import shutil
    shutil.rmtree(a["release"])
    assert tx.check(process=False)["rollback_ready"] is False


def test_static_launchd_contract_is_release_independent():
    stable = "/Users/yura/.hermes/foundation/bin/hermes-gateway-selector"
    text1 = gateway_launchd.generate_static_selector_launchd_plist([stable])
    text2 = gateway_launchd.generate_static_selector_launchd_plist([stable])
    assert text1 == text2
    plist = plistlib.loads(text1.encode())
    assert plist["Label"] == "ai.hermes.gateway"
    assert plist["ProgramArguments"][0] == "/usr/bin/osascript"
    assert plist["WorkingDirectory"] == "/Users/yura/.hermes"
    assert stable in " ".join(plist["ProgramArguments"])
    assert "core-v1-binding-iter2-from-9978cfd3" not in text1
    assert "hnf-production-line-candidate-03" not in text1


def test_threat_model_retains_trusted_owner_limit():
    text = selector.TRUSTED_OWNER_LIMIT.lower()
    assert "same-uid" in text and "owning uid" in text and "uf_append" in text


# D-156 real CLI dispatch coverage.
def _dispatch_double(kind, events):
    class TransactionDouble:
        def __init__(self, receipt):
            events.append((kind, "init", str(receipt)))
            self.data = {"state": "TEST_DOUBLE"}

        def _run(self, action):
            events.append((kind, action))
            return {"dispatch": kind, "action": action}

        def check(self):
            return self._run("check")

        def activate(self):
            return self._run("activate")

        def rollback(self):
            return self._run("rollback")

        def accept(self):
            return self._run("accept")

        def execute(self):
            return self._run("execute")

    return TransactionDouble


def _run_real_cli_dispatch(tmp_path, monkeypatch, capsys, receipt_value, *, action="check", raw=False):
    events = []
    monkeypatch.setattr(gateway_release, "SelectorReleaseTransaction", _dispatch_double("selector", events))
    monkeypatch.setattr(gateway_release, "ReleaseTransaction", _dispatch_double("legacy", events))
    receipt = tmp_path / "receipt.json"
    if raw:
        receipt.write_text(receipt_value)
    else:
        receipt.write_text(json.dumps(receipt_value))
    rc = gateway_release.main([action, "--receipt", str(receipt)])
    output = json.loads(capsys.readouterr().out)
    return rc, output, events


def test_cli_dispatch_schema2_static_selector_uses_selector_transaction(tmp_path, monkeypatch, capsys):
    rc, output, events = _run_real_cli_dispatch(
        tmp_path, monkeypatch, capsys,
        {"schema": 2, "mode": "STATIC_SELECTOR_V1"}, action="activate",
    )
    assert rc == 0
    assert output["ok"] is True and output["dispatch"] == "selector" and output["action"] == "activate"
    assert [event[:2] for event in events] == [("selector", "init"), ("selector", "activate")]
    assert not any(event[0] == "legacy" for event in events)


def test_cli_dispatch_schema1_without_mode_uses_legacy_transaction(tmp_path, monkeypatch, capsys):
    rc, output, events = _run_real_cli_dispatch(
        tmp_path, monkeypatch, capsys,
        {"schema": 1}, action="rollback",
    )
    assert rc == 0
    assert output["ok"] is True and output["dispatch"] == "legacy" and output["action"] == "rollback"
    assert [event[:2] for event in events] == [("legacy", "init"), ("legacy", "rollback")]
    assert not any(event[0] == "selector" for event in events)


@pytest.mark.parametrize("receipt_value", [
    {"schema": 2},
    {"schema": 2, "mode": "WRONG"},
    {"schema": 1, "mode": "STATIC_SELECTOR_V1"},
    {"schema": 3},
    {"mode": "STATIC_SELECTOR_V1"},
])
def test_cli_dispatch_unknown_or_conflicting_receipts_fail_closed(
    tmp_path, monkeypatch, capsys, receipt_value
):
    rc, output, events = _run_real_cli_dispatch(tmp_path, monkeypatch, capsys, receipt_value)
    assert rc == 1
    assert output["ok"] is False and output["state"] == "UNCLASSIFIED"
    assert "unsupported or ambiguous" in output["error"]
    assert events == []


def test_cli_dispatch_non_object_receipt_fails_closed(tmp_path, monkeypatch, capsys):
    rc, output, events = _run_real_cli_dispatch(tmp_path, monkeypatch, capsys, ["schema", 2])
    assert rc == 1
    assert output["ok"] is False and output["state"] == "UNCLASSIFIED"
    assert "JSON object" in output["error"]
    assert events == []


def test_cli_dispatch_malformed_json_is_controlled_failure(tmp_path, monkeypatch, capsys):
    rc, output, events = _run_real_cli_dispatch(tmp_path, monkeypatch, capsys, '{"schema":2', raw=True)
    assert rc == 1
    assert output["ok"] is False and output["state"] == "UNCLASSIFIED"
    assert "unreadable or malformed" in output["error"]
    assert events == []
