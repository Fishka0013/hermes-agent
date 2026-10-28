from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest

WT = Path("/Users/yura/GPT/Sandboxes/HermesNativeFirst/hnf-static-selector-foundation-isolated-01")
B1 = Path("/Users/yura/GPT/Sandboxes/HermesNativeFirst/hnf-static-selector-foundation-runtime-validation-01-build1")
B2 = Path("/Users/yura/GPT/Sandboxes/HermesNativeFirst/hnf-static-selector-foundation-runtime-validation-01-build2")
TOOL = WT / "tools/hnf_static_selector_foundation"
LIBS = {"__init__.py", "gateway_release_selector.py", "gateway_release.py", "gateway_release_errors.py", "gateway_release_metadata.py", "release_inventory.py"}


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def modules():
    return (
        _module("d160_build_foundation", TOOL / "build_foundation.py"),
        _module("d160_foundation_launcher", TOOL / "hermes_gateway_selector.py"),
    )


def _write_fake_release(root: Path, marker: Path):
    (root / "bin").mkdir(parents=True)
    (root / "hermes-agent").mkdir()
    (root / "site").mkdir()
    launcher = root / "bin/hermes"
    launcher.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$HNF_FAKE_HANDOFF_MARKER\"\nexit 0\n")
    launcher.chmod(0o755)
    fake_python = root / "bin/fake-python"
    fake_python.write_text("fake foundation admission executable\n")
    fake_python.chmod(0o755)
    manifest = {
        "schema": 1,
        "target": "darwin-arm64",
        "source": {"commit": "a" * 40, "tree": "b" * 40},
        "runtime": {
            "repoDir": "hermes-agent",
            "storePython": "bin/fake-python",
            "commands": {"hermes": "bin/hermes"},
            "sitePackages": "site",
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    return launcher, manifest


@pytest.fixture(scope="module")
def isolated_foundation(modules):
    builder, _launcher_module = modules
    scratch = Path(tempfile.mkdtemp(prefix="hnf-d160-foundation-test-", dir="/private/tmp")).resolve()
    foundation = scratch / "foundation"
    frozen = json.loads((TOOL / "frozen-input.json").read_text())
    expected = json.loads((TOOL / "expected-output.json").read_text())
    builder.build_payload(B1, foundation, frozen, TOOL / "hermes_gateway_selector.py", expected=expected)
    releases = scratch / "releases"
    releases.mkdir()
    release = releases / "fake-release"
    marker = scratch / "handoff-marker.txt"
    selected_launcher, manifest = _write_fake_release(release, marker)
    journal = foundation / "state/selection.jsonl"
    lib_root = foundation / "lib"
    code = """
import json, os, sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0, {lib!r})
from hermes_cli import gateway_release, gateway_release_selector, release_inventory
release=Path({release!r}); journal=Path({journal!r})
release_inventory.seal_inventory(release, {commit!r})
identity=gateway_release.candidate_identity(release)
journal.write_bytes(b''); journal.chmod(0o600)
gateway_release_selector.append_generation(journal, identity, expected_generation=None, expected_hash=None)
print(json.dumps(identity, sort_keys=True))
""".format(lib=str(lib_root), release=str(release), journal=str(journal), commit=manifest["source"]["commit"])
    python = foundation / builder.PYTHON_REL
    result = subprocess.run([str(python), "-I", "-S", "-c", code], text=True, capture_output=True, check=True)
    identity = json.loads(result.stdout.strip())
    admission_path = foundation / builder.ADMISSION_REL
    admission, raw = builder.generate_admission(foundation, journal, releases, admission_path)
    admission_sha = hashlib.sha256(raw).hexdigest()
    context = {
        "scratch": scratch, "foundation": foundation, "releases": releases, "release": release,
        "marker": marker, "selected_launcher": selected_launcher, "identity": identity,
        "journal": journal, "admission_path": admission_path, "admission": admission,
        "admission_raw": raw, "admission_sha": admission_sha, "python": python,
    }
    yield context
    shutil.rmtree(scratch)


def _run_launcher(ctx, *, admission_sha=None, extra_env=None, omit_hash=False):
    command = [str(ctx["python"]), "-I", "-S", str(ctx["foundation"] / "bin/hermes-gateway-selector")]
    if not omit_hash:
        command += ["--admission-sha256", admission_sha or ctx["admission_sha"]]
    env = os.environ.copy()
    env["HNF_FAKE_HANDOFF_MARKER"] = str(ctx["marker"])
    if extra_env:
        env.update(extra_env)
    return subprocess.run(command, text=True, capture_output=True, env=env)


def _replace_admission(ctx, value):
    original = ctx["admission_path"].read_bytes()
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    ctx["admission_path"].write_bytes(raw)
    return original, hashlib.sha256(raw).hexdigest()


def test_builder_requires_absent_output(modules, tmp_path):
    builder, _ = modules
    existing = tmp_path / "already-there"
    existing.mkdir()
    frozen = json.loads((TOOL / "frozen-input.json").read_text())
    with pytest.raises(ValueError, match="output path"):
        builder.build_payload(B1, existing, frozen, TOOL / "hermes_gateway_selector.py", expected=None)


def test_payload_has_exact_six_library_closure_and_full_frozen_runtime(modules, isolated_foundation):
    builder, _ = modules
    foundation = isolated_foundation["foundation"]
    assert {p.name for p in (foundation / "lib/hermes_cli").iterdir()} == LIBS
    assert builder.tree_identity(B1 / builder.RUNTIME_REL) == builder.tree_identity(foundation / builder.FOUNDATION_RUNTIME_REL)
    text = (foundation / "bin/hermes-gateway-selector").read_text()
    assert "hnf-static-selector-foundation-runtime-validation" not in text
    assert "/hermes-agent/.hermes/releases/" not in text


def test_payload_reproduction_from_build2_matches_build1(modules, isolated_foundation):
    builder, _ = modules
    scratch2 = isolated_foundation["scratch"] / "foundation2"
    frozen = json.loads((TOOL / "frozen-input.json").read_text())
    expected = json.loads((TOOL / "expected-output.json").read_text())
    r2 = builder.build_payload(B2, scratch2, frozen, TOOL / "hermes_gateway_selector.py", expected=expected)
    r1 = builder.foundation_inventory_identity(isolated_foundation["foundation"])
    assert r2["foundation_inventory_sha256"] == r1["sha256"]
    assert (scratch2 / builder.INVENTORY_REL).read_bytes() == (isolated_foundation["foundation"] / builder.INVENTORY_REL).read_bytes()
    assert (scratch2 / builder.LAUNCHER_REL).read_bytes() == (isolated_foundation["foundation"] / builder.LAUNCHER_REL).read_bytes()
    assert builder.tree_identity(scratch2 / builder.FOUNDATION_RUNTIME_REL) == builder.tree_identity(isolated_foundation["foundation"] / builder.FOUNDATION_RUNTIME_REL)


def test_selector_command_uses_frozen_python_i_s_and_exact_launcher(modules, isolated_foundation):
    builder, _ = modules
    command = builder.selector_command(isolated_foundation["foundation"], "0" * 64)
    assert command == [str(isolated_foundation["foundation"] / builder.PYTHON_REL), "-I", "-S", str(isolated_foundation["foundation"] / builder.LAUNCHER_REL), "--admission-sha256", "0" * 64]


def test_full_isolated_admission_startup_and_exact_exec_handoff(isolated_foundation):
    ctx = isolated_foundation
    result = _run_launcher(ctx)
    assert result.returncode == 0, result.stderr
    assert ctx["marker"].read_text().splitlines() == [
        "--run-module", "hermes_cli.stderr_timestamp", "--error-log",
        "/Users/yura/.hermes/logs/gateway.error.log", "--", str(ctx["selected_launcher"]),
        "gateway", "run", "--external-supervisor",
    ]


def test_admission_hash_required_and_wrong_hash_rejected(isolated_foundation):
    assert _run_launcher(isolated_foundation, omit_hash=True).returncode != 0
    result = _run_launcher(isolated_foundation, admission_sha="f" * 64)
    assert result.returncode != 0 and "SHA256" in result.stderr


@pytest.mark.parametrize("kind", ["malformed", "nonobject", "unknown-field", "root-mismatch", "python-mismatch"])
def test_strict_admission_rejects_malformed_semantics(isolated_foundation, kind):
    ctx = isolated_foundation
    original = ctx["admission_path"].read_bytes()
    try:
        if kind == "malformed":
            raw = b"{\n"; ctx["admission_path"].write_bytes(raw); digest = hashlib.sha256(raw).hexdigest()
        elif kind == "nonobject":
            raw = b"[]\n"; ctx["admission_path"].write_bytes(raw); digest = hashlib.sha256(raw).hexdigest()
        else:
            value = json.loads(original)
            if kind == "unknown-field": value["unexpected"] = True
            elif kind == "root-mismatch": value["foundation_root"] = "/private/tmp/not-the-foundation"
            else: value["python_path"] = str(ctx["foundation"] / "bin/hermes-gateway-selector")
            _, digest = _replace_admission(ctx, value)
        assert _run_launcher(ctx, admission_sha=digest).returncode != 0
    finally:
        ctx["admission_path"].write_bytes(original)


def test_immutable_library_drift_rejected(isolated_foundation):
    ctx = isolated_foundation
    target = ctx["foundation"] / "lib/hermes_cli/gateway_release_errors.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"# drift\n")
        result = _run_launcher(ctx)
        assert result.returncode != 0 and "inventory" in result.stderr.lower()
    finally:
        target.write_bytes(original); target.chmod(0o644)


def test_launcher_drift_rejected(isolated_foundation):
    ctx = isolated_foundation
    target = ctx["foundation"] / "bin/hermes-gateway-selector"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n# drift\n"); target.chmod(0o755)
        assert _run_launcher(ctx).returncode != 0
    finally:
        target.write_bytes(original); target.chmod(0o755)


def test_journal_security_drift_rejected(isolated_foundation):
    ctx = isolated_foundation
    ctx["journal"].chmod(0o644)
    try:
        result = _run_launcher(ctx)
        assert result.returncode != 0 and "security" in result.stderr.lower()
    finally:
        ctx["journal"].chmod(0o600)


def test_selected_release_identity_drift_rejected(isolated_foundation):
    ctx = isolated_foundation
    manifest = ctx["release"] / "manifest.json"
    original = manifest.read_bytes()
    try:
        manifest.write_bytes(original + b" ")
        assert _run_launcher(ctx).returncode != 0
    finally:
        manifest.write_bytes(original)


def test_host_pythonpath_cannot_substitute_foundation_modules(isolated_foundation):
    ctx = isolated_foundation
    evil = ctx["scratch"] / "evil/hermes_cli"
    evil.mkdir(parents=True)
    (evil / "__init__.py").write_text("raise RuntimeError('host PYTHONPATH used')\n")
    result = _run_launcher(ctx, extra_env={"PYTHONPATH": str(evil.parent)})
    assert result.returncode == 0, result.stderr


def test_foundation_import_origins_are_inside_foundation_lib(isolated_foundation):
    ctx = isolated_foundation
    code = "import sys; sys.dont_write_bytecode=True; sys.path.insert(0,%r); import hermes_cli, hermes_cli.gateway_release_selector as s; print(hermes_cli.__file__); print(s.__file__)" % str(ctx["foundation"] / "lib")
    result = subprocess.run([str(ctx["python"]), "-I", "-S", "-c", code], text=True, capture_output=True, check=True)
    for line in result.stdout.splitlines():
        assert Path(line).resolve().is_relative_to((ctx["foundation"] / "lib").resolve())


def test_exec_handoff_uses_only_verified_selected_launcher_and_no_fallback(modules, monkeypatch):
    _builder, launcher = modules
    calls = []
    def fail_exec(path, argv):
        calls.append((path, argv)); raise OSError("synthetic exec failure")
    monkeypatch.setattr(launcher.os, "execv", fail_exec)
    selected = "/verified/release/bin/hermes"
    with pytest.raises(OSError, match="synthetic"):
        launcher.exec_handoff({"launcher": selected})
    assert len(calls) == 1
    assert calls[0] == (selected, [selected, "--run-module", "hermes_cli.stderr_timestamp", "--error-log", "/Users/yura/.hermes/logs/gateway.error.log", "--", selected, "gateway", "run", "--external-supervisor"])


def test_threat_model_is_explicit_and_no_rebaseline(modules):
    _builder, launcher = modules
    text = (launcher.TRUSTED_OWNER_LIMIT + " " + (TOOL / "hermes_gateway_selector.py").read_text()).lower()
    assert "trusted" in text and "same-uid isolation" in text and "no automatic rebaseline" in text


def test_foundation_inventory_document_drift_rejected(isolated_foundation):
    ctx = isolated_foundation
    target = ctx["foundation"] / "admission/foundation-inventory.json"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b" ")
        result = _run_launcher(ctx)
        assert result.returncode != 0 and "inventory" in result.stderr.lower()
    finally:
        target.write_bytes(original); target.chmod(0o644)


def test_user_site_cannot_substitute_foundation_modules(isolated_foundation):
    ctx = isolated_foundation
    userbase = ctx["scratch"] / "userbase"
    evil = userbase / "lib/python3.14/site-packages/hermes_cli"
    evil.mkdir(parents=True)
    (evil / "__init__.py").write_text("raise RuntimeError('user site used')\n")
    result = _run_launcher(ctx, extra_env={"PYTHONUSERBASE": str(userbase)})
    assert result.returncode == 0, result.stderr


def test_builder_rejects_frozen_candidate_identity_drift(modules, isolated_foundation):
    builder, _ = modules
    frozen = json.loads((TOOL / "frozen-input.json").read_text())
    frozen["candidate_inventory_sha256"] = "0" * 64
    destination = isolated_foundation["scratch"] / "identity-drift-output"
    with pytest.raises(ValueError, match="candidate_inventory_sha256"):
        builder.build_payload(B1, destination, frozen, TOOL / "hermes_gateway_selector.py", expected=None)
    assert not destination.exists()
