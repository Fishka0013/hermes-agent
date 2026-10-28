#!/usr/bin/env python3
import argparse
import hashlib
import json
import marshal
import py_compile
import struct
import subprocess
from pathlib import Path
from py_compile import PycInvalidationMode

HERE = Path(__file__).resolve().parent
FROZEN = json.loads((HERE / 'frozen-input.json').read_text())
EXPECTED = json.loads((HERE / 'expected-output.json').read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(*args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sealed-release', required=True)
    parser.add_argument('--dest', required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    base = Path(args.sealed_release).resolve()
    dest = Path(args.dest).resolve()
    if dest.exists():
        raise SystemExit('STOP_DEST_EXISTS')
    if sha(base / 'manifest.json') != FROZEN['manifest_sha256']:
        raise SystemExit('STOP_MANIFEST_IDENTITY_MISMATCH')
    if sha(base / 'release-inventory.json') != FROZEN['release_inventory_sha256']:
        raise SystemExit('STOP_RELEASE_INVENTORY_IDENTITY_MISMATCH')
    for rel, expected in FROZEN['target_source_sha256'].items():
        if sha(base / 'hermes-agent' / rel) != expected:
            raise SystemExit('STOP_BASE_SOURCE_IDENTITY_MISMATCH ' + rel)
    for rel in FROZEN.get('required_absent_source', []):
        if (base / 'hermes-agent' / rel).exists():
            raise SystemExit('STOP_BASE_SOURCE_UNEXPECTEDLY_PRESENT ' + rel)
    for name, expected in FROZEN['accepted_patch_sha256'].items():
        if sha(HERE / 'patches' / name) != expected:
            raise SystemExit('STOP_PATCH_IDENTITY_MISMATCH ' + name)

    run('cp', '-cR', base, dest)
    sealed = json.loads((dest / 'release-inventory.json').read_text())['entries']
    allowed = set(sealed) | {'manifest.json', 'release-inventory.json'}
    extras = []
    for path in list(dest.rglob('*')):
        if path.is_file() or path.is_symlink():
            if path.relative_to(dest).as_posix() not in allowed:
                extras.append(path)
    for path in extras:
        path.unlink()
    for path in sorted([x for x in dest.rglob('*') if x.is_dir()], key=lambda x: len(x.parts), reverse=True):
        try:
            path.rmdir()
        except OSError:
            pass

    for patch_name in ('model_tools.patch', 'website_policy.patch', 'gateway_run.patch', 'gateway_release_static_selector.patch'):
        with (HERE / 'patches' / patch_name).open('rb') as patch_file:
            run('patch', '-p1', '--fuzz=0', '-d', dest / 'hermes-agent', stdin=patch_file)
    # The selector source is created by the patch, so freeze its mode instead of inheriting process umask.
    (dest / 'hermes-agent/hermes_cli/gateway_release_selector.py').chmod(0o644)

    pyexe = base / 'tools/python-3.14.7+20260901-darwin-arm64/bin/python3.14'
    if not pyexe.exists():
        raise SystemExit('STOP_SEALED_PYTHON_MISSING')
    items = [
        ('hermes-agent/tools/website_policy.py', 'hermes-agent/tools/__pycache__/website_policy.cpython-314.pyc', None),
        ('hermes-agent/model_tools.py', 'hermes-agent/__pycache__/model_tools.cpython-314.pyc', None),
        ('hermes-agent/gateway/run.py', 'hermes-agent/gateway/__pycache__/run.cpython-314.pyc', None),
        ('hermes-agent/hermes_cli/gateway_release.py', 'hermes-agent/hermes_cli/__pycache__/gateway_release.cpython-314.pyc', None),
        ('hermes-agent/hermes_cli/gateway_launchd.py', 'hermes-agent/hermes_cli/__pycache__/gateway_launchd.cpython-314.pyc', None),
        ('hermes-agent/hermes_cli/gateway_release_selector.py',
         'hermes-agent/hermes_cli/__pycache__/gateway_release_selector.cpython-314.pyc',
         'hermes-agent/hermes_cli/__pycache__/gateway_release.cpython-314.pyc'),
    ]
    for src_rel, pyc_rel, template_rel in items:
        template = base / (template_rel or pyc_rel)
        old = template.read_bytes()
        flags = struct.unpack('<I', old[4:8])[0]
        if flags != 1:
            raise SystemExit('STOP_UNEXPECTED_PYC_FLAGS ' + str(template.relative_to(base)))
        code = marshal.loads(old[16:])
        dfile = code.co_filename if template_rel is None else str(Path(code.co_filename).with_name(Path(src_rel).name))
        out = dest / pyc_rel
        out.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(
            str(dest / src_rel),
            cfile=str(out),
            dfile=dfile,
            doraise=True,
            invalidation_mode=PycInvalidationMode.UNCHECKED_HASH,
        )
        out.chmod(0o444)

    for rel, expected in EXPECTED['changed_entries'].items():
        if sha(dest / rel) != expected:
            raise SystemExit('STOP_CHANGED_OUTPUT_HASH_MISMATCH ' + rel)
    print(json.dumps({'result': 'BUILD_COMPLETE', 'pruned_nonsealed_files': len(extras)}, sort_keys=True))


if __name__ == '__main__':
    main()
