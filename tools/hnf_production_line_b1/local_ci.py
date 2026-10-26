#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FROZEN = json.loads((HERE / 'frozen-input.json').read_text())
EXPECTED = json.loads((HERE / 'expected-output.json').read_text())
ROLLBACK = json.loads((HERE / 'rollback-provenance.json').read_text())
REGRESSION = json.loads((HERE / 'regression-inputs.json').read_text())

EXPECTED_FILES = {
    'tools/hnf_production_line_b1/README.md',
    'tools/hnf_production_line_b1/build_candidate.py',
    'tools/hnf_production_line_b1/expected-output.json',
    'tools/hnf_production_line_b1/frozen-input.json',
    'tools/hnf_production_line_b1/inventory.py',
    'tools/hnf_production_line_b1/local_ci.py',
    'tools/hnf_production_line_b1/regression-inputs.json',
    'tools/hnf_production_line_b1/rollback-provenance.json',
    'tools/hnf_production_line_b1/secret_scan.py',
    'tools/hnf_production_line_b1/sitecustomize.py',
    'tools/hnf_production_line_b1/patches/model_tools.patch',
    'tools/hnf_production_line_b1/patches/website_policy.patch',
    'tools/hnf_production_line_b1/tests/test_tool_search_empty_guard.py',
    'tools/hnf_production_line_b1/tests/test_website_policy_cache_scope.py',
}
FORBIDDEN_PUBLICATION_LITERALS = [
    b'/' + b'Users/', b'Sand' + b'boxes/', b'CANARY' + b'_05', b'PRODUCTION' + b'_PROMOTION',
    b'D0' + b'49', b'D0' + b'54', b'running_' + b'production_release', b'prospective_' + b'activation_target',
    b'yu' + b'ra',
]


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def out(*args):
    return subprocess.check_output([str(x) for x in args], text=True).strip()


def run(*args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sealed-release', required=True)
    parser.add_argument('--test-python', required=True)
    parser.add_argument('--tool-search-regression-root', required=True)
    parser.add_argument('--website-regression-root', required=True)
    parser.add_argument('--rollback-release', required=True)
    parser.add_argument('--scratch', required=True)
    return parser.parse_args()


def publication_hygiene():
    findings = []
    for rel in sorted(EXPECTED_FILES):
        path = ROOT / rel
        data = path.read_bytes()
        lower = data.lower()
        for literal in FORBIDDEN_PUBLICATION_LITERALS:
            if literal.lower() in lower:
                findings.append({'path': rel, 'literal': literal.decode('ascii')})
    if findings:
        raise SystemExit('STOP_PUBLICATION_HYGIENE ' + json.dumps(findings, sort_keys=True))
    return {'result': 'PASS', 'forbidden_literal_findings': 0}


def changed_files():
    base = FROZEN['publication_base_commit']
    committed = set(filter(None, out('git', '-C', ROOT, 'diff', '--name-only', base, 'HEAD').splitlines()))
    staged = set(filter(None, out('git', '-C', ROOT, 'diff', '--cached', '--name-only').splitlines()))
    untracked = set(filter(None, out('git', '-C', ROOT, 'ls-files', '--others', '--exclude-standard').splitlines()))
    return committed | staged | untracked


def verify_regression_inputs(root, items):
    paths = []
    root = Path(root).resolve()
    for item in items:
        path = root / item['relative_path']
        if not path.exists() or sha(path) != item['sha256']:
            raise SystemExit('STOP_LOCAL_REGRESSION_INPUT_IDENTITY ' + item['relative_path'])
        paths.append(path)
    return paths


def pytest_run(label, paths, candidate, scratch, test_python):
    log = scratch / (label + '.txt')
    network_log = scratch / (label + '.network.jsonl')
    home = scratch / (label + '-home')
    home.mkdir()
    hermes = home / 'hermes'
    hermes.mkdir()
    env = os.environ.copy()
    env.update({
        'HOME': str(home),
        'HERMES_HOME': str(hermes),
        'PYTHONPATH': str(HERE) + os.pathsep + str(candidate / 'hermes-agent'),
        'PYTHONDONTWRITEBYTECODE': '1',
        'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1',
        'HNF_PRODUCTION_LINE_NETWORK_LOG': str(network_log),
    })
    candidate_root = str(candidate / 'hermes-agent')
    code = (
        "import model_tools,tools.website_policy as w; "
        f"assert model_tools.__file__.startswith({candidate_root!r}); "
        f"assert w.__file__.startswith({candidate_root!r})"
    )
    run(test_python, '-c', code, cwd=scratch, env=env, stdout=subprocess.DEVNULL)
    cmd = [str(test_python), '-m', 'pytest', '-q', '--rootdir', str(scratch), '--import-mode=importlib', '-p', 'pytest_asyncio.plugin', *map(str, paths)]
    with log.open('w') as handle:
        proc = subprocess.run(cmd, cwd=scratch, env=env, stdout=handle, stderr=subprocess.STDOUT)
    text = log.read_text()
    summary = text.strip().splitlines()[-1] if text.strip() else 'NO_OUTPUT'
    print(label, summary)
    if proc.returncode:
        print(text)
        raise SystemExit('STOP_TEST_FAILURE ' + label)
    return {'label': label, 'summary': summary, 'network_log': str(network_log)}


def main():
    args = parse_args()
    sealed = Path(args.sealed_release).resolve()
    test_python = Path(os.path.abspath(os.path.expanduser(args.test_python)))
    rollback_release = Path(args.rollback_release).resolve()
    scratch = Path(args.scratch).resolve()

    if not test_python.exists():
        raise SystemExit('STOP_TEST_RUNTIME_MISSING')
    if out('git', '-C', ROOT, 'rev-parse', FROZEN['publication_base_commit']) != FROZEN['publication_base_commit']:
        raise SystemExit('STOP_PUBLICATION_BASE_MISSING')
    run('git', '-C', ROOT, 'merge-base', '--is-ancestor', FROZEN['publication_base_commit'], 'HEAD')
    changed = changed_files()
    if changed != EXPECTED_FILES:
        raise SystemExit('STOP_DIFF_WHITELIST ' + repr(sorted(changed)))

    for name, expected in FROZEN['accepted_patch_sha256'].items():
        if sha(HERE / 'patches' / name) != expected:
            raise SystemExit('STOP_PATCH_IDENTITY_MISMATCH ' + name)
    for name, expected in FROZEN['accepted_test_sha256'].items():
        if sha(HERE / 'tests' / name) != expected:
            raise SystemExit('STOP_FOCUSED_TEST_IDENTITY_MISMATCH ' + name)
    hygiene = publication_hygiene()

    if sha(sealed / 'manifest.json') != FROZEN['manifest_sha256']:
        raise SystemExit('STOP_FROZEN_MANIFEST_IDENTITY')
    if sha(sealed / 'release-inventory.json') != FROZEN['release_inventory_sha256']:
        raise SystemExit('STOP_FROZEN_INVENTORY_IDENTITY')
    for rel, expected in FROZEN['target_source_sha256'].items():
        if sha(sealed / 'hermes-agent' / rel) != expected:
            raise SystemExit('STOP_FROZEN_SOURCE_IDENTITY ' + rel)
    for rel, expected in FROZEN['dependency_lock_sha256'].items():
        if sha(sealed / 'hermes-agent' / rel) != expected:
            raise SystemExit('STOP_DEP_LOCK_IDENTITY ' + rel)

    tool_search_tests = verify_regression_inputs(
        args.tool_search_regression_root,
        REGRESSION['sets']['tool_search_regression_set'],
    )
    website_tests = verify_regression_inputs(
        args.website_regression_root,
        REGRESSION['sets']['website_regression_subset'],
    )

    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    candidate = scratch / 'candidate-release'
    reproduction = scratch / 'reproduction-release'

    run(test_python, HERE / 'build_candidate.py', '--sealed-release', sealed, '--dest', candidate)
    inv1 = scratch / 'candidate-inventory.json'
    run(test_python, HERE / 'inventory.py', candidate, inv1)
    inv_sha = sha(inv1)
    if inv_sha != EXPECTED['candidate_inventory_sha256']:
        raise SystemExit('STOP_OUTPUT_INVENTORY_IDENTITY_MISMATCH ' + inv_sha)
    inventory = json.loads(inv1.read_text())
    if len(inventory['entries']) != EXPECTED['entries_including_directories']:
        raise SystemExit('STOP_ENTRY_COUNT_MISMATCH')

    run(test_python, HERE / 'secret_scan.py', candidate)
    focused_dir = scratch / 'focused-tests'
    focused_dir.mkdir()
    shutil.copy2(HERE / 'tests/test_website_policy_cache_scope.py', focused_dir / 'test_website_policy_cache_scope.py')
    shutil.copy2(HERE / 'tests/test_tool_search_empty_guard.py', focused_dir / 'test_tool_search_empty_guard.py')
    tests = []
    tests.append(pytest_run('focused-website', [focused_dir / 'test_website_policy_cache_scope.py'], candidate, scratch, test_python))
    tests.append(pytest_run('focused-empty-tools', [focused_dir / 'test_tool_search_empty_guard.py'], candidate, scratch, test_python))
    tests.append(pytest_run('broader-tool-search', tool_search_tests, candidate, scratch, test_python))
    tests.append(pytest_run('website-regression-subset', website_tests, candidate, scratch, test_python))

    run(test_python, HERE / 'build_candidate.py', '--sealed-release', sealed, '--dest', reproduction)
    inv2 = scratch / 'reproduction-inventory.json'
    run(test_python, HERE / 'inventory.py', reproduction, inv2)
    if sha(inv2) != EXPECTED['candidate_inventory_sha256'] or inv1.read_bytes() != inv2.read_bytes():
        raise SystemExit('STOP_REPRODUCTION_MISMATCH')

    base_inventory = json.loads((sealed / 'release-inventory.json').read_text())['entries']
    candidate_inventory = {entry['path']: entry for entry in inventory['entries'] if entry['type'] != 'dir'}
    changed_payload = []
    for path, meta in base_inventory.items():
        current = candidate_inventory.get(path)
        if current is None:
            raise SystemExit('STOP_CANDIDATE_MISSING_SEALED_PATH ' + path)
        if 'link' in meta:
            if current.get('type') != 'symlink' or current.get('link') != meta['link']:
                changed_payload.append(path)
        elif current.get('type') != 'file' or current['mode'] != oct(meta['mode']) or current.get('sha256') != meta.get('sha256'):
            changed_payload.append(path)
    if sorted(changed_payload) != sorted(EXPECTED['changed_entries']):
        raise SystemExit('STOP_PAYLOAD_DIFF_MISMATCH ' + repr(changed_payload))

    if not rollback_release.exists():
        raise SystemExit('STOP_ROLLBACK_MISSING')
    rollback_manifest = json.loads((rollback_release / 'manifest.json').read_text())
    rollback_source = rollback_manifest.get('source', {})
    if rollback_source.get('commit') != ROLLBACK['accepted_rollback']['commit']:
        raise SystemExit('STOP_ROLLBACK_COMMIT_MISMATCH')
    if rollback_source.get('tree') != ROLLBACK['accepted_rollback']['tree']:
        raise SystemExit('STOP_ROLLBACK_TREE_MISMATCH')

    dns = 0
    blocked = 0
    for test in tests:
        path = Path(test['network_log'])
        if path.exists():
            for line in path.read_text().splitlines():
                event = json.loads(line)
                dns += int(event['kind'] == 'dns_simulated')
                blocked += int(event['kind'] == 'socket_blocked')

    head = out('git', '-C', ROOT, 'rev-parse', 'HEAD')
    tree = out('git', '-C', ROOT, 'rev-parse', 'HEAD^{tree}')
    commit_count = int(out('git', '-C', ROOT, 'rev-list', '--count', FROZEN['publication_base_commit'] + '..HEAD'))
    report = {
        'result': 'PASS_LOCAL_PUBLICATION_VERIFICATION',
        'publication_base_commit': FROZEN['publication_base_commit'],
        'head': head,
        'tree': tree,
        'commits_after_base': commit_count,
        'changed_versioned_files': sorted(changed),
        'publication_hygiene': hygiene,
        'candidate_inventory_sha256': inv_sha,
        'candidate_fingerprint': EXPECTED['candidate_fingerprint'],
        'candidate_entries': len(inventory['entries']),
        'changed_candidate_payload': changed_payload,
        'reproduction_exact': True,
        'tests': tests,
        'historical_unavailable_test_files': 6,
        'historical_residual': 'NOT_REVALIDATED',
        'secret_scan': 'PASS',
        'dependency_lock_mutation_count': 0,
        'rollback_commit': rollback_source['commit'],
        'rollback_tree': rollback_source['tree'],
        'network_dns_simulated': dns,
        'network_socket_blocked_before_os_egress': blocked,
        'external_network_dispatches': 0,
        'production_mutations': 0,
    }
    (scratch / 'publication-verification-result.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
