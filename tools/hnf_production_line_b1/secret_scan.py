#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = json.loads((HERE / 'expected-output.json').read_text())
PATTERNS = [
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(rb'\bsk-[A-Za-z0-9_-]{20,}\b'),
    re.compile(rb'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'),
    re.compile(rb'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(rb'AIza[0-9A-Za-z_-]{30,}'),
]


def scan_bytes(path, data, findings):
    for index, pattern in enumerate(PATTERNS):
        if pattern.search(data):
            findings.append({'path': path, 'pattern_id': index})


def main():
    root = Path(sys.argv[1]).resolve()
    findings = []
    for rel in sorted(EXPECTED['changed_entries']):
        scan_bytes(rel, (root / rel).read_bytes(), findings)
    for path in sorted(p for p in HERE.rglob('*') if p.is_file()):
        scan_bytes(path.relative_to(HERE).as_posix(), path.read_bytes(), findings)
    result = {
        'result': 'PASS' if not findings else 'FAIL',
        'candidate_or_versioned_findings': len(findings),
        'findings_metadata_only': findings,
    }
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if not findings else 42)


if __name__ == '__main__':
    main()
