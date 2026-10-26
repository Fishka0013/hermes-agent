#!/usr/bin/env python3
import hashlib, json, os, stat, sys
from pathlib import Path

def sha256_file(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def build_inventory(root):
    root = Path(root)
    entries = []
    for p in sorted(root.rglob('*'), key=lambda x: x.relative_to(root).as_posix()):
        rel = p.relative_to(root).as_posix()
        st = p.lstat()
        mode = oct(stat.S_IMODE(st.st_mode))
        if p.is_symlink():
            entries.append({'link': os.readlink(p), 'mode': mode, 'path': rel, 'type': 'symlink'})
        elif p.is_dir():
            entries.append({'mode': mode, 'path': rel, 'type': 'dir'})
        elif p.is_file():
            entries.append({'mode': mode, 'path': rel, 'sha256': sha256_file(p), 'size': st.st_size, 'type': 'file'})
        else:
            raise SystemExit('STOP_UNSUPPORTED_FILE_TYPE ' + rel)
    return {'entries': entries, 'schema': 'hnf-candidate-release-inventory-v1'}

def main():
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    data = build_inventory(root)
    out.write_text(json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n')
    print(json.dumps({'entries': len(data['entries']), 'inventory_sha256': sha256_file(out)}, sort_keys=True))

if __name__ == '__main__':
    main()
