"""Preserve launch selector metadata on macOS; only bounded Hermes plist files."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


def metadata_hash(path: Path) -> str:
    info = path.stat()
    value = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
             "flags": getattr(info, "st_flags", 0), "xattrs": {}, "acl": ""}
    if sys.platform == "darwin":
        names = subprocess.check_output(["/usr/bin/xattr", str(path)], timeout=5, text=True).splitlines()
        for name in sorted(names):
            # Values stay in this process and are represented only by a digest.
            raw = subprocess.check_output(["/usr/bin/xattr", "-px", name, str(path)], timeout=5)
            value["xattrs"][name] = hashlib.sha256(raw).hexdigest()
        lines = subprocess.check_output(["/bin/ls", "-ldeO", str(path)], timeout=5, text=True).splitlines()
        value["acl"] = "\n".join(lines[1:])
    else:
        for name in sorted(os.listxattr(path)):
            value["xattrs"][name] = hashlib.sha256(os.getxattr(path, name)).hexdigest()
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def copy_metadata(source: Path, destination: Path):
    if source.is_symlink() or destination.is_symlink():
        raise ValueError("selector metadata source/destination must not be symlinks")
    if sys.platform == "darwin":
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        copyfile = library.copyfile
        copyfile.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32)
        copyfile.restype = ctypes.c_int
        # SDK copyfile.h: ACL=1, STAT=2, XATTR=4. No file data is copied.
        if copyfile(os.fsencode(source), os.fsencode(destination), None, 7) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "launch selector metadata copy failed")
    else:
        shutil.copystat(source, destination, follow_symlinks=False)
    if metadata_hash(source) != metadata_hash(destination):
        raise ValueError("launch selector metadata copy was incomplete")
