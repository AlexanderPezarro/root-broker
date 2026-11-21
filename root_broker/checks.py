"""What a request is checked for when it is made: argv[0] on root's PATH, file pinning, agent-writable files."""
import grp
import hashlib
import os
import pwd
import shutil
import stat

from .config import ROOT_PATH


def prepare(argv, cwd, uid):
    """Validate a request. Returns (argv with argv[0] resolved, {path: sha256} of files named in it, warnings)."""
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty list of strings")
    if any("\0" in a for a in argv):
        raise ValueError("NUL in argv")
    exe = argv[0] if os.path.isabs(argv[0]) else shutil.which(argv[0], path=ROOT_PATH)
    if not exe or not os.path.isfile(exe):
        raise ValueError(f"{argv[0]!r} not found on root's PATH")
    if not os.path.isdir(cwd):
        raise ValueError(f"cwd {cwd!r} is not a directory")
    files, warnings = {}, []
    for a in [exe] + argv[1:]:
        p = a if os.path.isabs(a) else os.path.join(cwd, a)
        if a.startswith("-") or not os.path.isfile(p):
            continue
        files[os.path.abspath(p)] = sha256(p)
        if writable_by(p, uid):
            warnings.append(f"{p} is writable by the requester: review its contents, not just its name")
    return [exe] + argv[1:], files, warnings


def changed_files(files):
    """Paths among pinned {path: sha256} that are gone or no longer match."""
    return [p for p, h in files.items() if not os.path.isfile(p) or sha256(p) != h]


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def writable_by(p, uid):
    """True if uid could change p, by writing the file or replacing it in any parent directory."""
    try:
        pw = pwd.getpwuid(uid)
        groups = {pw.pw_gid} | {g.gr_gid for g in grp.getgrall() if pw.pw_name in g.gr_mem}
    except KeyError:
        groups = set()
    for path in {os.path.abspath(p), os.path.realpath(p)}:  # the link itself and what it points at
        while True:
            st = os.lstat(path)
            if st.st_uid == uid or st.st_mode & stat.S_IWOTH or (st.st_gid in groups and st.st_mode & stat.S_IWGRP):
                if not stat.S_ISLNK(st.st_mode) or st.st_uid == uid:
                    return True
            if path == "/":
                break
            path = os.path.dirname(path)
    return False
