"""Running an approved command as root: no shell, clean environment, pinned files re-checked first."""
import subprocess

from .checks import changed_files
from .config import MAX_OUT, ROOT_PATH

ENV = {"PATH": ROOT_PATH, "HOME": "/root", "LANG": "C.UTF-8", "USER": "root", "LOGNAME": "root"}


def execute(r, timeout):
    """Run request r. Returns (output, exit code, final state: "done" or "refused")."""
    changed = changed_files(r["files"])
    if changed:
        return f"refused: changed since the request was made: {', '.join(changed)}\n", 126, "refused"
    try:
        p = subprocess.run(r["argv"], cwd=r["cwd"], env=ENV, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        out, code = p.stdout[:MAX_OUT].decode(errors="replace"), p.returncode
    except subprocess.TimeoutExpired as e:
        out, code = (e.stdout or b"")[:MAX_OUT].decode(errors="replace") + "\n[timed out]\n", 124
    except OSError as e:
        out, code = f"{e}\n", 127
    return out, code, "done"
