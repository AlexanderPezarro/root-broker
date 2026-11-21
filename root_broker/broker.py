"""Request state: submit, approve, deny, wait, TTL grants, and the audit log they are rebuilt from."""
import json
import os
import pwd
import threading
import time

from . import config
from .checks import prepare
from .execute import execute
from .notify import notify


class Broker:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self.reqs = {}        # id -> request dict
        self.grants = {}      # key -> expiry epoch
        os.makedirs(os.path.join(config.STATE, "out"), mode=0o700, exist_ok=True)
        self.log_path = os.path.join(config.STATE, "audit.jsonl")
        self.next_id = self._load()

    # -------------------------------------------------------- audit log

    def _load(self):
        n = 0
        try:
            with open(self.log_path) as f:
                for line in f:
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    n = max(n, int(ev.get("id", 0)))
                    if ev.get("event") == "request":
                        r = dict(ev["req"])
                        r["state"] = "expired"  # anything still pending at restart is dropped, never run later
                        self.reqs[r["id"]] = r
                    elif ev.get("id") in self.reqs and ev.get("event") in ("done", "denied", "refused"):
                        self.reqs[ev["id"]].update(state=ev["event"], exit=ev.get("exit"))
        except FileNotFoundError:
            pass
        return n + 1

    def audit(self, event, **kw):
        kw.update(event=event, t=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        with open(self.log_path, "a") as f:
            f.write(json.dumps(kw) + "\n")
        os.chmod(self.log_path, 0o640)

    # -------------------------------------------------------- operations

    def key(self, r):
        """What an auto-approval grant matches on: the same command, cwd and file contents."""
        return json.dumps([r["argv"], r["cwd"], sorted(r["files"].items())])

    def submit(self, msg, uid):
        if uid not in self.cfg["allowed_uids"]:
            raise PermissionError(f"uid {uid} may not submit requests")
        reason = str(msg.get("reason") or "").strip()
        if not reason:
            raise ValueError("--reason is required")
        argv, files, warnings = prepare(msg.get("argv"), msg.get("cwd") or "/", uid)
        with self.lock:
            rid = self.next_id
            self.next_id += 1
            r = dict(id=rid, uid=uid, user=uname(uid), argv=argv, cwd=msg.get("cwd") or "/", reason=reason[:500],
                     files=files, warnings=warnings, created=time.time(), state="pending")
            self.reqs[rid] = r
            self.audit("request", id=rid, req=r)
            auto = argv in self.cfg["auto_approve"] and not warnings
            granted = self.grants.get(self.key(r), 0) > time.time()
        if auto or granted:
            self.approve(rid, 0, ttl=0, note="auto-approved" if auto else "within approved TTL")
        else:
            notify(self.cfg, r)
        return rid

    def approve(self, rid, uid, ttl=0, note=""):
        with self.lock:
            r = self._pending(rid)
            r["state"] = "running"
            if ttl:
                self.grants[self.key(r)] = time.time() + min(ttl, self.cfg["max_ttl"])
            self.audit("approved", id=rid, by=uid, ttl=ttl, note=note)
        threading.Thread(target=self.run, args=(r,), daemon=True).start()

    def deny(self, rid, uid, note=""):
        with self.cond:
            r = self._pending(rid)
            r.update(state="denied", note=note)
            self.audit("denied", id=rid, by=uid, note=note)
            self.cond.notify_all()

    def _pending(self, rid):
        r = self.reqs.get(rid)
        if not r:
            raise KeyError(f"no request {rid}")
        if r["state"] == "pending" and time.time() - r["created"] > self.cfg["request_ttl"]:
            r["state"] = "expired"
        if r["state"] != "pending":
            raise ValueError(f"request {rid} is {r['state']}, not pending")
        return r

    def run(self, r):
        out, code, state = execute(r, self.cfg["run_timeout"])
        path = os.path.join(config.STATE, "out", f"{r['id']}.txt")
        with open(path, "w") as f:
            f.write(out)
        os.chmod(path, 0o600)
        with self.cond:
            r.update(state=state, exit=code, output=out)
            self.audit(state, id=r["id"], exit=code, output_file=path)
            self.cond.notify_all()

    def wait(self, rid, timeout):
        end = time.time() + timeout
        with self.cond:
            while True:
                r = self.reqs.get(rid)
                if not r:
                    raise KeyError(f"no request {rid}")
                if r["state"] == "pending" and time.time() - r["created"] > self.cfg["request_ttl"]:
                    r["state"] = "expired"
                if r["state"] not in ("pending", "running"):
                    return r
                left = end - time.time()
                if left <= 0:
                    return r
                self.cond.wait(min(left, 5))


def view(r, full=False):
    """The fields of a request sent to clients."""
    v = {k: r.get(k) for k in ("id", "user", "argv", "cwd", "reason", "warnings", "state", "exit", "created", "note")}
    if full:
        v["output"] = r.get("output")
    return v


def uname(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)
