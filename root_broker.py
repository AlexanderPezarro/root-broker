#!/usr/bin/env python3
"""Root approval broker: an agent asks for one exact root command, a human approves it, root runs it.

One file, stdlib only. Installed root-owned by install.sh as:
  /usr/local/bin/request-root   (anyone)   ask for a command to run as root
  /usr/local/sbin/root-broker   (root/you) daemon, plus approve/deny/list for the human

Agent side (no sudo):
  request-root --reason "apply new TLS config" -- systemctl restart caddy
  request-root --no-wait --reason ... -- CMD...   prints the request id and returns
  request-root wait ID                            block until ID finishes, print its output
  request-root list                               pending and recent requests

Human side (sudo is the approval boundary: the agent can't type your password):
  sudo root-broker approve ID [--ttl 30m]   run it; --ttl also auto-approves the identical request for a while
  sudo root-broker deny ID [--note why]
  root-broker list                          (no sudo needed)

Phone side (optional, config "phone"): the daemon also serves a small approval page on the Tailscale IP. It
accepts a connection only if tailscaled says it comes from one of the listed device StableIDs. WireGuard
authenticates that, so a process on this host (the agent) can't pass for the phone. The ntfy push links to it.

The daemon never uses a shell. It resolves argv[0] against root's PATH (never the caller's), runs with a
clean environment, records a sha256 of every existing file named in argv at request time and refuses to
run if any of them changed before execution, and writes every request and result to an audit log.
"""
import argparse
import hashlib
import hmac
import html
import http.client
import http.server
import json
import os
import pwd
import secrets
import shlex
import shutil
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

SOCK = os.environ.get("ROOT_BROKER_SOCK", "/run/root-broker/broker.sock")
STATE = os.environ.get("ROOT_BROKER_STATE", "/var/lib/root-broker")
CONFIG = os.environ.get("ROOT_BROKER_CONFIG", "/etc/root-broker/config.json")
TAILSCALED_SOCK = os.environ.get("ROOT_BROKER_TAILSCALED_SOCK", "/run/tailscale/tailscaled.sock")
ROOT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUT = 1 << 20  # bytes of stdout+stderr returned and kept per request
DEFAULTS = {
    "allowed_uids": [1000],      # who may submit requests
    "approver_uids": [0],        # who may approve; keep this root-only
    "request_ttl": 3600,         # seconds a pending request stays approvable
    "run_timeout": 900,          # seconds a command may run
    "max_ttl": 4 * 3600,         # cap on --ttl auto-approval
    "ntfy_url": None,            # e.g. "https://ntfy.example.com/root-broker"; None = no push notification
    "ntfy_token": None,          # ntfy access token (tk_...) of a publish-only user; set by ntfy-setup.sh
    "auto_approve": [],          # exact argv lists (argv[0] absolute) that run without asking, e.g. read-only status
    "phone": None,               # phone approval over Tailscale; None = off. See PHONE_DEFAULTS.
}
PHONE_DEFAULTS = {
    "listen": None,              # "<this host's Tailscale IPv4>:PORT", e.g. "100.64.0.1:7444"
    "nodes": [],                 # Tailscale StableIDs allowed to approve (tailscale whois / status --json)
    "url": None,                 # link put in the ntfy push; default http://<listen>
    "hosts": [],                 # extra Host header values to accept (e.g. a MagicDNS name:port)
    "bind_device": "tailscale0",  # SO_BINDTODEVICE: only accept packets that arrived on this interface
    "allow_warned": False,       # may the phone approve ⚠ requests (agent-editable files)? Default: sudo only
    "ttl_button": 1800,          # seconds for the "approve + auto-approve identical" button; 0 hides it
}


# ---------------------------------------------------------------- wire protocol: one JSON object per line

def send(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def recv(f):
    line = f.readline()
    if not line:
        raise EOFError
    return json.loads(line)


def call(obj, timeout=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(SOCK)
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
        sys.exit(f"request-root: can't reach the broker at {SOCK} ({e}). Is root-broker.service running?")
    send(s, obj)
    return s, s.makefile("r")


# ---------------------------------------------------------------- daemon

class Broker:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self.reqs = {}        # id -> request dict
        self.grants = {}      # key -> expiry epoch
        os.makedirs(os.path.join(STATE, "out"), mode=0o700, exist_ok=True)
        self.log_path = os.path.join(STATE, "audit.jsonl")
        self.next_id = self._load()
        self.form_key = secrets.token_bytes(32)  # per boot; signs the phone page's approve forms

    def form_token(self, rid):
        return hmac.new(self.form_key, f"approve:{rid}".encode(), "sha256").hexdigest()

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

    # -------------------------------------------------------- request checks

    def prepare(self, argv, cwd, uid):
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

    def key(self, r):
        return json.dumps([r["argv"], r["cwd"], sorted(r["files"].items())])

    # -------------------------------------------------------- operations

    def submit(self, msg, uid):
        if uid not in self.cfg["allowed_uids"]:
            raise PermissionError(f"uid {uid} may not submit requests")
        reason = str(msg.get("reason") or "").strip()
        if not reason:
            raise ValueError("--reason is required")
        argv, files, warnings = self.prepare(msg.get("argv"), msg.get("cwd") or "/", uid)
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
            self.notify(r)
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
        changed = [p for p, h in r["files"].items() if not os.path.isfile(p) or sha256(p) != h]
        if changed:
            out, code, state = f"refused: changed since the request was made: {', '.join(changed)}\n", 126, "refused"
        else:
            env = {"PATH": ROOT_PATH, "HOME": "/root", "LANG": "C.UTF-8", "USER": "root", "LOGNAME": "root"}
            try:
                p = subprocess.run(r["argv"], cwd=r["cwd"], env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=self.cfg["run_timeout"])
                out, code = p.stdout[:MAX_OUT].decode(errors="replace"), p.returncode
            except subprocess.TimeoutExpired as e:
                out, code = (e.stdout or b"")[:MAX_OUT].decode(errors="replace") + "\n[timed out]\n", 124
            except OSError as e:
                out, code = f"{e}\n", 127
            state = "done"
        path = os.path.join(STATE, "out", f"{r['id']}.txt")
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

    def notify(self, r):
        url = self.cfg.get("ntfy_url")
        if not url:
            return
        body = f"#{r['id']} {r['user']}: {visible(shlex.join(r['argv']))}\nwhy: {visible(r['reason'])}"
        if r["warnings"]:
            body += "\n⚠ " + "\n⚠ ".join(visible(w) for w in r["warnings"])
        body += f"\napprove: sudo root-broker approve {r['id']}"
        headers = {"Title": f"Root request #{r['id']}", "Priority": "high", "Tags": "key"}
        if self.cfg.get("ntfy_token"):
            headers["Authorization"] = f"Bearer {self.cfg['ntfy_token']}"
        phone = self.cfg.get("phone")
        if phone:
            link = f"{phone_base_url(phone)}/r/{r['id']}"
            headers.update(Click=link, Actions=f"view, Review, {link}")
            body += " or tap Review"
        req = urllib.request.Request(url, data=body.encode(), method="POST", headers=headers)
        try:
            urllib.request.urlopen(req, timeout=10).close()
        except Exception as e:  # a failed push must not block the request
            print(f"ntfy failed: {e}", file=sys.stderr)

    # -------------------------------------------------------- connection handler

    def handle(self, conn):
        f = conn.makefile("r")
        try:
            uid = peer_uid(conn)
            msg = recv(f)
            op = msg.get("op")
            if op == "submit":
                rid = self.submit(msg, uid)
                send(conn, {"ok": True, "id": rid})
            elif op == "wait":
                r = self.wait(int(msg["id"]), float(msg.get("timeout", 540)))
                self.check_owner(r, uid)
                send(conn, {"ok": True, "req": view(r, full=True)})
            elif op == "list":
                with self.lock:
                    rs = [view(r) for r in sorted(self.reqs.values(), key=lambda r: -r["id"])
                          if uid == 0 or r["uid"] == uid][: int(msg.get("n", 20))]
                send(conn, {"ok": True, "reqs": rs})
            elif op in ("approve", "deny"):
                if uid not in self.cfg["approver_uids"]:
                    raise PermissionError("only an approver may do that: run it with sudo")
                if op == "approve":
                    self.approve(int(msg["id"]), uid, ttl=int(msg.get("ttl") or 0), note=msg.get("note", ""))
                else:
                    self.deny(int(msg["id"]), uid, note=msg.get("note", ""))
                send(conn, {"ok": True})
            else:
                raise ValueError(f"unknown op {op!r}")
        except EOFError:
            pass
        except Exception as e:
            try:
                send(conn, {"ok": False, "error": f"{type(e).__name__}: {e}"})
            except OSError:
                pass
        finally:
            conn.close()

    def check_owner(self, r, uid):
        if uid != 0 and r["uid"] != uid:
            raise PermissionError("not your request")


def view(r, full=False):
    v = {k: r.get(k) for k in ("id", "user", "argv", "cwd", "reason", "warnings", "state", "exit", "created", "note")}
    if full:
        v["output"] = r.get("output")
    return v


def peer_uid(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


def uname(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


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
        groups = {pw.pw_gid} | {g.gr_gid for g in __import__("grp").getgrall() if pw.pw_name in g.gr_mem}
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


# ---------------------------------------------------------------- phone approval over Tailscale
#
# Who may approve: only a TCP connection that tailscaled maps to a configured device StableID. Loopback, the
# host's own Tailscale IP, LAN and docker traffic all fail that check. The other checks stop a web page open on
# the phone from approving for you: the Host header must be ours (stops DNS rebinding), a POST must come from our
# own origin, and it must carry an HMAC token that only appears inside our own page. The page has no scripts and
# can't be framed, and every agent-supplied string is escaped, with non-ASCII/control characters made visible.

class _TailscaledConn(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("local-tailscaled.sock", timeout=5)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(TAILSCALED_SOCK)


def tailnet_whois(ip, port):
    """The Tailscale node behind a peer address, as tailscaled sees it, or None."""
    addr = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    c = _TailscaledConn()
    try:
        c.request("GET", "/localapi/v0/whois?addr=" + urllib.parse.quote(addr))
        r = c.getresponse()
        return json.loads(r.read(1 << 20)).get("Node") if r.status == 200 else None
    finally:
        c.close()


def phone_base_url(phone):
    return (phone.get("url") or f"http://{phone['listen']}").rstrip("/")


def visible(s):
    """Plain-text form of agent-controlled text: non-ASCII and control characters (bidi overrides,
    homoglyphs, terminal escapes) become \\uXXXX so they can't disguise the command."""
    return "".join(ch if ch == "\n" or " " <= ch <= "~" else f"\\u{ord(ch):04x}" for ch in str(s))


def show(s):
    """HTML-escape agent-controlled text, with the characters visible() rewrites highlighted."""
    out = []
    for ch in str(s):
        if ch == "\n" or " " <= ch <= "~":
            out.append(html.escape(ch))
        else:
            out.append(f'<mark>\\u{ord(ch):04x}</mark>')
    return "".join(out)


CSS = """body{font:16px/1.45 system-ui,sans-serif;margin:0;padding:16px;background:#fff;color:#111;max-width:46rem}
@media(prefers-color-scheme:dark){body{background:#111;color:#eee}code,pre{background:#222!important}}
code,pre{background:#f2f2f2;padding:2px 4px;border-radius:4px;overflow-wrap:anywhere;white-space:pre-wrap}
pre{padding:8px;max-height:60vh;overflow:auto}.warn{color:#b45309;font-weight:600}mark{background:#fde047;color:#000}
button{font-size:18px;padding:14px;margin:6px 0;width:100%;border-radius:8px;border:0}
.ok{background:#15803d;color:#fff}.ttl{background:#1d4ed8;color:#fff}.no{background:#b91c1c;color:#fff}
a{color:inherit}li{margin:4px 0}"""


class PhoneHandler(http.server.BaseHTTPRequestHandler):
    broker = None
    phone = None
    server_version = "root-broker"
    sys_version = ""
    timeout = 20

    def log_message(self, fmt, *args):
        print("phone: " + fmt % args, file=sys.stderr, flush=True)

    def send_page(self, code, title, body):
        data = (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                f"<title>{html.escape(title)}</title><style>{CSS}</style><h2>{html.escape(title)}</h2>{body}").encode()
        self.send_response(code)
        for k, v in (("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(data))),
                     ("Cache-Control", "no-store"), ("Referrer-Policy", "same-origin"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                     ("Content-Security-Policy",
                      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def gate(self, post=False):
        """Return the approving device's name, or send a 403 and return None."""
        listen = self.phone["listen"]
        hosts = {listen, *self.phone["hosts"], urllib.parse.urlsplit(phone_base_url(self.phone)).netloc}
        if self.headers.get("Host", "") not in hosts:
            self.send_page(403, "Wrong host", "<p>Unexpected Host header.</p>")
            return None
        ip, port = self.client_address[:2]
        try:
            node = tailnet_whois(ip, port) or {}
        except (OSError, ValueError) as e:
            print(f"phone: whois failed: {e}", file=sys.stderr, flush=True)
            node = {}
        if node.get("StableID") not in self.phone["nodes"]:
            self.send_page(403, "Not an approver", f"<p>Approvals are accepted only from the configured phone. "
                                                   f"This connection is from {show((node.get('Name') or ip).rstrip('.'))}.</p>")
            return None
        if post:
            # Sec-Fetch-Site is set by the browser and can't be forged by a page, so trust it when present.
            # Otherwise fall back to Origin. A null Origin is refused, because no-referrer pages and
            # sandboxed frames send it too.
            origin = self.headers.get("Origin")
            site = self.headers.get("Sec-Fetch-Site")
            if site is not None:
                bad = site != "same-origin"
            else:
                bad = origin is not None and urllib.parse.urlsplit(origin).netloc not in hosts
            if bad:
                print(f"phone: refused cross-site POST (Sec-Fetch-Site={site!r}, Origin={origin!r})",
                      file=sys.stderr, flush=True)
                self.send_page(403, "Cross-site request", "<p>Approve from the review page itself.</p>")
                return None
        return (node.get("ComputedName") or node.get("Name") or node["StableID"]).rstrip(".")

    def request_id(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if len(parts) == 2 and parts[0] == "r" and parts[1].isdigit():
            return int(parts[1])
        return None

    def do_GET(self):
        if self.gate() is None:
            return
        rid = self.request_id()
        if self.path.split("?")[0] in ("/", ""):
            return self.list_page()
        if rid is None or rid not in self.broker.reqs:
            return self.send_page(404, "Not found", "<p><a href='/'>Pending requests</a></p>")
        self.detail_page(self.broker.reqs[rid])

    def do_POST(self):
        who = self.gate(post=True)
        if who is None:
            return
        rid = self.request_id()
        n = int(self.headers.get("Content-Length") or 0)
        if rid is None or not 0 < n <= 4096:
            return self.send_page(400, "Bad request", "")
        form = urllib.parse.parse_qs(self.rfile.read(n).decode(errors="replace"))
        token, action = form.get("token", [""])[0], form.get("action", [""])[0]
        if not hmac.compare_digest(token, self.broker.form_token(rid)):
            return self.send_page(403, "Stale page", f"<p>Reload <a href='/r/{rid}'>the request</a> and try again.</p>")
        r = self.broker.reqs.get(rid)
        by = f"phone:{who}"
        try:
            if action == "deny":
                self.broker.deny(rid, by, note=f"denied from {who}")
            elif action in ("approve", "approve_ttl"):
                if r and r["warnings"] and not self.phone["allow_warned"]:
                    raise PermissionError("this request has ⚠ warnings: approve it with sudo after reading the files")
                ttl = self.phone["ttl_button"] if action == "approve_ttl" else 0
                self.broker.approve(rid, by, ttl=ttl, note=f"approved from {who}")
            else:
                raise ValueError(f"unknown action {action!r}")
        except (KeyError, ValueError, PermissionError) as e:
            return self.send_page(409, "Not done", f"<p>{html.escape(str(e))}</p><p><a href='/r/{rid}'>Back</a></p>")
        self.broker.wait(rid, 10)  # usually enough to show the result on the same page
        self.detail_page(self.broker.reqs[rid])

    def list_page(self):
        with self.broker.lock:
            rs = sorted(self.broker.reqs.values(), key=lambda r: -r["id"])[:15]
        items = "".join(f"<li><a href='/r/{r['id']}'>#{r['id']} {show(r['state'])}</a>: "
                        f"<code>{show(shlex.join(r['argv']))}</code></li>" for r in rs)
        self.send_page(200, "Root requests", f"<ul>{items or '<li>none</li>'}</ul>")

    def detail_page(self, r):
        state = r["state"]
        if state == "pending" and time.time() - r["created"] > self.broker.cfg["request_ttl"]:
            state = "expired"
        age = int(time.time() - r["created"])
        args = "".join(f"<li><code>{show(a)}</code></li>" for a in r["argv"])
        b = (f"<p><b>{show(state)}</b> · {show(r['user'])} · {age // 60} min ago</p>"
             f"<p>Command:</p><pre>{show(shlex.join(r['argv']))}</pre>"
             f"<p>Arguments, one per line:</p><ol start=0>{args}</ol>"
             f"<p>cwd <code>{show(r['cwd'])}</code></p><p>Why: {show(r['reason'])}</p>")
        for w in r["warnings"]:
            b += f"<p class=warn>⚠ {show(w)}</p>"
        if r["files"]:
            b += "<p>Files pinned by hash:</p><ul>" + "".join(
                f"<li><code>{show(p)}</code> {h[:12]}</li>" for p, h in r["files"].items()) + "</ul>"
        if state == "pending":
            if r["warnings"] and not self.phone["allow_warned"]:
                b += (f"<p class=warn>A file in this request can be edited by the agent. Read it, then approve with "
                      f"<code>sudo root-broker approve {r['id']}</code>.</p>")
                buttons = "<button class=no name=action value=deny>Deny</button>"
            else:
                buttons = "<button class=ok name=action value=approve>Approve and run as root</button>"
                ttl = min(self.phone["ttl_button"], self.broker.cfg["max_ttl"])
                if ttl:
                    buttons += (f"<button class=ttl name=action value=approve_ttl>Approve, and auto-approve this exact"
                                f" request for {ttl // 60} min</button>")
                buttons += "<button class=no name=action value=deny>Deny</button>"
            b += (f"<form method=post action='/r/{r['id']}'>"
                  f"<input type=hidden name=token value='{self.broker.form_token(r['id'])}'>{buttons}</form>")
        elif state in ("done", "refused"):
            b += f"<p>Exit {show(r.get('exit'))}</p><pre>{show((r.get('output') or '')[-20000:])}</pre>"
        elif state == "running":
            b += f"<p>Still running. <a href='/r/{r['id']}'>Refresh</a></p>"
        if r.get("note"):
            b += f"<p>Note: {show(r['note'])}</p>"
        self.send_page(200, f"Root request #{r['id']}", b + "<p><a href='/'>All requests</a></p>")


class PhoneServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    bind_device = None

    def server_bind(self):
        if self.bind_device:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.bind_device.encode())
        socketserver.TCPServer.server_bind(self)  # skip HTTPServer's reverse-DNS lookup
        self.server_name, self.server_port = self.server_address[:2]


def phone_serve(broker, phone):
    host, _, port = phone["listen"].rpartition(":")
    handler = type("Handler", (PhoneHandler,), {"broker": broker, "phone": phone})
    PhoneServer.bind_device = phone["bind_device"]
    while True:  # the Tailscale IP may not exist yet at boot
        try:
            srv = PhoneServer((host.strip("[]"), int(port)), handler)
        except OSError as e:
            print(f"phone listener on {phone['listen']}: {e}; retrying in 15s", file=sys.stderr, flush=True)
            time.sleep(15)
            continue
        print(f"phone approvals on http://{phone['listen']} for {', '.join(phone['nodes'])}", flush=True)
        srv.serve_forever()


def load_config():
    cfg = dict(DEFAULTS)
    try:
        st = os.stat(CONFIG)
        if os.geteuid() == 0 and (st.st_uid != 0 or st.st_mode & 0o022):
            sys.exit(f"{CONFIG} must be owned by root and not group/world writable")
        with open(CONFIG) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    if cfg.get("phone"):
        phone = dict(PHONE_DEFAULTS)
        phone.update(cfg["phone"])
        if not phone["listen"] or not phone["nodes"] or not all(isinstance(n, str) for n in phone["nodes"]):
            sys.exit('config "phone" needs "listen" ("IP:PORT") and "nodes" (Tailscale StableIDs)')
        cfg["phone"] = phone
    return cfg


def serve():
    if os.geteuid() != 0 and not os.environ.get("ROOT_BROKER_TEST"):
        sys.exit("root-broker serve must run as root")
    cfg = load_config()
    b = Broker(cfg)
    os.makedirs(os.path.dirname(SOCK), exist_ok=True)
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    s.bind(SOCK)
    os.umask(old)
    gid = int(os.environ.get("ROOT_BROKER_GID", "-1"))
    if gid >= 0:
        os.chown(SOCK, 0, gid)
    os.chmod(SOCK, 0o660 if gid >= 0 else 0o666)  # peer uid is checked on every op anyway
    s.listen(16)
    print(f"root-broker listening on {SOCK}", flush=True)
    if cfg.get("phone"):
        threading.Thread(target=phone_serve, args=(b, cfg["phone"]), daemon=True).start()
    while True:
        conn, _ = s.accept()
        threading.Thread(target=b.handle, args=(conn,), daemon=True).start()


# ---------------------------------------------------------------- CLI

def ok(f):
    resp = recv(f)
    if not resp.get("ok"):
        sys.exit(f"error: {resp.get('error')}")
    return resp


def fmt(r):
    age = int(time.time() - r["created"])
    line = f"#{r['id']:<4} {r['state']:<8} {age // 60:>4}m  {r['user']}: {' '.join(r['argv'])}"
    line += f"\n       cwd {r['cwd']}  why: {r['reason']}"
    for w in r.get("warnings") or []:
        line += f"\n       ⚠ {w}"
    return line


def do_wait(rid, timeout):
    _, f = call({"op": "wait", "id": rid, "timeout": timeout})
    try:
        r = ok(f)["req"]
    except EOFError:  # the daemon restarted mid-wait; it drops pending requests on restart
        print(f"request #{rid}: the broker restarted while waiting, so the request was dropped. Submit it again.",
              file=sys.stderr)
        return 77
    if r["state"] in ("pending", "running"):
        print(f"request #{rid} still {r['state']}. Ask the user to run: sudo root-broker approve {rid}\n"
              f"then: request-root wait {rid}", file=sys.stderr)
        return 75
    if r["state"] in ("denied", "expired"):
        print(f"request #{rid} was {r['state']}" + (f": {r.get('note')}" if r.get("note") else ""), file=sys.stderr)
        return 77
    sys.stdout.write(r.get("output") or "")
    return r["exit"] if isinstance(r["exit"], int) else 1


def parse_ttl(s):
    if not s:
        return 0
    mult = {"s": 1, "m": 60, "h": 3600}.get(s[-1], None)
    return int(s[:-1]) * mult if mult else int(s)


def request_main(args):
    p = argparse.ArgumentParser(prog="request-root", description="Ask a human to run one exact command as root.",
                                epilog="request-root wait ID | request-root list")
    p.add_argument("--reason", "-r", help="why this is needed (shown to the approver)")
    p.add_argument("--no-wait", action="store_true", help="print the request id and return at once")
    p.add_argument("--timeout", type=float, default=110,
                   help="seconds to wait for approval+run before returning exit 75 (default 110, under a 2-min tool timeout)")
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    if args[:1] in (["-h"], ["--help"]):
        p.print_help()
        return 0
    if args[:1] == ["wait"] and len(args) >= 2:
        return do_wait(int(args[1].lstrip("#")), float(args[2]) if len(args) > 2 else 110)
    if args[:1] == ["list"]:
        return list_main(args[1:])
    a = p.parse_args(args)
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not cmd:
        p.error("no command given: request-root --reason WHY -- CMD [ARGS...]")
    if cmd[0] == "sudo":
        cmd = cmd[1:]
    _, f = call({"op": "submit", "argv": cmd, "cwd": os.getcwd(), "reason": a.reason})
    rid = ok(f)["id"]
    print(f"request #{rid} submitted: {' '.join(cmd)}", file=sys.stderr)
    if a.no_wait:
        print(rid)
        print(f"waiting on approval: sudo root-broker approve {rid}", file=sys.stderr)
        return 0
    print(f"waiting for approval (user runs: sudo root-broker approve {rid})...", file=sys.stderr)
    return do_wait(rid, a.timeout)


def list_main(args):
    _, f = call({"op": "list", "n": int(args[0]) if args else 20})
    for r in ok(f)["reqs"]:
        print(fmt(r))
    return 0


def admin_main(args):
    p = argparse.ArgumentParser(prog="root-broker")
    sub = p.add_subparsers(dest="op", required=True)
    sub.add_parser("serve")
    sub.add_parser("list").add_argument("n", nargs="?", type=int, default=20)
    for name in ("approve", "deny"):
        sp = sub.add_parser(name)
        sp.add_argument("id")
        sp.add_argument("--note", default="")
        if name == "approve":
            sp.add_argument("--ttl", default="", help="also auto-approve the identical request for this long, e.g. 30m")
    sp = sub.add_parser("show")
    sp.add_argument("id")
    a = p.parse_args(args)
    if a.op == "serve":
        return serve()
    if a.op == "list":
        return list_main([str(a.n)])
    rid = int(a.id.lstrip("#"))
    if a.op == "show":
        _, f = call({"op": "list", "n": 1000})
        for r in ok(f)["reqs"]:
            if r["id"] == rid:
                print(fmt(r))
                return 0
        sys.exit(f"no request {rid}")
    if a.op == "approve":
        _, f = call({"op": "list", "n": 1000})
        for r in ok(f)["reqs"]:
            if r["id"] == rid:
                print(fmt(r))
        _, f = call({"op": "approve", "id": rid, "ttl": parse_ttl(a.ttl), "note": a.note})
        ok(f)
        print(f"approved #{rid}" + (f" (identical requests auto-approved for {a.ttl})" if a.ttl else ""))
    else:
        _, f = call({"op": "deny", "id": rid, "note": a.note})
        ok(f)
        print(f"denied #{rid}")
    return 0


if __name__ == "__main__":
    name = os.path.basename(sys.argv[0])
    sys.exit((request_main if name.startswith("request-root") else admin_main)(sys.argv[1:]))
