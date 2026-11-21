"""End-to-end smoke test: runs a real daemon as you (ROOT_BROKER_TEST=1), against temporary paths and a fake
tailscaled, and drives it through request-root, root-broker and the phone page.

  python3 tests/smoke.py                         test the checkout; exit 1 on any failed check
  python3 tests/smoke.py --transcript            also print a normalised transcript of every call
  python3 tests/smoke.py --entry OTHER_BUILD     test another build, e.g. to diff transcripts before/after a refactor

Needs no root and no network: the phone server listens on 127.0.0.1, and tailscaled is faked so whois always
answers "the configured phone". Commands run as you, so the requests are harmless ones (echo, cat, id).
"""
import argparse
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("--entry", default=os.path.join(HERE, "..", "root-broker"), help="entry script to test")
ap.add_argument("--work", help="working directory (default: a fresh temp dir, removed afterwards)")
ap.add_argument("--transcript", action="store_true", help="print the normalised transcript")
opts = ap.parse_args()

entry = os.path.abspath(opts.entry)
work = os.path.abspath(opts.work) if opts.work else tempfile.mkdtemp(prefix="root-broker-smoke-")
shutil.rmtree(work, ignore_errors=True)
os.makedirs(work + "/bin")
for n in ("request-root", "root-broker"):
    os.symlink(entry, f"{work}/bin/{n}")
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    PORT = s.getsockname()[1]
uid = os.getuid()
cfg = {"allowed_uids": [uid], "approver_uids": [uid], "auto_approve": [["/usr/bin/id", "-u"]],
       "phone": {"listen": f"127.0.0.1:{PORT}", "nodes": ["nPHONE"], "bind_device": None}}
with open(f"{work}/config.json", "w") as f:
    json.dump(cfg, f)
env = dict(os.environ, ROOT_BROKER_TEST="1", ROOT_BROKER_SOCK=f"{work}/broker.sock", ROOT_BROKER_STATE=f"{work}/state",
           ROOT_BROKER_CONFIG=f"{work}/config.json", ROOT_BROKER_TAILSCALED_SOCK=f"{work}/ts.sock")


class FakeTailscaled(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"Node": {"StableID": "nPHONE", "Name": "pixel."}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class UnixHTTP(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        c, _ = self.socket.accept()
        return c, ("127.0.0.1", 0)


threading.Thread(target=UnixHTTP(f"{work}/ts.sock", FakeTailscaled).serve_forever, daemon=True).start()

out, failures = [], []


def log(*a):
    out.append(" ".join(str(x) for x in a))


def expect(cond, what):
    log("  check:", "ok" if cond else "FAIL", what)
    if not cond:
        failures.append(what)


def norm(s):
    s = s.replace(work, "WORK")
    return re.sub(r"name=token value='[0-9a-f]+'", "name=token value='TOKEN'", s)


def run(*args, code=None):
    p = subprocess.run([f"{work}/bin/{args[0]}", *args[1:]], env=env, cwd=work, capture_output=True, text=True)
    log(f"$ {' '.join(args)}  -> exit {p.returncode}")
    log("  stdout:", norm(p.stdout))
    log("  stderr:", norm(p.stderr))
    if code is not None:
        expect(p.returncode == code, f"{' '.join(args)!r} exits {code} (got {p.returncode})")
    return p


def start():
    d = subprocess.Popen([sys.executable, entry, "serve"], env=env, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    for addr, fam in ((f"{work}/broker.sock", socket.AF_UNIX), (("127.0.0.1", PORT), socket.AF_INET)):
        for _ in range(100):
            try:
                with socket.socket(fam) as s:
                    s.connect(addr)
                break
            except OSError:
                time.sleep(0.05)
    return d


def page(method, path, body=None, headers=None, status=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    h = {"Host": f"127.0.0.1:{PORT}", **(headers or {})}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read().decode()
    hdrs = {k: v for k, v in r.getheaders() if k != "Date"}
    c.close()
    log(f"HTTP {method} {path} -> {r.status} {json.dumps(hdrs, sort_keys=True)}")
    log("  ", norm(data))
    if status is not None:
        expect(r.status == status, f"{method} {path} {headers or ''} -> {status} (got {r.status})")
    return data


def token(html_):
    return re.search(r"name=token value='([0-9a-f]+)'", html_).group(1)


d = start()
try:
    # socket: auto-approve, approve, deny, pinned file changed, bad requests, TTL grants
    p = run("request-root", "--reason", "auto", "--", "id", "-u", code=0)
    expect(p.stdout.strip() == str(uid), "auto-approved command returns its output")
    run("request-root", "--no-wait", "--reason", "echo test", "--", "echo", "hi", code=0)
    run("root-broker", "approve", "2", code=0)
    expect(run("request-root", "wait", "2", code=0).stdout == "hi\n", "approved command's output comes back")
    run("request-root", "--no-wait", "--reason", "will deny", "--", "false", code=0)
    run("root-broker", "deny", "#3", "--note", "nope", code=0)
    expect("nope" in run("request-root", "wait", "3", code=77).stderr, "deny note reaches the agent")
    with open(f"{work}/f.txt", "w") as f:
        f.write("one\n")
    p = run("request-root", "--no-wait", "--reason", "pinned", "--", "cat", "f.txt", code=0)
    expect("writable by the requester" in run("request-root", "list").stdout, "agent-editable file is warned about")
    with open(f"{work}/f.txt", "w") as f:
        f.write("two\n")
    run("root-broker", "approve", "4", code=0)
    expect("refused: changed" in run("request-root", "wait", "4", code=126).stdout, "changed pinned file is refused")
    expect("not found on root's PATH" in run("request-root", "--reason", "x", "--", "definitely-not-a-cmd", code=1).stderr,
           "unknown command is rejected")
    expect("--reason is required" in run("request-root", "--", "echo", "no reason", code=1).stderr, "reason is required")
    run("request-root", "--no-wait", "--reason", "ttl", "--", "echo", "ttl", code=0)
    run("root-broker", "approve", "5", "--ttl", "1m", code=0)
    run("request-root", "wait", "5", code=0)
    expect(run("request-root", "--reason", "ttl again", "--", "echo", "ttl", code=0).stdout == "ttl\n",
           "identical request runs at once within the TTL")

    # phone: the gate, the form token, warned requests
    run("request-root", "--no-wait", "--reason", "phone ‮", "--", "echo", "from phone", code=0)
    html_ = page("GET", "/r/7", status=200)
    expect("<mark>\\u202e</mark>" in html_, "control characters are highlighted on the page")
    tok = token(html_)
    page("GET", "/r/7", headers={"Host": "evil.example"}, status=403)
    page("POST", "/r/7", f"token={tok}&action=approve", {"Sec-Fetch-Site": "cross-site"}, status=403)
    page("POST", "/r/7", "token=bad&action=approve", {"Sec-Fetch-Site": "same-origin"}, status=403)
    html_ = page("POST", "/r/7", f"token={tok}&action=approve", {"Sec-Fetch-Site": "same-origin"}, status=200)
    expect("<p>Exit 0</p><pre>from phone\n</pre>" in html_, "phone approval runs the command")
    run("request-root", "--no-wait", "--reason", "phone warned", "--", "cat", "f.txt", code=0)
    page("POST", "/r/8", f"token={tok}&action=approve", {"Sec-Fetch-Site": "same-origin"}, status=403)
    tok8 = token(page("GET", "/r/8", status=200))
    page("POST", "/r/8", f"token={tok8}&action=approve", {"Sec-Fetch-Site": "same-origin"}, status=409)
    page("POST", "/r/8", f"token={tok8}&action=deny", {"Origin": f"http://127.0.0.1:{PORT}"}, status=200)
    page("GET", "/", status=200)
    page("GET", "/nope", status=404)

    # restart: anything still pending is dropped, never run later
    run("request-root", "--no-wait", "--reason", "left pending", "--", "echo", "pending", code=0)
    run("root-broker", "show", "9", code=0)
    d.terminate()
    d.wait()
    d = start()
    run("root-broker", "list", "3", code=0)
    expect("expired" in run("root-broker", "approve", "9", code=1).stderr, "pending request is dropped on restart")

    # terminal: escape sequences and bidi characters in agent text are shown, not interpreted
    run("request-root", "--no-wait", "--reason", "tty ‮", "--", "echo", "a\x1b[2K\rb", code=0)
    for p in (run("root-broker", "show", "10", code=0), run("root-broker", "list", "1", code=0)):
        expect("\x1b" not in p.stdout and "‮" not in p.stdout, "no raw escape/bidi characters reach the terminal")
        expect("\\u001b[2K\\u000db" in p.stdout and "\\u202e" in p.stdout, "escaped characters are made visible")
    run("request-root", "--help", code=0)
finally:
    d.terminate()
    d.wait()

with open(f"{work}/state/audit.jsonl") as f:
    events = [json.loads(line) for line in f]
expect({"event": "approved", "id": 7, "by": "phone:pixel"}.items() <= next(
    (e for e in events if e.get("event") == "approved" and e.get("id") == 7), {}).items(),
       "phone approval is audited with the device name")
for ev in events:
    ev.pop("t", None)
    if "req" in ev:
        ev["req"].pop("created", None)
    log("audit", norm(json.dumps(ev, sort_keys=True)))
if opts.transcript:
    print("\n".join(out))
if not opts.work:
    shutil.rmtree(work, ignore_errors=True)
print(f"{len(failures)} failed" + "".join(f"\n  FAIL {w}" for w in failures) if failures else "all checks passed",
      file=sys.stderr)
sys.exit(1 if failures else 0)
