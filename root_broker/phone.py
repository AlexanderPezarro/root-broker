"""Phone approval over Tailscale: a small HTTP server on the host's Tailscale IP.

Who may approve: only a TCP connection that tailscaled maps to a configured device StableID. Loopback, the
host's own Tailscale IP, LAN and docker traffic all fail that check. The other checks stop a web page open on
the phone from approving for you: the Host header must be ours (stops DNS rebinding), a POST must come from our
own origin, and it must carry an HMAC token that only appears inside our own page. The page has no scripts and
can't be framed, and every agent-supplied string is escaped, with non-ASCII/control characters made visible.
"""
import hmac
import html
import http.server
import secrets
import socket
import socketserver
import sys
import time
import urllib.parse

from . import pages, tailscale
from .config import phone_base_url
from .text import show

HEADERS = (("Cache-Control", "no-store"), ("Referrer-Policy", "same-origin"),
           ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
           ("Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"))


def form_token(key, rid):
    return hmac.new(key, f"approve:{rid}".encode(), "sha256").hexdigest()


class PhoneHandler(http.server.BaseHTTPRequestHandler):
    broker = None
    phone = None
    form_key = None  # per boot; signs the approve forms
    server_version = "root-broker"
    sys_version = ""
    timeout = 20

    def log_message(self, fmt, *args):
        print("phone: " + fmt % args, file=sys.stderr, flush=True)

    def send_page(self, code, title, body):
        data = pages.document(title, body)
        self.send_response(code)
        for k, v in (("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(data))), *HEADERS):
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
            node = tailscale.whois(ip, port) or {}
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
        if not hmac.compare_digest(token, form_token(self.form_key, rid)):
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
        self.send_page(200, *pages.list_page(rs))

    def detail_page(self, r):
        token = form_token(self.form_key, r["id"])
        self.send_page(200, *pages.detail_page(r, self.broker.cfg, self.phone, token))


class PhoneServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    bind_device = None

    def server_bind(self):
        if self.bind_device:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.bind_device.encode())
        socketserver.TCPServer.server_bind(self)  # skip HTTPServer's reverse-DNS lookup
        self.server_name, self.server_port = self.server_address[:2]


def serve(broker, phone):
    host, _, port = phone["listen"].rpartition(":")
    handler = type("Handler", (PhoneHandler,), {"broker": broker, "phone": phone,
                                                "form_key": secrets.token_bytes(32)})
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
