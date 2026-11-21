"""Asking tailscaled (its local API) which Tailscale node is on the other end of a connection."""
import http.client
import json
import socket
import urllib.parse

from . import config


class _TailscaledConn(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("local-tailscaled.sock", timeout=5)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(config.TAILSCALED_SOCK)


def whois(ip, port):
    """The Tailscale node behind a peer address, as tailscaled sees it, or None."""
    addr = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    c = _TailscaledConn()
    try:
        c.request("GET", "/localapi/v0/whois?addr=" + urllib.parse.quote(addr))
        r = c.getresponse()
        return json.loads(r.read(1 << 20)).get("Node") if r.status == 200 else None
    finally:
        c.close()
