"""Wire protocol between the CLI and the daemon: one JSON object per line over a Unix socket."""
import json
import socket
import sys

from . import config


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
        s.connect(config.SOCK)
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
        sys.exit(f"request-root: can't reach the broker at {config.SOCK} ({e}). Is root-broker.service running?")
    send(s, obj)
    return s, s.makefile("r")
