"""The daemon's Unix-socket listener: identifies each caller by SO_PEERCRED and dispatches ops to the broker."""
import os
import socket
import struct
import sys
import threading

from . import config, phone
from .broker import Broker, view
from .protocol import recv, send


def peer_uid(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


def check_owner(r, uid):
    if uid != 0 and r["uid"] != uid:
        raise PermissionError("not your request")


def handle(broker, conn):
    f = conn.makefile("r")
    try:
        uid = peer_uid(conn)
        msg = recv(f)
        op = msg.get("op")
        if op == "submit":
            rid = broker.submit(msg, uid)
            send(conn, {"ok": True, "id": rid})
        elif op == "wait":
            r = broker.wait(int(msg["id"]), float(msg.get("timeout", 540)))
            check_owner(r, uid)
            send(conn, {"ok": True, "req": view(r, full=True)})
        elif op == "list":
            with broker.lock:
                rs = [view(r) for r in sorted(broker.reqs.values(), key=lambda r: -r["id"])
                      if uid == 0 or r["uid"] == uid][: int(msg.get("n", 20))]
            send(conn, {"ok": True, "reqs": rs})
        elif op in ("approve", "deny"):
            if uid not in broker.cfg["approver_uids"]:
                raise PermissionError("only an approver may do that: run it with sudo")
            if op == "approve":
                broker.approve(int(msg["id"]), uid, ttl=int(msg.get("ttl") or 0), note=msg.get("note", ""))
            else:
                broker.deny(int(msg["id"]), uid, note=msg.get("note", ""))
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


def serve():
    if os.geteuid() != 0 and not os.environ.get("ROOT_BROKER_TEST"):
        sys.exit("root-broker serve must run as root")
    cfg = config.load_config()
    b = Broker(cfg)
    sock = config.SOCK
    os.makedirs(os.path.dirname(sock), exist_ok=True)
    try:
        os.unlink(sock)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    s.bind(sock)
    os.umask(old)
    gid = int(os.environ.get("ROOT_BROKER_GID", "-1"))
    if gid >= 0:
        os.chown(sock, 0, gid)
    os.chmod(sock, 0o660 if gid >= 0 else 0o666)  # peer uid is checked on every op anyway
    s.listen(16)
    print(f"root-broker listening on {sock}", flush=True)
    if cfg.get("phone"):
        threading.Thread(target=phone.serve, args=(b, cfg["phone"]), daemon=True).start()
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(b, conn), daemon=True).start()
