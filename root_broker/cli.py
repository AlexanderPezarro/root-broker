"""Command lines: request-root (the agent's client) and root-broker (daemon + the human's approve/deny/list)."""
import argparse
import os
import sys
import time

from .protocol import call, recv


def main(argv=None):
    argv = sys.argv if argv is None else argv
    name = os.path.basename(argv[0])
    return (request_main if name.startswith("request-root") else admin_main)(argv[1:])


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


def parse_ttl(s):
    if not s:
        return 0
    mult = {"s": 1, "m": 60, "h": 3600}.get(s[-1], None)
    return int(s[:-1]) * mult if mult else int(s)


# ---------------------------------------------------------------- request-root

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


# ---------------------------------------------------------------- root-broker

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
        from .daemon import serve  # only the daemon needs the server side
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
