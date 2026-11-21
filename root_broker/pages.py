"""HTML for the phone approval pages. Pure functions: each returns (title, body) or the finished document.

Every agent-supplied string goes through show(), which escapes it and highlights non-ASCII/control characters.
"""
import html
import shlex
import time

from .text import show

CSS = """body{font:16px/1.45 system-ui,sans-serif;margin:0;padding:16px;background:#fff;color:#111;max-width:46rem}
@media(prefers-color-scheme:dark){body{background:#111;color:#eee}code,pre{background:#222!important}}
code,pre{background:#f2f2f2;padding:2px 4px;border-radius:4px;overflow-wrap:anywhere;white-space:pre-wrap}
pre{padding:8px;max-height:60vh;overflow:auto}.warn{color:#b45309;font-weight:600}mark{background:#fde047;color:#000}
button{font-size:18px;padding:14px;margin:6px 0;width:100%;border-radius:8px;border:0}
.ok{background:#15803d;color:#fff}.ttl{background:#1d4ed8;color:#fff}.no{background:#b91c1c;color:#fff}
a{color:inherit}li{margin:4px 0}"""


def document(title, body):
    return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style><h2>{html.escape(title)}</h2>{body}").encode()


def list_page(reqs):
    items = "".join(f"<li><a href='/r/{r['id']}'>#{r['id']} {show(r['state'])}</a>: "
                    f"<code>{show(shlex.join(r['argv']))}</code></li>" for r in reqs)
    return "Root requests", f"<ul>{items or '<li>none</li>'}</ul>"


def detail_page(r, cfg, phone, token):
    """One request, with approve/deny buttons while it is pending. token is the form's HMAC token."""
    state = r["state"]
    if state == "pending" and time.time() - r["created"] > cfg["request_ttl"]:
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
        if r["warnings"] and not phone["allow_warned"]:
            b += (f"<p class=warn>A file in this request can be edited by the agent. Read it, then approve with "
                  f"<code>sudo root-broker approve {r['id']}</code>.</p>")
            buttons = "<button class=no name=action value=deny>Deny</button>"
        else:
            buttons = "<button class=ok name=action value=approve>Approve and run as root</button>"
            ttl = min(phone["ttl_button"], cfg["max_ttl"])
            if ttl:
                buttons += (f"<button class=ttl name=action value=approve_ttl>Approve, and auto-approve this exact"
                            f" request for {ttl // 60} min</button>")
            buttons += "<button class=no name=action value=deny>Deny</button>"
        b += (f"<form method=post action='/r/{r['id']}'>"
              f"<input type=hidden name=token value='{token}'>{buttons}</form>")
    elif state in ("done", "refused"):
        b += f"<p>Exit {show(r.get('exit'))}</p><pre>{show((r.get('output') or '')[-20000:])}</pre>"
    elif state == "running":
        b += f"<p>Still running. <a href='/r/{r['id']}'>Refresh</a></p>"
    if r.get("note"):
        b += f"<p>Note: {show(r['note'])}</p>"
    return f"Root request #{r['id']}", b + "<p><a href='/'>All requests</a></p>"
