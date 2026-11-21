"""The ntfy push sent for every request that needs a decision."""
import shlex
import sys
import urllib.request

from .config import phone_base_url
from .text import visible


def notify(cfg, r):
    url = cfg.get("ntfy_url")
    if not url:
        return
    body = f"#{r['id']} {r['user']}: {visible(shlex.join(r['argv']))}\nwhy: {visible(r['reason'])}"
    if r["warnings"]:
        body += "\n⚠ " + "\n⚠ ".join(visible(w) for w in r["warnings"])
    body += f"\napprove: sudo root-broker approve {r['id']}"
    headers = {"Title": f"Root request #{r['id']}", "Priority": "high", "Tags": "key"}
    if cfg.get("ntfy_token"):
        headers["Authorization"] = f"Bearer {cfg['ntfy_token']}"
    phone = cfg.get("phone")
    if phone:
        link = f"{phone_base_url(phone)}/r/{r['id']}"
        headers.update(Click=link, Actions=f"view, Review, {link}")
        body += " or tap Review"
    req = urllib.request.Request(url, data=body.encode(), method="POST", headers=headers)
    try:
        urllib.request.urlopen(req, timeout=10).close()
    except Exception as e:  # a failed push must not block the request
        print(f"ntfy failed: {e}", file=sys.stderr)
