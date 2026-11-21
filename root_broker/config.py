"""Paths, defaults and loading the config file."""
import json
import os
import sys

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


def phone_base_url(phone):
    return (phone.get("url") or f"http://{phone['listen']}").rstrip("/")
