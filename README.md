# root-broker

Let a coding agent ask for root without ever giving it sudo.

The agent asks for one exact command and gives a reason. You look at that command and approve or deny it. A small daemon running as root then runs it and hands the output and exit code back to the agent. You approve with your sudo password, which the agent can't type, or optionally from your phone.

```
agent:  request-root --reason "open port 8080 for the reverse proxy" -- ufw allow 8080/tcp
you:    root-broker list                        # pending requests (no sudo needed)
        sudo root-broker approve 12             # runs it; the agent's call returns the output
        sudo root-broker approve 12 --ttl 30m   # and auto-approves the identical request for 30 min
        sudo root-broker deny 12 --note "use 8081"
```

## How it works

The code is stdlib-only Python: an entry script, `root-broker`, plus the `root_broker/` package beside it. `install.sh` copies both into `/usr/local/lib/root-broker` (root-owned) and links the entry script under two names:

- **`request-root`** is the agent's client. It sends the request over a Unix socket and blocks until the command has run or the wait times out.
- **`root-broker`** is the daemon (`serve`, run by systemd as root) plus your `list` / `show` / `approve` / `deny` commands.

### Code layout

Each module in `root_broker/` does one job. In the order a request passes through them:

| module | what it does |
|---|---|
| `cli.py` | the `request-root` and `root-broker` command lines (client side) |
| `protocol.py` | the socket wire format, one JSON object per line |
| `daemon.py` | the socket listener: identifies the caller (`SO_PEERCRED`) and dispatches each op |
| `checks.py` | request-time checks: argv[0] on root's PATH, file hashes, agent-writable files |
| `broker.py` | request state (submit, approve, deny, wait, TTL grants) and the audit log |
| `execute.py` | running an approved command: no shell, clean env, pinned files re-checked |
| `notify.py` | the ntfy push |
| `phone.py`, `pages.py`, `tailscale.py` | the phone approval server and its gate, its HTML pages, the tailscaled whois lookup |
| `text.py` | escaping agent-controlled text for the terminal, the push and HTML |
| `config.py` | paths, defaults and config loading |

The daemon identifies every caller by the kernel's peer credentials on the socket (`SO_PEERCRED`), not by anything the caller claims. Only allowed uids may submit requests, and only approver uids may approve them. By default only root can approve, so approving means running `sudo`.

```
agent ──request-root──▶ /run/root-broker/broker.sock ──▶ root-broker daemon (root)
                                                           │  pending request
you ───sudo root-broker approve──────────────────────────▶ │  approved → run, no shell
                                                           ▼
                                        output + exit code back to the agent, audit log
```

### What it checks before running

- **No shell.** argv is run directly, so pipes, globs and `$(...)` are just literal text.
- **Root's PATH.** `argv[0]` is resolved against a fixed root PATH, never the caller's.
- **Clean environment.** The command doesn't inherit any of the agent's environment variables.
- **Files are pinned.** Every existing file named in argv is hashed when the request is made. If any of them changes before you approve, the run is refused (exit 126).
- **Agent-editable files are flagged.** If the agent could edit a file in the request, or replace it in any parent directory, the request carries a ⚠ warning: review the file's contents, not just its name.
- **Requests expire.** A pending request expires after an hour, and pending requests are dropped when the daemon restarts, never run later.
- **Everything is audited.** Every request, decision and result goes to `/var/lib/root-broker/audit.jsonl`, and each command's output is saved under `out/`.
- **Auto-approve list.** `auto_approve` in the config lists exact argv lists that run without asking, such as read-only status commands. The match must be exact, and a request with ⚠ warnings is never auto-approved.

### Exit codes for the agent

The command's own exit code is passed through. Beyond that:

- **75**: the request is still pending. The client waits 110 s, to stay under a typical tool timeout. Re-check later with `request-root wait ID`.
- **77**: the request was denied or expired.
- **126**: the run was refused because a pinned file changed.

## Optional: notifications and phone approval

**Push notifications.** Set `ntfy_url`, and optionally `ntfy_token`, and every request that needs a decision sends an [ntfy](https://ntfy.sh) push with the command, the reason and any warnings. `ntfy-setup.sh` sets this up against a self-hosted ntfy server running in Docker: it creates a publish-only ntfy user and writes the token into the root-only config.

**Phone approval over Tailscale.** With a `phone` block, the daemon also serves a small approval page on the host's Tailscale IP, and the push gets a **Review** button that opens it:

```json
"phone": {"listen": "<tailscale-ip>:7444", "nodes": ["<device StableID>"]}
```

The page shows the full command (one argument per line, with any non-ASCII or control characters highlighted), the reason, the warnings and the pinned file hashes. It has buttons to approve, approve and auto-approve for a while, or deny. These checks decide whether an approval counts:

- **Tailscale identity.** For each connection, the daemon asks tailscaled which device sent it and accepts only the listed device StableIDs (`tailscale whois`). WireGuard authenticates that answer, so a process on the host itself, the agent included, can't pass for the phone.
- **Tailscale interface.** The listener is bound to `tailscale0`, so only packets that actually arrived over Tailscale reach it.
- **No hijacking from other pages.** The Host header must match, which stops DNS rebinding, and a POST must be same-origin and carry an HMAC token that appears only inside the page. The page runs no scripts and can't be framed.
- **Warned requests need sudo.** A request with ⚠ warnings can only be denied from the phone, unless you set `allow_warned`.

Other options: `url` (the link in the push), `hosts` (extra accepted Host values), `ttl_button` and `bind_device`. The phone is effectively a root key, so keep a screen lock on it.

## Install

The installed code runs as root, so review it first.

```bash
sudo ./install.sh        # root-owned copy in /usr/local/sbin, config in /etc/root-broker, systemd unit
sudo NTFY_CONTAINER=ntfy NTFY_BASE=https://ntfy.example.com ./ntfy-setup.sh   # optional
```

To keep your own settings next to the code, copy `config.example.json` to `config.json`, which is gitignored. `install.sh` uses it to seed the installed config on first install and never overwrites an existing one. Keep the ntfy token out of this copy, because the checkout is agent-readable. After install, edit `/etc/root-broker/config.json` (`0600`, root-owned) to set `allowed_uids`, `auto_approve` and, if you want phone approval, `phone`. In `root-broker.service`, set `ROOT_BROKER_GID` to the agent user's group.

The checkout can stay editable by the agent because the installed copy isn't: a change takes effect only after you re-run `install.sh`.

**Smoke test:** `python3 tests/smoke.py` runs a real daemon as you against temporary paths and a fake tailscaled, and checks approve, deny, pinned files, TTL grants, the phone gate and restart handling. Run it before `install.sh`.

**Testing without root:** set `ROOT_BROKER_TEST=1`, point `ROOT_BROKER_SOCK`, `ROOT_BROKER_STATE` and `ROOT_BROKER_CONFIG` at temporary paths, and run `root-broker serve`.

## Limits

This is a review and audit layer. It is only a hard security boundary if the agent's user has no other route to root. For example, membership of the `docker` group is equivalent to root. To make the boundary real, use rootless Docker or remove the agent from that group.
