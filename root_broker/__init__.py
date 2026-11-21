"""Root approval broker: an agent asks for one exact root command, a human approves it, root runs it.

Stdlib only. Installed root-owned by install.sh under /usr/local/lib/root-broker, with:
  /usr/local/bin/request-root   (anyone)   ask for a command to run as root
  /usr/local/sbin/root-broker   (root/you) daemon, plus approve/deny/list for the human

Agent side (no sudo):
  request-root --reason "apply new TLS config" -- systemctl restart caddy
  request-root --no-wait --reason ... -- CMD...   prints the request id and returns
  request-root wait ID                            block until ID finishes, print its output
  request-root list                               pending and recent requests

Human side (sudo is the approval boundary: the agent can't type your password):
  sudo root-broker approve ID [--ttl 30m]   run it; --ttl also auto-approves the identical request for a while
  sudo root-broker deny ID [--note why]
  root-broker list                          (no sudo needed)

Phone side (optional, config "phone"): the daemon also serves a small approval page on the Tailscale IP. It
accepts a connection only if tailscaled says it comes from one of the listed device StableIDs. WireGuard
authenticates that, so a process on this host (the agent) can't pass for the phone. The ntfy push links to it.

The daemon never uses a shell. It resolves argv[0] against root's PATH (never the caller's), runs with a
clean environment, records a sha256 of every existing file named in argv at request time and refuses to
run if any of them changed before execution, and writes every request and result to an audit log.

Modules, roughly in the order a request passes through them:
  config     paths, defaults, loading /etc/root-broker/config.json
  protocol   the Unix-socket wire format (one JSON object per line) and the client's call()
  cli        request-root and root-broker command lines (the client side)
  daemon     the socket listener: identifies the caller (SO_PEERCRED) and dispatches ops to the broker
  checks     what a request is checked for: argv[0] on root's PATH, file pinning, agent-writable files
  broker     request state: submit, approve, deny, wait, TTL grants, audit log
  execute    running an approved command: no shell, clean env, pinned files re-checked
  notify     the ntfy push
  text       making agent-controlled text safe to show (plain text and HTML)
  phone      the phone approval web server and its access gate
  pages      the phone approval HTML pages
  tailscale  asking tailscaled who is on the other end of a connection
"""
