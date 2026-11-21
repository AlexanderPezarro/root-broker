#!/bin/sh
# Install or update the root broker from this checkout. Review the diff first: this code runs as root.
#   sudo ./install.sh
# Installs root-owned copies (the checkout stays agent-editable; the installed copy does not).
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
python3 -I -m py_compile "$here/root_broker.py"
install -o root -g root -m 0755 "$here/root_broker.py" /usr/local/sbin/root-broker
ln -sf /usr/local/sbin/root-broker /usr/local/bin/request-root
install -d -o root -g root -m 0755 /etc/root-broker
# first install only: seed from the gitignored local config.json if there is one, else the example.
# An existing /etc config is never overwritten (it holds the ntfy token).
seed=$here/config.example.json
[ -f "$here/config.json" ] && seed=$here/config.json
[ -f /etc/root-broker/config.json ] || install -o root -g root -m 0600 "$seed" /etc/root-broker/config.json
# root-only: it holds the ntfy token, and anyone who can read that can send (and fake) your pushes
chown root:root /etc/root-broker/config.json && chmod 0600 /etc/root-broker/config.json
install -o root -g root -m 0644 "$here/root-broker.service" /etc/systemd/system/root-broker.service
systemctl daemon-reload
systemctl enable --now root-broker.service
systemctl restart root-broker.service
sleep 1
systemctl --no-pager --lines=3 status root-broker.service
echo "installed. config: /etc/root-broker/config.json  audit log: /var/lib/root-broker/audit.jsonl"
