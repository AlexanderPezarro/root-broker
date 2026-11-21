#!/bin/sh
# Send root-broker pushes through a self-hosted ntfy server running in Docker.
#   sudo NTFY_CONTAINER=ntfy NTFY_BASE=https://ntfy.example.com ./ntfy-setup.sh
# Run after sudo ./install.sh. Safe to re-run: each run rotates the token.
#
# What it does:
#   - ntfy user "root-broker": publish-only on $TOPIC, logs in only by token
#   - optional: gives the ntfy user $PHONE_USER (your phone app's login) read-only access to $TOPIC
#   - writes ntfy_url and ntfy_token into /etc/root-broker/config.json (0600)
#   - restarts the broker and sends a test push
# The token only ever passes through this root process and the root-only config; it isn't printed.
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
C=${NTFY_CONTAINER:?set NTFY_CONTAINER to the ntfy container name}
BASE=${NTFY_BASE:?set NTFY_BASE to the ntfy server URL, e.g. https://ntfy.example.com}
TOPIC=${TOPIC:-root-broker}
PHONE_USER=${PHONE_USER:-}
CFG=/etc/root-broker/config.json
[ -f "$CFG" ] || { echo "$CFG missing: run sudo ./install.sh first" >&2; exit 1; }

if ! docker exec "$C" ntfy user list 2>&1 | grep -q '^user root-broker '; then
  # random password that nobody keeps: this user logs in only by token
  NTFY_PASSWORD=$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(32))') \
    docker exec -e NTFY_PASSWORD "$C" ntfy user add root-broker >/dev/null
fi
docker exec "$C" ntfy access root-broker "$TOPIC" write-only >/dev/null
[ -z "$PHONE_USER" ] || docker exec "$C" ntfy access "$PHONE_USER" "$TOPIC" read-only >/dev/null

# token list covers every user; only touch the root-broker section
for old in $(docker exec "$C" ntfy token list 2>&1 | awk '/^user /{u=$2} u=="root-broker"' | grep -o 'tk_[A-Za-z0-9]*' || true); do
  docker exec "$C" ntfy token remove root-broker "$old" >/dev/null
done
# ntfy prints the new token on stderr
NTFY_TOKEN=$(docker exec "$C" ntfy token add --label=root-broker root-broker 2>&1 | grep -o 'tk_[A-Za-z0-9]*' || true)
[ -n "$NTFY_TOKEN" ] || { echo "couldn't create an ntfy token" >&2; exit 1; }
export NTFY_TOKEN

CFG="$CFG" NTFY_URL="$BASE/$TOPIC" python3 -I - <<'EOF'
import json, os
path = os.environ["CFG"]
with open(path) as f:
    cfg = json.load(f)
cfg["ntfy_url"] = os.environ["NTFY_URL"]
cfg["ntfy_token"] = os.environ["NTFY_TOKEN"]
tmp = path + ".tmp"
with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
EOF
chown root:root "$CFG" && chmod 0600 "$CFG"

systemctl restart root-broker.service
sleep 1
curl -fsS -o /dev/null -H "Authorization: Bearer $NTFY_TOKEN" -H "Title: root-broker test" -H "Tags: key" \
  -d "Pushes from root-broker reach this device." "$BASE/$TOPIC" \
  && echo "test push sent to $BASE/$TOPIC"
journalctl -u root-broker.service -n 3 --no-pager
docker exec "$C" ntfy access
