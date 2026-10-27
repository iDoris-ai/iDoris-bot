#!/usr/bin/env bash
# Clean-host restore drill.
#
# Copies deploy/vpn, brings up a lab Headscale (http server_url, DERP off),
# enrolls one node, then:
#   1. refuses an unsafe backup destination without stopping the stack
#   2. writes a full bundle
#   3. destroys the stack, including volumes
#   4. restores into an empty second copy
#   5. checks the original node is still listed and the same enrollment
#      token can enroll a second node
#
# Usage: bash deploy/vpn/test/restore-drill.sh
set -euo pipefail
umask 077

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
origin="$repo/deploy/vpn"
src="$repo/deploy/.drill-src"
dst="$repo/deploy/.drill-dst"
bundle_root="$repo/deploy/.drill-backup"
bundle="$bundle_root/bundle"

die() { echo "drill: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v python3 >/dev/null || die "python3 is required"
command -v rsync >/dev/null || die "rsync is required"

PROJ="idoris-vpn-ctl-$(python3 -c 'import random; print(random.randint(100000, 999999))')"
export COMPOSE_PROJECT_NAME="$PROJ"
ENROLL_UID="$(id -u)"
ENROLL_GID="$(id -g)"
export ENROLL_UID ENROLL_GID

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
free_udp() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

HEADSCALE_PORT="$(free_port)"
HEADPLANE_PORT="$(free_port)"
ENROLL_PORT="$(free_port)"
DERP_STUN_PORT="$(free_udp)"
export HEADSCALE_PORT HEADPLANE_PORT ENROLL_PORT DERP_STUN_PORT

copy_tree() {
  local from="$1" to="$2"
  mkdir -p "$to"
  rsync -a \
    --exclude 'test/.lab/' \
    --exclude 'test/.probe.log' \
    --exclude 'backups/' \
    --exclude '.admin-mode' \
    --exclude '.env' \
    --exclude 'enroll/config.json' \
    --exclude 'enroll/headscale.apikey' \
    --exclude 'enroll/token-labels.json' \
    --exclude 'enroll/minted-tokens.txt' \
    --exclude 'headplane/cookie_secret' \
    --exclude 'headscale/managed.json' \
    "$from/" "$to/"
}

redact() { sed -E 's/hskey-[A-Za-z0-9_.:+/=-]+/[redacted]/g; s/idv1_[0-9a-f]+/[redacted]/g'; }

cleanup() {
  local ec=$?
  if [[ "$ec" -ne 0 ]]; then
    echo "drill: dumping logs (exit ${ec})" >&2
    if [[ -d "$src" ]]; then
      docker compose --project-directory "$src" --project-name "$PROJ" logs --tail 40 2>/dev/null | redact >&2 || true
    fi
    if [[ -d "$dst" ]]; then
      docker compose --project-directory "$dst" --project-name "$PROJ" logs --tail 40 2>/dev/null | redact >&2 || true
    fi
  fi
  docker ps -aq --filter "label=idoris-vpn-drill=${PROJ}" | while read -r id; do
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
  if [[ -d "$src" ]]; then
    docker compose --project-directory "$src" --project-name "$PROJ" --profile tailnet-admin down -v >/dev/null 2>&1 || true
  fi
  if [[ -d "$dst" ]]; then
    docker compose --project-directory "$dst" --project-name "$PROJ" --profile tailnet-admin down -v >/dev/null 2>&1 || true
  fi
  rm -rf "$src" "$dst" "$bundle_root"
  exit "$ec"
}
trap cleanup EXIT

rm -rf "$src" "$dst" "$bundle_root"
mkdir -p "$bundle_root"
chmod 700 "$bundle_root"
copy_tree "$origin" "$src"

python3 - "$src/headscale/config.yaml" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
old = "server_url: https://vpn.example.org"
new = "server_url: http://headscale:8080"
if old not in text:
    raise SystemExit("lab config: server_url placeholder not found")
text = text.replace(old, new, 1)
old_derp = "    enabled: true\n    region_id: 999"
new_derp = "    enabled: false\n    region_id: 999"
if old_derp not in text:
    raise SystemExit("lab config: embedded DERP block not found")
text = text.replace(old_derp, new_derp, 1)
open(path, "w").write(text)
PY

cat > "$src/.env" <<EOF
COMPOSE_PROJECT_NAME=${PROJ}
ENROLL_UID=${ENROLL_UID}
ENROLL_GID=${ENROLL_GID}
HEADSCALE_PORT=${HEADSCALE_PORT}
HEADPLANE_PORT=${HEADPLANE_PORT}
ENROLL_PORT=${ENROLL_PORT}
DERP_STUN_PORT=${DERP_STUN_PORT}
HEADPLANE_BIND=127.0.0.1
EOF
chmod 600 "$src/.env"
od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > "$src/headplane/cookie_secret"
chmod 600 "$src/headplane/cookie_secret"

python3 "$src/policy.py" init \
  --policy "$src/headscale/policy.hujson" \
  --state "$src/headscale/managed.json" \
  --org acme --admin admin >/dev/null

echo "drill: project=${PROJ} headscale=${HEADSCALE_PORT} enroll=${ENROLL_PORT}"
cd "$src"
BUILDX_NO_DEFAULT_ATTESTATIONS=1 docker compose build enroll
docker compose up -d --wait --wait-timeout 180 headscale
docker compose exec -T headscale headscale users create admin >/dev/null
docker compose exec -T headscale headscale users create acme >/dev/null
docker compose exec -T headscale headscale policy check -f /etc/headscale/policy.hujson
docker compose kill -s HUP headscale >/dev/null

acme_id="$(docker compose exec -T headscale headscale users list -o json | python3 -c '
import json, sys
raw = json.load(sys.stdin)
users = raw.get("users", raw) if isinstance(raw, dict) else raw
for u in users:
    if u.get("name") == "acme":
        print(u["id"])
        raise SystemExit
raise SystemExit("acme user missing")
')"

api_key="$(docker compose exec -T headscale headscale apikeys create --expiration 24h | tr -d '\r\n')"
[[ "$api_key" == hskey-api-* ]] || die "apikeys create did not return an API key"
printf '%s' "$api_key" > "$src/enroll/headscale.apikey"
chmod 600 "$src/enroll/headscale.apikey"
unset api_key

image="$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["enroll"]["image"])')"

echo "drill: list-credentials reads a legacy hash and a labelled object"
mkdir -p "$bundle_root/shape"
python3 - "$bundle_root/shape/config.json" <<'PY'
import json, sys
cfg = {
    "control_url": "http://headscale:8080",
    "headscale_url": "http://headscale:8080",
    "headscale_api_key_file": "/etc/idoris/headscale.apikey",
    "tenants": [{
        "name": "acme",
        "headscale_user_id": "1",
        "token_hashes": [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            {
                "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "label": "bootstrap-acme",
                "created_at": "2026-10-27T00:00:00Z",
            },
        ],
        "preauth_ttl": "10m",
    }],
}
with open(sys.argv[1], "w") as fh:
    json.dump(cfg, fh)
    fh.write("\n")
PY
shape_list="$(docker run --rm --network none -v "$bundle_root/shape:/work:ro" --entrypoint idoris-vpn-enroll "$image" list-credentials --config /work/config.json --entry acme)"
printf '%s\n' "$shape_list" | python3 -c '
import sys
text = sys.stdin.read()
if "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in text:
    raise SystemExit("list printed a full hash")
if "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in text:
    raise SystemExit("list printed a full hash")
rows = {}
for line in text.splitlines():
    parts = line.split("\t")
    if len(parts) != 3:
        raise SystemExit("expected 3 tab fields, got %r" % line)
    rows[parts[0]] = parts
if rows.get("-") != ["-", "aaaaaaaaaaaa", "-"]:
    raise SystemExit("legacy hash was not listed as -")
if rows.get("bootstrap-acme") != ["bootstrap-acme", "bbbbbbbbbbbb", "2026-10-27T00:00:00Z"]:
    raise SystemExit("labelled object was not listed")
print("credential shapes ok")
'
rm -rf "$bundle_root/shape"

mint_out="$(docker run --rm --network none --entrypoint idoris-vpn-enroll "$image" token new)"
TOKEN="$(grep -oE 'idv1_[0-9a-f]{64}' <<<"$mint_out" | head -n1 || true)"
HASH="$(grep -oE '^[[:space:]]*[0-9a-f]{64}[[:space:]]*$' <<<"$mint_out" | tr -d '[:space:]' | head -n1 || true)"
unset mint_out
[[ -n "$TOKEN" && -n "$HASH" ]] || die "could not parse token new"

python3 - "$src/enroll/config.json" "$acme_id" "$HASH" <<'PY'
import json, sys
path, uid, digest = sys.argv[1:]
cfg = {
    "control_url": "http://headscale:8080",
    "headscale_url": "http://headscale:8080",
    "headscale_api_key_file": "/etc/idoris/headscale.apikey",
    "tenants": [{
        "name": "acme",
        "headscale_user_id": str(uid),
        "token_hashes": [digest],
        "preauth_ttl": "10m",
    }],
}
with open(path, "w") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
PY
chmod 600 "$src/enroll/config.json"
unset HASH

docker compose up -d --wait --wait-timeout 180 enroll headplane
docker compose exec -T enroll idoris-vpn-enroll check --config /etc/idoris/enroll.json

enroll_key() {
  local hostname="$1"
  python3 - "$TOKEN" "$hostname" "http://127.0.0.1:${ENROLL_PORT}/v1/enroll" <<'PY'
import json, sys, urllib.request
token, hostname, url = sys.argv[1:]
body = json.dumps({"hostname": hostname, "os": "linux"}).encode()
req = urllib.request.Request(url, data=body, headers={
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json",
})
with urllib.request.urlopen(req, timeout=20) as resp:
    data = json.load(resp)
key = data.get("auth_key") or ""
if not key.startswith("hskey-auth-"):
    raise SystemExit("enroll did not return an auth key")
sys.stdout.write(key)
PY
}

net_name() {
  local cid
  cid="$(docker compose ps -q headscale)"
  docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$cid" | head -n1
}

start_member() {
  local cname="$1" hostname="$2" key
  key="$(enroll_key "$hostname")"
  docker run -d --name "$cname" \
    --label "idoris-vpn-drill=${PROJ}" \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    --device /dev/net/tun:/dev/net/tun \
    --network "$(net_name)" \
    -e "TS_AUTHKEY=${key}" \
    -e TS_AUTH_ONCE=true \
    -e TS_USERSPACE=false \
    -e TS_STATE_DIR=/var/lib/tailscale \
    -e "TS_HOSTNAME=${hostname}" \
    -e TS_ACCEPT_DNS=false \
    -e "TS_EXTRA_ARGS=--login-server=http://headscale:8080" \
    --entrypoint /usr/local/bin/containerboot \
    tailscale/tailscale:v1.104.2 >/dev/null
  unset key
}

# Names Headscale recorded. Exact match so drill-member-2 does not count as drill-member.
nodes_have() {
  local host="$1"
  docker compose exec -T headscale headscale nodes list -o json | python3 -c 'import json,sys
host = sys.argv[1]
raw = json.load(sys.stdin)
found = set()
def walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("given_name", "name", "hostname") and isinstance(v, str):
                found.add(v)
            else:
                walk(v)
    elif isinstance(o, list):
        for i in o:
            walk(i)
walk(raw)
dns = host + ".idoris.internal"
raise SystemExit(0 if host in found or dns in found else 1)
' "$host"
}

echo "drill: joining drill-member"
start_member "${PROJ}-member" drill-member
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if docker exec "${PROJ}-member" tailscale status --json 2>/dev/null | python3 -c 'import json,sys
s=json.load(sys.stdin)
raise SystemExit(0 if s.get("BackendState")=="Running" else 1)'; then
    ready=1
    break
  fi
  sleep 3
done
[[ "$ready" == 1 ]] || die "drill-member did not reach Running"
nodes_have drill-member || die "headscale did not list drill-member before backup"

echo "drill: refusing unsafe backup destinations"
python3 -c 'import os,sys; os.mkdir(sys.argv[1], 0o755); os.chmod(sys.argv[1], 0o755)' "$bundle_root/loose"
set +e
loose_out="$(bash "$src/ctl.sh" backup "$bundle_root/loose" 2>&1)"
loose_ec=$?
set -e
[[ "$loose_ec" -ne 0 ]] || die "accepted a mode 0755 backup directory"
grep -q "not private" <<<"$loose_out" || die "loose destination was not refused: ${loose_out}"
docker compose ps --status running -q headscale | grep -q . || die "loose-dest refusal stopped headscale"
ln -s "$bundle_root/loose" "$bundle_root/via-link"
set +e
link_out="$(bash "$src/ctl.sh" backup "$bundle_root/via-link" 2>&1)"
link_ec=$?
set -e
[[ "$link_ec" -ne 0 ]] || die "accepted a symlink backup destination"
grep -q "symlink" <<<"$link_out" || die "symlink destination was not refused: ${link_out}"
docker compose ps --status running -q headscale | grep -q . || die "symlink refusal stopped headscale"

echo "drill: backup, destroy, restore into an empty tree"
bash "$src/ctl.sh" backup "$bundle"
python3 - "$bundle" <<'PY'
import os, sys
root = sys.argv[1]
required = [
    "manifest.json",
    "headscale/db.sqlite",
    "headscale/noise_private.key",
    "state/enroll/config.json",
    "state/enroll/headscale.apikey",
    "state/headplane/cookie_secret",
    "state/dotenv",
    "state/headscale/managed.json",
    "state/headscale/config.yaml",
    "state/headscale/policy.hujson",
    "state/headplane/config.yaml",
    "state/compose.yaml",
]
for rel in required:
    path = os.path.join(root, rel)
    if not os.path.isfile(path) or os.path.islink(path):
        raise SystemExit("missing %s" % rel)
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise SystemExit("%s mode %o" % (rel, mode))
# This drill turns embedded DERP off, so Headscale v0.29.6 never writes the key.
derp = os.path.join(root, "headscale/derp_server_private.key")
if os.path.lexists(derp):
    raise SystemExit("embedded DERP is off; derp key should be omitted")
for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
    if os.path.islink(dirpath):
        raise SystemExit("symlink dir %s" % dirpath)
    mode = os.stat(dirpath).st_mode & 0o777
    if mode & 0o077:
        raise SystemExit("dir %s mode %o" % (dirpath, mode))
    for name in filenames:
        path = os.path.join(dirpath, name)
        if os.path.islink(path):
            raise SystemExit("symlink %s" % path)
text = open(os.path.join(root, "manifest.json")).read()
for needle in ("idv1_", "hskey-", "ENROLL_TOKEN"):
    if needle in text:
        raise SystemExit("manifest contains %s" % needle)
if "headscale" not in text:
    raise SystemExit("manifest has no headscale image")
sidecar = os.path.join(root, "state/enroll/token-labels.json")
if os.path.lexists(sidecar):
    raise SystemExit("fresh backup must not contain token-labels.json")
print("bundle layout ok")
PY

docker rm -f "${PROJ}-member" >/dev/null
docker compose --profile tailnet-admin down -v
if docker volume ls --format '{{.Name}}' | grep -q "^${PROJ}_"; then
  die "volumes survived compose down -v"
fi
# The shell is still inside $src. Removing it makes the next python fail
# (pyenv tries to stay in the deleted directory).
cd "$repo"
rm -rf "$src"

echo "drill: restoring into a clean copy"
copy_tree "$origin" "$dst"
bash "$dst/ctl.sh" restore "$bundle" --force

# The restored config carries the lab server_url. Confirm the token hash
# survived, then enroll a second node on the rebuilt stack.
python3 - "$dst/enroll/config.json" "$TOKEN" <<'PY'
import hashlib, json, sys
cfg = json.load(open(sys.argv[1]))
want = hashlib.sha256(sys.argv[2].encode()).hexdigest()
got = []
for item in cfg["tenants"][0]["token_hashes"]:
    if isinstance(item, str):
        got.append(item.lower())
    elif isinstance(item, dict) and isinstance(item.get("hash"), str):
        got.append(item["hash"].lower())
    else:
        raise SystemExit("token_hashes entry is not a hex string or an object")
if want not in got:
    raise SystemExit("restored enroll config does not contain the original token hash")
print("restored token hash matches")
PY

cd "$dst"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if docker compose exec -T headscale headscale health >/dev/null 2>&1 \
    && docker compose exec -T enroll idoris-vpn-enroll check --config /etc/idoris/enroll.json >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker compose exec -T headscale headscale health >/dev/null
nodes_have drill-member || die "restored database lost drill-member"

echo "drill: token list shows the restored legacy credential as -"
listed="$(bash "$dst/ctl.sh" token list --entry acme)"
prefix="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:12])' "$TOKEN")"
printf '%s\n' "$listed" | python3 -c '
import sys
prefix = sys.argv[1]
rows = [line.rstrip("\n").split("\t") for line in sys.stdin if line.strip()]
hits = [r for r in rows if len(r) == 3 and r[0] == "-" and r[1].lower() == prefix]
if len(hits) != 1:
    raise SystemExit("token list did not show one unlabeled credential")
if any(len(part) == 64 for row in rows for part in row):
    raise SystemExit("token list printed a full hash")
print("token list ok")
' "$prefix"

echo "drill: same token enrolls a new node"
start_member "${PROJ}-member2" drill-member-2
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if nodes_have drill-member && nodes_have drill-member-2; then
    ready=1
    break
  fi
  sleep 3
done
[[ "$ready" == 1 ]] || die "restored token did not enroll drill-member-2 beside the original node"

echo "drill: restore ignores an obsolete token-labels.json"
mkdir -p "$bundle/state/enroll"
printf '%s\n' '{"version":1,"entries":{}}' > "$bundle/state/enroll/token-labels.json"
chmod 600 "$bundle/state/enroll/token-labels.json"
set +e
second="$(bash "$dst/ctl.sh" restore "$bundle" --force 2>&1)"
second_ec=$?
set -e
if [[ "$second_ec" -ne 0 ]]; then
  printf '%s\n' "$second" | redact >&2
  die "restore failed when token-labels.json was present"
fi
grep -q 'ignoring obsolete' <<<"$second" || die "restore did not ignore token-labels.json"
[[ ! -e "$dst/enroll/token-labels.json" && ! -L "$dst/enroll/token-labels.json" ]] || die "restore copied token-labels.json"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if docker compose exec -T headscale headscale health >/dev/null 2>&1 \
    && docker compose exec -T enroll idoris-vpn-enroll check --config /etc/idoris/enroll.json >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker compose exec -T headscale headscale health >/dev/null
nodes_have drill-member || die "restore with a sidecar file lost drill-member"
listed="$(bash "$dst/ctl.sh" token list --entry acme)"
printf '%s\n' "$listed" | python3 -c '
import sys
prefix = sys.argv[1]
rows = [line.rstrip("\n").split("\t") for line in sys.stdin if line.strip()]
hits = [r for r in rows if len(r) == 3 and r[0] == "-" and r[1].lower() == prefix]
if len(hits) != 1:
    raise SystemExit("token list changed after ignoring token-labels.json")
print("obsolete sidecar ignored")
' "$prefix"
echo "drill: ok"
unset TOKEN
