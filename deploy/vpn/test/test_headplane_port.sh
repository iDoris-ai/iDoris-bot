#!/usr/bin/env bash
# HEADPLANE_PORT on the command line wins over .env, and the same value is
# what config generation, .env, and compose config all keep.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/idoris-hp-port.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

mkdir -p "$tmp/vpn/headplane" "$tmp/vpn/enroll" "$tmp/vpn/headscale" "$tmp/vpn/tailnet-admin"
# compose config resolves bind sources. Copy the deployment files, then
# replace the secrets and the port.
rsync -a \
  --exclude 'test/.lab/' \
  --exclude 'backups/' \
  --exclude '.env' \
  --exclude '.admin-mode' \
  --exclude 'enroll/config.json' \
  --exclude 'enroll/headscale.apikey' \
  --exclude 'enroll/minted-tokens.txt' \
  --exclude 'headplane/cookie_secret' \
  --exclude 'headscale/managed.json' \
  "$root/" "$tmp/vpn/"
printf '0123456789abcdef0123456789abcdef' > "$tmp/vpn/headplane/cookie_secret"
printf '%s\n' '{"control_url":"https://vpn.example.org","tenants":[]}' > "$tmp/vpn/enroll/config.json"
printf '%s\n' 'hskey-api-not-a-real-key' > "$tmp/vpn/enroll/headscale.apikey"
chmod 600 "$tmp/vpn/headplane/cookie_secret" "$tmp/vpn/enroll/config.json" "$tmp/vpn/enroll/headscale.apikey"
cat > "$tmp/vpn/.env" <<'EOF'
COMPOSE_PROJECT_NAME=idoris-vpn-r4o-port
HEADPLANE_BIND=127.0.0.1
HEADPLANE_PORT=3000
HEADSCALE_PORT=18080
ENROLL_PORT=18787
DERP_STUN_PORT=13478
ENROLL_UID=65532
ENROLL_GID=65532
EOF
chmod 600 "$tmp/vpn/.env"

# shellcheck disable=SC2034
here="$tmp/vpn"
die() { echo "headplane-port: $*" >&2; exit 1; }
# shellcheck disable=SC1091
source "$tmp/vpn/ops-lib.sh"

export HEADPLANE_PORT=3300
apply_headplane_access tunnel
unset HEADPLANE_PORT
grep -q 'base_url: "http://127.0.0.1:3300"' "$tmp/vpn/headplane/config.yaml" || {
  echo "base_url was not generated from port 3300" >&2
  exit 1
}
grep -q '^HEADPLANE_PORT=3300$' "$tmp/vpn/.env" || {
  echo ".env did not keep HEADPLANE_PORT=3300" >&2
  cat "$tmp/vpn/.env" >&2
  exit 1
}
published="$(compose config --format json | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
ports = cfg["services"]["headplane"]["ports"]
for item in ports:
    if str(item.get("target")) == "3000":
        print(item.get("published"))
        raise SystemExit
raise SystemExit("headplane has no published port")
')"
[[ "$published" == "3300" ]] || {
  echo "compose config published $published, want 3300" >&2
  exit 1
}
echo "test_headplane_port: ok"
