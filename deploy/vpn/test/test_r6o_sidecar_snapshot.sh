#!/usr/bin/env bash
# Headscale can be up in tunnel/published mode while the sidecar container
# is gone and the named volume still holds tailscaled.state (`down`, then
# `up` without the tailnet-admin profile). A restore that fails after the
# snapshot must put those bytes back. Deleting the file is allowed only when
# the snapshot recorded that the volume or the file was confirmed absent.
set -euo pipefail
umask 077

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
origin="$repo/deploy/vpn"
root="$origin"
alpine="alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63"
rand="$(python3 -c 'import random; print(random.randint(100000, 999999))')"
proj="idoris-vpn-r6o-side-${rand}"
src="$repo/deploy/.r6o-side-${rand}"
bundle="$(mktemp -d "${TMPDIR:-/tmp}/r6o-side-bundle.XXXXXX")"
work="$(mktemp -d "${TMPDIR:-/tmp}/r6o-side-work.XXXXXX")"
sid_vol="${proj}_vpn-sidecar-state"
hs_vol="${proj}_headscale-data"
original='original-r6o-sidecar'
planted='bundle-r6o-sidecar'

die() { echo "r6o-sidecar: $*" >&2; exit 1; }

cleanup() {
  if [[ -d "$src" ]]; then
    docker compose -p "$proj" --project-directory "$src" --profile tailnet-admin down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  docker volume rm -f "$sid_vol" "$hs_vol" \
    "${proj}_headscale-run" "${proj}_headplane-data" >/dev/null 2>&1 || true
  docker network rm "${proj}_default" >/dev/null 2>&1 || true
  rm -rf "$src" "$bundle" "$work"
}
trap cleanup EXIT

read_state() {
  docker run --rm --network none -v "${sid_vol}:/data:ro" "$alpine" \
    sh -c 'if [ -f /data/tailscaled.state ]; then cat /data/tailscaled.state; else printf MISSING; fi'
}

echo "test: copy the stack and boot headscale without a sidecar container"
command -v rsync >/dev/null || die "rsync not found"
command -v docker >/dev/null || die "docker not found"
mkdir -p "$src"
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
  "$origin/" "$src/"

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

hs_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
hp_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
en_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
stun_port="$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
op_uid="$(id -u)"
op_gid="$(id -g)"
cat > "$src/.env" <<EOF
COMPOSE_PROJECT_NAME=${proj}
ENROLL_UID=${op_uid}
ENROLL_GID=${op_gid}
HEADSCALE_PORT=${hs_port}
HEADPLANE_PORT=${hp_port}
ENROLL_PORT=${en_port}
DERP_STUN_PORT=${stun_port}
HEADPLANE_BIND=127.0.0.1
HEADPLANE_ACCESS=tunnel
EOF
chmod 600 "$src/.env"
printf 'mode=published\n' > "$src/.admin-mode"
chmod 600 "$src/.admin-mode"
mkdir -p "$src/enroll" "$src/headplane"
printf '%s\n' '{"tenants":[]}' > "$src/enroll/config.json"
printf '%s\n' 'seed-api-key' > "$src/enroll/headscale.apikey"
printf '%s' '0123456789abcdef0123456789abcdef' > "$src/headplane/cookie_secret"
chmod 600 "$src/enroll/config.json" "$src/enroll/headscale.apikey" "$src/headplane/cookie_secret"
python3 "$src/policy.py" init \
  --policy "$src/headscale/policy.hujson" \
  --state "$src/headscale/managed.json" \
  --org acme --admin admin >/dev/null

# shellcheck disable=SC2034
here="$src"
# shellcheck disable=SC1091
source "$root/ops-lib.sh"
echo "test: sourced ops-lib; project=${proj} headscale=${hs_port}"

export COMPOSE_PROJECT_NAME="$proj"
export BUILDX_NO_DEFAULT_ATTESTATIONS=1
docker compose -p "$proj" --project-directory "$src" build enroll
docker compose -p "$proj" --project-directory "$src" up -d --wait --wait-timeout 180 headscale

hs_cid="$(docker compose -p "$proj" --project-directory "$src" ps -aq headscale)"
[[ -n "$hs_cid" ]] || die "headscale container is missing"
sid_cid="$(docker compose -p "$proj" --project-directory "$src" --profile tailnet-admin ps -aq vpn-sidecar || true)"
[[ -z "$sid_cid" ]] || die "sidecar container already exists: ${sid_cid}"

vol_name="$(docker compose -p "$proj" --project-directory "$src" --profile tailnet-admin config --format json | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
print((cfg.get("volumes") or {}).get("vpn-sidecar-state", {}).get("name") or "")
')"
[[ "$vol_name" == "$sid_vol" ]] || die "compose sidecar volume is ${vol_name}, want ${sid_vol}"

docker volume create "$sid_vol" >/dev/null
printf '%s\n' "$original" > "$work/original-sidecar"
docker run --rm --network none -v "${sid_vol}:/data" -v "$work/original-sidecar:/src:ro" "$alpine" \
  sh -c 'cp /src /data/tailscaled.state'
marker="$(cd "$src" && pwd -P)"
docker run --rm --network none -v "${hs_vol}:/data" -e MARK="$marker" "$alpine" \
  sh -c 'umask 022; printf %s "$MARK" > /data/.idoris-deploy-dir'
got="$(read_state)"
[[ "$got" == "$original" ]] || die "seed identity is ${got}"
echo "test: headscale container ${hs_cid} is present, sidecar container is absent, volume holds the original identity"

mkdir -p "$bundle/headscale" "$bundle/state/enroll" "$bundle/state/headscale" \
  "$bundle/state/headplane" "$bundle/sidecar" "$bundle/headplane"
docker cp "$hs_cid:/var/lib/headscale/db.sqlite" "$bundle/headscale/db.sqlite"
docker cp "$hs_cid:/var/lib/headscale/noise_private.key" "$bundle/headscale/noise_private.key"
[[ -s "$bundle/headscale/db.sqlite" && -s "$bundle/headscale/noise_private.key" ]] \
  || die "seed did not produce a headscale database"
cp "$src/enroll/headscale.apikey" "$bundle/state/enroll/headscale.apikey"
cp "$src/headplane/cookie_secret" "$bundle/state/headplane/cookie_secret"
cp "$src/headscale/managed.json" "$bundle/state/headscale/managed.json"
cp "$src/headscale/config.yaml" "$bundle/state/headscale/config.yaml"
cp "$src/headscale/policy.hujson" "$bundle/state/headscale/policy.hujson"
cp "$src/headplane/config.yaml" "$bundle/state/headplane/config.yaml"
cp "$src/compose.yaml" "$bundle/state/compose.yaml"
cp "$src/.env" "$bundle/state/dotenv"
printf '%s\n' '{not-json' > "$bundle/state/enroll/config.json"
printf '%s\n' '{}' > "$bundle/manifest.json"
printf 'mode=tailnet-admin\n' > "$bundle/admin-mode"
payload="$(mktemp -d "$work/bundle-sid.XXXXXX")"
printf '%s\n' "$planted" > "$payload/tailscaled.state"
tar -C "$payload" -cf "$bundle/sidecar/state.tar" tailscaled.state
rm -rf "$payload"
chmod 600 "$bundle/state/dotenv" "$bundle/state/enroll/config.json" \
  "$bundle/state/enroll/headscale.apikey" "$bundle/state/headplane/cookie_secret"

run_failed_restore() {
  local log="$work/restore.out"
  : > "$log"
  set +e
  (
    set -euo pipefail
    restore_deployment "$bundle" 0
  ) >"$log" 2>&1
  ec=$?
  set -e
  out="$(cat "$log")"
}

expect_enroll_failure() {
  local label="$1"
  [[ "$ec" -ne 0 ]] || die "${label}: invalid enroll restore succeeded: $out"
  if ! grep -q 'enroll config check failed' <<<"$out" && ! grep -q 'enroll-1 is unhealthy' <<<"$out"; then
    die "${label}: failure was not the enroll config: $out"
  fi
  if grep -q 'rollback incomplete' <<<"$out"; then
    die "${label}: rollback incomplete: $out"
  fi
  if grep -q 'not captured' <<<"$out"; then
    die "${label}: sidecar state was not captured: $out"
  fi
  grep -q 'rollback complete' <<<"$out" || die "${label}: rollback did not finish: $out"
}

echo "test: failed restore with headscale up keeps the original sidecar bytes"
run_failed_restore
expect_enroll_failure "retained identity"
got="$(read_state)"
[[ "$got" == "$original" ]] || die "sidecar identity after failed restore: ${got}"
hs_cid="$(docker compose -p "$proj" --project-directory "$src" ps -aq headscale)"
[[ -n "$hs_cid" ]] || die "rollback removed the headscale container"
sid_cid="$(docker compose -p "$proj" --project-directory "$src" --profile tailnet-admin ps -aq vpn-sidecar || true)"
[[ -z "$sid_cid" ]] || die "rollback left a sidecar container: ${sid_cid}"

echo "test: confirmed absence still removes the bundle sidecar identity"
docker run --rm --network none -v "${sid_vol}:/data" "$alpine" rm -f /data/tailscaled.state
got="$(read_state)"
[[ "$got" == "MISSING" ]] || die "could not clear sidecar identity before the absent restore: ${got}"
run_failed_restore
expect_enroll_failure "confirmed absent"
got="$(read_state)"
[[ "$got" == "MISSING" ]] || die "confirmed-absent rollback left ${got}"

echo "test_r6o_sidecar_snapshot: ok"
