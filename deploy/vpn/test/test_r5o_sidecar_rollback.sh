#!/usr/bin/env bash
# Containerless rollback must put the saved sidecar identity back.
# A tailnet-admin restore that fails the enroll check, after containers
# have been removed, still has the original tailscaled.state.
set -euo pipefail
umask 077

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
origin="$repo/deploy/vpn"
root="$origin"
alpine="alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63"
rand="$(python3 -c 'import random; print(random.randint(100000, 999999))')"
proj="idoris-vpn-r5o-side-${rand}"
src="$repo/deploy/.r5o-side-${rand}"
bundle="$repo/deploy/.r5o-side-bundle-${rand}"
fast="$repo/deploy/.r5o-side-fast-${rand}"
sid_vol="${proj}_vpn-sidecar-state"
hs_vol="${proj}_headscale-data"

die() { echo "r5o-sidecar: $*" >&2; exit 1; }

cleanup() {
  if [[ -d "$src" ]]; then
    docker compose -p "$proj" --project-directory "$src" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  docker volume rm -f "$sid_vol" "$hs_vol" \
    "${proj}_headscale-run" "${proj}_headplane-data" >/dev/null 2>&1 || true
  docker network rm "${proj}_default" >/dev/null 2>&1 || true
  rm -rf "$src" "$bundle" "$fast"
}
trap cleanup EXIT

read_state() {
  docker run --rm --network none -v "${sid_vol}:/data:ro" "$alpine" \
    sh -c 'if [ -f /data/tailscaled.state ]; then cat /data/tailscaled.state; else printf MISSING; fi'
}

echo "test: alpine sidecar restore does not need a container"
mkdir -p "$fast/headscale" "$fast/snap/headscale"
printf 'services: {}\n' > "$fast/compose.yaml"
printf 'COMPOSE_PROJECT_NAME=%s\n' "$proj" > "$fast/.env"
chmod 600 "$fast/.env"
# shellcheck disable=SC2034
here="$fast"
# shellcheck disable=SC1091
source "$root/ops-lib.sh"
docker volume create "$sid_vol" >/dev/null
docker run --rm --network none -v "${sid_vol}:/data" "$alpine" \
  sh -c 'printf wrong-identity > /data/tailscaled.state'
payload="$(mktemp -d "$fast/payload.XXXXXX")"
printf 'original-sidecar\n' > "$payload/tailscaled.state"
tar -C "$payload" -cf "$fast/snap/sidecar-state.tar" tailscaled.state
rm -rf "$payload"
export COMPOSE_PROJECT_LOCK="$proj"
_restore_sidecar_volume "$fast/snap" || die "sidecar volume restore failed"
got="$(read_state)"
[[ "$got" == "original-sidecar" ]] || die "helper left ${got}"

echo "test: a snapshot with no sidecar tar removes a planted identity"
rm -f "$fast/snap/sidecar-state.tar"
docker run --rm --network none -v "${sid_vol}:/data" "$alpine" \
  sh -c 'printf planted > /data/tailscaled.state'
_restore_sidecar_volume "$fast/snap" || die "missing-tar sidecar restore failed"
got="$(read_state)"
[[ "$got" == "MISSING" ]] || die "planted identity remained: ${got}"
docker volume rm -f "$sid_vol" >/dev/null
unset COMPOSE_PROJECT_LOCK

echo "test: failed tailnet-admin restore puts the original sidecar identity back"
command -v rsync >/dev/null || die "rsync not found"
mkdir -p "$src" "$bundle"
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
printf 'mode=tailnet-admin\n' > "$src/.admin-mode"
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

export COMPOSE_PROJECT_NAME="$proj"
export BUILDX_NO_DEFAULT_ATTESTATIONS=1
docker compose -p "$proj" --project-directory "$src" build enroll
docker compose -p "$proj" --project-directory "$src" up -d --wait --wait-timeout 180 headscale
docker volume create "$sid_vol" >/dev/null
printf 'original-sidecar\n' > "$fast/original-sidecar"
docker run --rm --network none -v "${sid_vol}:/data" -v "$fast/original-sidecar:/src:ro" "$alpine" \
  sh -c 'cp /src /data/tailscaled.state'
marker="$(cd "$src" && pwd -P)"
docker run --rm --network none -v "${hs_vol}:/data" -e MARK="$marker" "$alpine" \
  sh -c 'umask 022; printf %s "$MARK" > /data/.idoris-deploy-dir'
docker compose -p "$proj" --project-directory "$src" down --remove-orphans >/dev/null

mkdir -p "$bundle/headscale" "$bundle/state/enroll" "$bundle/state/headscale" \
  "$bundle/state/headplane" "$bundle/sidecar" "$bundle/headplane"
docker run --rm --network none -v "${hs_vol}:/data:ro" "$alpine" \
  tar -C /data -cf - db.sqlite noise_private.key | tar -C "$bundle/headscale" -xf -
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
payload="$(mktemp -d "$fast/bundle-sid.XXXXXX")"
printf 'bundle-sidecar\n' > "$payload/tailscaled.state"
tar -C "$payload" -cf "$bundle/sidecar/state.tar" tailscaled.state
rm -rf "$payload"
chmod 600 "$bundle/state/dotenv" "$bundle/state/enroll/config.json" \
  "$bundle/state/enroll/headscale.apikey" "$bundle/state/headplane/cookie_secret"

# shellcheck disable=SC2034
here="$src"
# restore_deployment installs its own EXIT trap. Run it in a subshell so
# this script's cleanup trap still removes the project.
set +e
out="$(
  set -euo pipefail
  { restore_deployment "$bundle" 0; } 2>&1
)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || die "invalid enroll restore succeeded: $out"
# Invalid JSON stops the enroll process. Compose --wait then reports the
# container unhealthy before idoris-vpn-enroll check runs. Either line is
# this failure; a later sidecar health timeout is not.
if ! grep -q 'enroll config check failed' <<<"$out" && ! grep -q 'enroll-1 is unhealthy' <<<"$out"; then
  die "failure was not the enroll config: $out"
fi
got="$(read_state)"
[[ "$got" == "original-sidecar" ]] || die "sidecar identity after failed restore: ${got}"
if grep -q 'rollback incomplete' <<<"$out"; then
  die "sidecar rollback did not finish: $out"
fi

echo "test_r5o_sidecar_rollback: ok"
