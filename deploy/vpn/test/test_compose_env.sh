#!/usr/bin/env bash
# Inherited COMPOSE_PROFILES must not reach docker, and published mode must
# name its services and reject a running headplane-tailnet.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/idoris-compose-env.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

mkdir -p "$tmp/vpn" "$tmp/bin"
cp "$root/ops-lib.sh" "$tmp/vpn/"
cat > "$tmp/vpn/.env" <<'EOF'
COMPOSE_PROJECT_NAME=idoris-vpn-r4o-env
HEADPLANE_BIND=127.0.0.1
HEADPLANE_PORT=3000
EOF
chmod 600 "$tmp/vpn/.env"
printf 'mode=published\n' > "$tmp/vpn/.admin-mode"
chmod 600 "$tmp/vpn/.admin-mode"

export DOCKER_LOG="$tmp/docker.log"
export SHOW_TAILNET="${SHOW_TAILNET:-0}"
: > "$DOCKER_LOG"
cat > "$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'ENV COMPOSE_PROFILES=%s\n' "${COMPOSE_PROFILES-unset}"
  printf 'ENV COMPOSE_FILE=%s\n' "${COMPOSE_FILE-unset}"
  printf 'ENV COMPOSE_PATH_SEPARATOR=%s\n' "${COMPOSE_PATH_SEPARATOR-unset}"
  printf 'CMD'
  printf ' %q' "$@"
  printf '\n'
} >> "${DOCKER_LOG:?}"
if [[ "$*" == *" config "* ]]; then
  printf '%s\n' '{"services":{"headplane":{"ports":[{"target":3000,"published":"3000","host_ip":"127.0.0.1"}]},"headscale":{},"enroll":{}}}'
elif [[ "$*" == *"headplane-tailnet"* && "${SHOW_TAILNET:-0}" == "1" ]]; then
  printf '%s\n' 'cid-tailnet'
fi
EOF
chmod 755 "$tmp/bin/docker"

# Read by the sourced helpers. shellcheck cannot see that use.
# shellcheck disable=SC2034
here="$tmp/vpn"
die() { echo "compose-env: $*" >&2; exit 1; }
# shellcheck disable=SC1091
source "$tmp/vpn/ops-lib.sh"

export COMPOSE_PROFILES=tailnet-admin
export COMPOSE_FILE=/tmp/r4o-not-a-compose-file
export COMPOSE_PATH_SEPARATOR=:
export PATH="$tmp/bin:$PATH"

: > "$DOCKER_LOG"
start_stack_for_mode published
grep -q 'up -d --wait --wait-timeout 180 headscale enroll headplane' "$DOCKER_LOG" || {
  echo "published up did not name headscale enroll headplane" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
}
if grep -q 'ENV COMPOSE_PROFILES=tailnet-admin' "$DOCKER_LOG"; then
  echo "COMPOSE_PROFILES reached docker" >&2
  exit 1
fi
if grep -q 'ENV COMPOSE_FILE=/tmp/r4o-not-a-compose-file' "$DOCKER_LOG"; then
  echo "COMPOSE_FILE reached docker" >&2
  exit 1
fi
grep -q 'ENV COMPOSE_PROFILES=unset' "$DOCKER_LOG"
grep -q 'ENV COMPOSE_FILE=unset' "$DOCKER_LOG"

: > "$DOCKER_LOG"
export VPN_SERVER_ENROLL_TOKEN=idv1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
start_stack_for_mode tailnet-admin
grep -q 'up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet' "$DOCKER_LOG" || {
  echo "tailnet up did not name the profile services" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
}
unset VPN_SERVER_ENROLL_TOKEN

: > "$DOCKER_LOG"
export SHOW_TAILNET=1
set +e
out="$(verify_published_bindings published 2>&1)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || die "published mode accepted a running headplane-tailnet"
grep -q 'headplane-tailnet is running in published mode' <<<"$out" || die "missing exclusion error: $out"
echo "test_compose_env: ok"
