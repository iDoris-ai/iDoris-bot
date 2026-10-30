#!/usr/bin/env bash
# A tailnet-admin sidecar that already has tailscaled.state must come up
# without VPN_SERVER_ENROLL_TOKEN. A missing volume still demands the token.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/idoris-sidecar-id.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

mkdir -p "$tmp/vpn/headplane" "$tmp/bin"
cp "$root/ctl.sh" "$root/ops-lib.sh" "$tmp/vpn/"
cat > "$tmp/vpn/headplane/config.yaml" <<'EOF'
server:
  base_url: "http://127.0.0.1:3000"
  cookie_secure: false
EOF
cat > "$tmp/vpn/.env" <<'EOF'
COMPOSE_PROJECT_NAME=idoris-vpn-r4o-id
HEADPLANE_BIND=127.0.0.1
HEADPLANE_PORT=3000
EOF
printf 'mode=tailnet-admin\n' > "$tmp/vpn/.admin-mode"
chmod 600 "$tmp/vpn/.env" "$tmp/vpn/.admin-mode" "$tmp/vpn/headplane/config.yaml"

export DOCKER_LOG="$tmp/docker.log"
: > "$DOCKER_LOG"
cat > "$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'CMD'
  printf ' %q' "$@"
  printf '\n'
} >> "${DOCKER_LOG:?}"
if [[ "$1" == "volume" && "$2" == "ls" ]]; then
  if [[ "${HAS_IDENTITY:-0}" == "1" ]]; then
    printf '%s\n' 'idoris-vpn-r4o-id_vpn-sidecar-state'
  fi
  exit 0
fi
if [[ "$1" == "volume" && "$2" == "inspect" ]]; then
  if [[ "${HAS_IDENTITY:-0}" != "1" ]]; then
    exit 1
  fi
  exit 0
fi
if [[ "$1" == "run" ]]; then
  if [[ "${HAS_IDENTITY:-0}" != "1" ]]; then
    exit 1
  fi
  exit 0
fi
if [[ "$1" == "compose" && "$*" == *" ls "* ]]; then
  printf '%s\n' '[]'
  exit 0
fi
if [[ "$*" == *" config "* ]]; then
  printf '%s\n' '{"services":{"headscale":{},"enroll":{},"headplane":{},"headplane-tailnet":{},"vpn-sidecar":{}}}'
  exit 0
fi
exit 0
EOF
chmod 755 "$tmp/bin/docker"

run_up() {
  : > "$DOCKER_LOG"
  set +e
  out="$(env -u VPN_SERVER_ENROLL_TOKEN PATH="$tmp/bin:$PATH" HAS_IDENTITY="$1" \
    bash "$tmp/vpn/ctl.sh" up 2>&1)"
  ec=$?
  set -e
  printf '%s\n' "$out"
  return "$ec"
}

set +e
out="$(run_up 0)"
ec=$?
set -e
[[ "$ec" -ne 0 ]] || {
  echo "up without identity or token succeeded" >&2
  printf '%s\n' "$out" >&2
  echo "---- docker log ----" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
}
grep -q 'export VPN_SERVER_ENROLL_TOKEN' <<<"$out" || {
  echo "missing token refusal: $out" >&2
  exit 1
}
if grep -q 'vpn-sidecar headplane-tailnet' "$DOCKER_LOG"; then
  echo "profile services were started without identity" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
fi

set +e
out="$(run_up 1)"
ec=$?
set -e
[[ "$ec" -eq 0 ]] || {
  echo "up with sidecar identity failed: $out" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
}
grep -q 'up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet' "$DOCKER_LOG" || {
  echo "identity did not start the tailnet profile" >&2
  cat "$DOCKER_LOG" >&2
  printf '%s\n' "$out" >&2
  exit 1
}
if grep -q 'Published Headplane stays stopped' <<<"$out"; then
  echo "identity was treated as a missing token" >&2
  exit 1
fi
echo "test_sidecar_identity: ok"
