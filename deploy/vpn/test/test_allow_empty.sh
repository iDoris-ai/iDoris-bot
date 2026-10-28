#!/usr/bin/env bash
# ctl.sh token revoke and offboard forward --allow-empty to the enroll CLI.
# Docker is a stub. The last-credential refusal without the flag is covered
# by credentials.sh against the real CLI.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/idoris-allow-empty.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

mkdir -p "$tmp/vpn" "$tmp/bin" "$tmp/enroll"
cp "$root/ctl.sh" "$root/ops-lib.sh" "$root/compose.yaml" "$tmp/vpn/"
printf 'COMPOSE_PROJECT_NAME=idoris-vpn-r4o-empty\n' > "$tmp/vpn/.env"
chmod 600 "$tmp/vpn/.env"

export DOCKER_LOG="$tmp/docker.log"
: > "$DOCKER_LOG"
cat > "$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${DOCKER_LOG:?}"
if [[ "$*" == *" ls "* ]]; then
  printf '[]\n'
elif [[ "$*" == *" revoke "* ]]; then
  printf 'revoked acme kept 0123456789ab\n'
fi
EOF
chmod 755 "$tmp/bin/docker"

run() {
  env -u COMPOSE_PROJECT_NAME -u COMPOSE_PROFILES -u COMPOSE_FILE \
    PATH="$tmp/bin:$PATH" ENROLL_DIR="$tmp/enroll" \
    bash "$tmp/vpn/ctl.sh" "$@"
}

help_text="$(run help)"
grep -q -- '--allow-empty' <<<"$help_text"

: > "$DOCKER_LOG"
run token revoke --entry acme --label kept >/dev/null
grep -q 'revoke --config /work/config.json --entry acme --label kept' "$DOCKER_LOG"
if grep -q -- '--allow-empty' "$DOCKER_LOG"; then
  echo "revoke without --allow-empty still forwarded it" >&2
  exit 1
fi

: > "$DOCKER_LOG"
run token revoke --entry acme --label kept --allow-empty >/dev/null
grep -q 'revoke --config /work/config.json --entry acme --label kept --allow-empty' "$DOCKER_LOG" || {
  echo "token revoke did not forward --allow-empty" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
}

: > "$DOCKER_LOG"
run offboard --entry acme --hash-prefix 0123456789ab >/dev/null
if grep -q -- '--allow-empty' "$DOCKER_LOG"; then
  echo "offboard without --allow-empty still forwarded it" >&2
  exit 1
fi

: > "$DOCKER_LOG"
off="$(run offboard --entry acme --hash-prefix 0123456789ab --allow-empty)"
grep -q 'revoke --config /work/config.json --entry acme --hash-prefix 0123456789ab --allow-empty' "$DOCKER_LOG" || {
  echo "offboard did not forward --allow-empty" >&2
  cat "$DOCKER_LOG" >&2
  exit 1
}
grep -q 'no node was expired or deleted' <<<"$off"
echo "test_allow_empty: ok"
