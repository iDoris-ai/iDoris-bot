#!/bin/sh
# Prove the tailnet-admin entrypoint does not mint a key when tailscaled.state
# already exists, and that VPN_SERVER_LOGIN_SERVER is what `tailscale up` gets.
# Uses the local tailscale image with a fake containerboot. No host ports.
set -eu

root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
image="${TS_IMAGE:-tailscale/tailscale:v1.104.2@sha256:b11583ad2e93e4671128538c88cf11f460444a5d7e449311dd1933a400ab849d}"
work="$(mktemp -d "${TMPDIR:-/tmp}/ts-entry.XXXXXX")"
chmod 700 "$work"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

die() { echo "tailnet-entrypoint: $*" >&2; exit 1; }

if grep -v '^[[:space:]]*#' "$root/tailnet-admin/entrypoint.sh" | grep -q -- '--advertise-tags'; then
  die "entrypoint passes --advertise-tags"
fi
grep -q 'VPN_SERVER_LOGIN_SERVER' "$root/compose.yaml" || die "compose does not pass VPN_SERVER_LOGIN_SERVER"

cat > "$work/containerboot" <<'EOF'
#!/bin/sh
echo "CONTAINERBOOT"
echo "TS_AUTHKEY=${TS_AUTHKEY-unset}"
echo "TS_EXTRA_ARGS=${TS_EXTRA_ARGS-unset}"
exit 0
EOF
chmod 755 "$work/containerboot"

cat > "$work/wget" <<'EOF'
#!/bin/sh
echo "WGET_CALLED" >&2
printf '%s\n' '{"auth_key":"tskey-auth-test","control_url":"https://vpn.example.org"}'
EOF
chmod 755 "$work/wget"

run_entry() {
  state_dir="$1"
  shift
  docker run --rm --network none \
    -e PATH="/opt/fake:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    -v "$root/tailnet-admin/entrypoint.sh:/usr/local/bin/idoris-tailnet-entrypoint.sh:ro" \
    -v "$work/containerboot:/usr/local/bin/containerboot:ro" \
    -v "$work/wget:/opt/fake/wget:ro" \
    -v "$state_dir:/var/lib/tailscale" \
    "$@" \
    --entrypoint /bin/sh \
    "$image" /usr/local/bin/idoris-tailnet-entrypoint.sh
}

mkdir -p "$work/state"
printf '%s\n' 'persisted-state' > "$work/state/tailscaled.state"
out="$(run_entry "$work/state" -e TS_STATE_DIR=/var/lib/tailscale 2>&1)" || die "persisted state exited non-zero: $out"
printf '%s\n' "$out" | grep -q 'not minting a key' || die "persisted state still tried to enroll: $out"
printf '%s\n' "$out" | grep -q 'WGET_CALLED' && die "persisted state called wget: $out"
printf '%s\n' "$out" | grep -q 'CONTAINERBOOT' || die "persisted state did not reach containerboot: $out"
printf '%s\n' "$out" | grep -q 'TS_AUTHKEY=$' || printf '%s\n' "$out" | grep -q 'TS_AUTHKEY=unset' \
  || die "persisted state exported an auth key: $out"
echo "  ok   persisted state does not mint"

mkdir -p "$work/empty"
if out="$(run_entry "$work/empty" -e TS_STATE_DIR=/var/lib/tailscale 2>&1)"; then
  die "missing state and missing token was accepted: $out"
fi
printf '%s\n' "$out" | grep -q 'VPN_SERVER_ENROLL_TOKEN' || die "missing token did not name VPN_SERVER_ENROLL_TOKEN: $out"
echo "  ok   empty state still requires a token"

out="$(run_entry "$work/empty" \
  -e TS_STATE_DIR=/var/lib/tailscale \
  -e ENROLL_TOKEN=idv1_test \
  -e ENROLL_URL=http://enroll:8787 \
  -e VPN_SERVER_LOGIN_SERVER=http://headscale:8080 2>&1)" || die "login-server override failed: $out"
printf '%s\n' "$out" | grep -q 'WGET_CALLED' || die "fresh start did not enroll: $out"
printf '%s\n' "$out" | grep -q 'TS_EXTRA_ARGS=--login-server=http://headscale:8080' \
  || die "VPN_SERVER_LOGIN_SERVER was not passed to containerboot: $out"
printf '%s\n' "$out" | grep -q 'TS_AUTHKEY=tskey-auth-test' || die "minted key was not exported"
echo "  ok   fresh start uses VPN_SERVER_LOGIN_SERVER"

out="$(run_entry "$work/empty" \
  -e TS_STATE_DIR=/var/lib/tailscale \
  -e ENROLL_TOKEN=idv1_test \
  -e ENROLL_URL=http://enroll:8787 \
  -e VPN_SERVER_LOGIN_SERVER= 2>&1)" || die "empty login-server failed: $out"
printf '%s\n' "$out" | grep -q 'TS_EXTRA_ARGS=--login-server=https://vpn.example.org' \
  || die "empty VPN_SERVER_LOGIN_SERVER did not fall back to control_url: $out"
echo "  ok   empty VPN_SERVER_LOGIN_SERVER falls back to control_url"
echo "tailnet-entrypoint: ok"
