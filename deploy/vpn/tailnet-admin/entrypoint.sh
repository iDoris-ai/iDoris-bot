#!/bin/sh
# Join this container to the tailnet as tag:vpn-server, then run containerboot.
# Headplane shares this network namespace (network_mode: service:vpn-sidecar)
# so its port 3000 is reachable only on the tailnet address.
#
# VPN_SERVER_ENROLL_TOKEN is the enrollment token for the "vpn-server" entry
# (bootstrap.sh init --tailnet-admin). The pre-auth key minted here is not
# printed. A persisted TS_STATE_DIR skips enrollment on later starts.
set -eu

if [ -n "${TS_AUTHKEY:-}" ]; then
  exec /usr/local/bin/containerboot
fi

token="${ENROLL_TOKEN:?set VPN_SERVER_ENROLL_TOKEN to the vpn-server enrollment token}"
url="${ENROLL_URL:-http://enroll:8787}"

resp="$(wget -qO- \
  --header "Authorization: Bearer ${token}" \
  --header "Content-Type: application/json" \
  --post-data '{"hostname":"vpn-server","os":"linux"}' \
  "${url}/v1/enroll")" || {
  echo "tailnet-admin: enrollment request failed" >&2
  exit 1
}

key="$(printf '%s' "$resp" | sed -n 's/.*"auth_key":"\([^"]*\)".*/\1/p')"
control="$(printf '%s' "$resp" | sed -n 's/.*"control_url":"\([^"]*\)".*/\1/p')"
if [ -z "$key" ] || [ -z "$control" ]; then
  echo "tailnet-admin: enrollment response had no auth_key; check the token and enroll logs" >&2
  exit 1
fi

# Optional override when the public server_url is not reachable from this
# container (hairpin NAT). The default is the control_url enroll returns,
# which is headscale's server_url.
login="${VPN_SERVER_LOGIN_SERVER:-$control}"

export TS_AUTHKEY="$key"
export TS_HOSTNAME="${TS_HOSTNAME:-vpn-server}"
export TS_AUTH_ONCE="${TS_AUTH_ONCE:-true}"
export TS_USERSPACE="${TS_USERSPACE:-false}"
export TS_STATE_DIR="${TS_STATE_DIR:-/var/lib/tailscale}"
export TS_ACCEPT_DNS="${TS_ACCEPT_DNS:-false}"
# The pre-auth key from the vpn-server enrollment entry already carries
# tag:vpn-server. Do not also pass --advertise-tags: the node is not an
# admin, and tagOwners would reject a tag the node asks for itself.
# TS_HOSTNAME and TS_ACCEPT_DNS are already applied by containerboot.
# Repeating them here makes `tailscale up` reject the flag as provided twice.
export TS_EXTRA_ARGS="--login-server=${login}"

echo "tailnet-admin: enrolled vpn-server, starting tailscaled" >&2
exec /usr/local/bin/containerboot
