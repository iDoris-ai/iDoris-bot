#!/usr/bin/env bash
# Bootstrap of the iDoris VPN control plane, and onboarding of further tenants.
#   1. builds the enrollment image and starts Headscale (waits until healthy)
#   2. creates the tenant (Headscale user <tenant>)
#   3. creates an API key for the enrollment service (once)
#   4. adds two enrollment entries to enroll/config.json, each with its own token:
#        <tenant>            members' personal devices
#        <tenant>-local-ai   the Local AI host, tagged tag:<tenant>-local-ai
#   5. starts everything and verifies it
#
# Usage: bash deploy/vpn/bootstrap.sh [tenant]      (tenant defaults to "acme")
#   Run it again with another name to add a tenant to a running installation;
#   then copy the TENANT BLOCKs in headscale/policy.hujson for that tenant.
# Needs: docker with compose v2, python3. No Go toolchain on the host.
# Idempotent: an existing user, API key, cookie secret and enrollment entry is
# kept and never gets a new token.
set -euo pipefail
umask 077
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

tenant="${1:-acme}"

die() { echo "bootstrap: $*" >&2; exit 1; }
trap 'echo "bootstrap failed; inspect with: (cd $here && docker compose ps && docker compose logs --tail=50)" >&2' ERR

command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v python3 >/dev/null || die "python3 is required"
# The name is used as Headscale user, in "<tenant>@" and in tag:<tenant>-local-ai
# (Headscale requires lowercase tags).
[[ "$tenant" =~ ^[a-z]([a-z0-9-]*[a-z0-9])?$ ]] || die "invalid tenant name '$tenant' (lowercase letters, digits and '-'; must start with a letter)"

# Only active lines count: the explanatory comments mention the placeholder too.
placeholder="$(grep -lE '^[^#]*vpn\.example\.org' headscale/config.yaml headplane/config.yaml || true)"
if [[ -n "$placeholder" ]]; then
  die "replace vpn.example.org with your public hostname in: ${placeholder//$'\n'/ }"
fi

# Strip quotes and trailing comments from `server_url: "https://host"  # note`.
control_url="$(sed -n 's/^server_url:[[:space:]]*//p' headscale/config.yaml | sed 's/[[:space:]]*#.*$//' | tr -d "\"'" | head -n1)"
[[ "$control_url" == https://* ]] || die "headscale/config.yaml server_url must be an https:// URL (got '$control_url')"
# Tailscale clients re-dial the control server on port 443 (controlhttp forceNoise443).
if [[ "${control_url#https://}" =~ :([0-9]+)(/|$) && "${BASH_REMATCH[1]}" != 443 ]]; then
  die "server_url must be served on port 443 (got '$control_url')"
fi

# Warn (never fail) when policy.hujson has no active rule for this tenant: its
# members and Local AI host would be able to reach nothing.
policy_warning=""
policy_body="$(sed 's#//.*$##' headscale/policy.hujson)"
if ! grep -qF "\"$tenant@" <<<"$policy_body" || ! grep -qF "\"tag:$tenant-local-ai" <<<"$policy_body"; then
  policy_warning="WARNING: headscale/policy.hujson has no active rules for tenant '$tenant' (\"$tenant@\" / tag:$tenant-local-ai).
         Until you copy the three TENANT BLOCKs for it, its devices can reach nothing.
         Then:  docker compose exec headscale headscale policy check -f /etc/headscale/policy.hujson
                docker compose kill -s HUP headscale"
  echo "$policy_warning" >&2
fi

hs() { docker compose exec -T headscale headscale "$@"; }

# Persist the uid/gid the enroll container runs as, so it can read the 0600
# secret files written below (compose.yaml: user: ${ENROLL_UID}:${ENROLL_GID}).
set_env() {
  local tmp
  tmp="$(mktemp .env.XXXXXX)"
  { grep -v "^$1=" .env 2>/dev/null || true; echo "$1=$2"; } > "$tmp"
  mv "$tmp" .env
}
set_env ENROLL_UID "$(id -u)"
set_env ENROLL_GID "$(id -g)"

# Headplane session secret: exactly 32 characters.
if [[ ! -s headplane/cookie_secret ]]; then
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > headplane/cookie_secret
  echo "wrote headplane/cookie_secret"
fi
[[ "$(wc -c < headplane/cookie_secret | tr -d ' ')" == 32 ]] || die "headplane/cookie_secret must be exactly 32 bytes"

echo "building enrollment image..."
# No provenance/SBOM attestations: they change the image digest on every build and
# make a re-run needlessly recreate the running enroll container.
BUILDX_NO_DEFAULT_ATTESTATIONS=1 docker compose build enroll

echo "starting headscale..."
docker compose up -d --wait --wait-timeout 120 headscale

# Print the id of Headscale user $1 (empty if it does not exist).
user_id_of() {
  hs users list -o json | python3 -c '
import json, sys
users = json.load(sys.stdin) or []
print(next((u["id"] for u in users if u.get("name") == sys.argv[1]), ""))' "$1"
}

user_id="$(user_id_of "$tenant")"
if [[ -z "$user_id" ]]; then
  hs users create "$tenant" >/dev/null
  user_id="$(user_id_of "$tenant")"
fi
[[ "$user_id" =~ ^[0-9]+$ ]] || die "could not resolve the Headscale user id of '$tenant' (got '$user_id')"
echo "headscale user '$tenant' has id $user_id"

if [[ ! -s enroll/headscale.apikey ]]; then
  api_key="$(hs apikeys create --expiration 8760h | tr -d '\r\n')"
  [[ "$api_key" == hskey-api-* ]] || die "unexpected 'apikeys create' output"
  printf '%s' "$api_key" > enroll/headscale.apikey
  echo "wrote enroll/headscale.apikey (expires in 365d; rotate with: headscale apikeys create / expire)"
fi

# Which of the tenant's two enrollment entries exist already?
have_members=0
have_ai=0
if [[ -e enroll/config.json ]]; then
  names="$(python3 -c 'import json, sys; print(" ".join(t["name"] for t in json.load(open(sys.argv[1])).get("tenants", [])))' enroll/config.json)"
  [[ " $names " == *" $tenant "* ]] && have_members=1
  [[ " $names " == *" $tenant-local-ai "* ]] && have_ai=1
fi

members_token=""
members_hash=""
ai_token=""
ai_hash=""
if (( have_members == 0 || have_ai == 0 )); then
  # `config --images enroll` also lists the images of its dependencies, in no fixed order.
  image="$(docker compose config --format json | python3 -c 'import json, sys; print(json.load(sys.stdin)["services"]["enroll"]["image"])')"
  # Output is two labelled lines; select by content, not by line number.
  mint() {
    local out tok hash
    out="$(docker run --rm --network none --entrypoint idoris-vpn-enroll "$image" token new)"
    tok="$(grep -oE 'idv1_[0-9a-f]{64}' <<<"$out" | head -n1 || true)"
    hash="$(grep -oE '^[[:space:]]*[0-9a-f]{64}[[:space:]]*$' <<<"$out" | tr -d '[:space:]' | head -n1 || true)"
    [[ -n "$tok" && -n "$hash" ]] || die "could not parse 'idoris-vpn-enroll token new' output"
    printf '%s %s\n' "$tok" "$hash"
  }
  if (( have_members == 0 )); then read -r members_token members_hash < <(mint); fi
  if (( have_ai == 0 )); then read -r ai_token ai_hash < <(mint); fi

  python3 - enroll/config.json "$control_url" "$tenant" "$user_id" "$members_hash" "$ai_hash" > enroll/config.json.tmp <<'PY'
import json, os, sys
path, control_url, tenant, user_id, members_hash, ai_hash = sys.argv[1:7]
if os.path.exists(path):
    with open(path) as f:
        cfg = json.load(f)
else:
    cfg = {
        "control_url": control_url,
        "headscale_url": "http://headscale:8080",
        "headscale_api_key_file": "/etc/idoris/headscale.apikey",
        "tenants": [],
    }
if members_hash:
    cfg["tenants"].append({
        "name": tenant,
        "headscale_user_id": user_id,
        "token_hashes": [members_hash],
        "preauth_ttl": "10m",
    })
if ai_hash:
    cfg["tenants"].append({
        "name": tenant + "-local-ai",
        "headscale_user_id": user_id,
        "token_hashes": [ai_hash],
        "acl_tags": ["tag:%s-local-ai" % tenant],
        "preauth_ttl": "10m",
        "rate_per_minute": 5,
    })
json.dump(cfg, sys.stdout, indent=2)
print()
PY
  mv enroll/config.json.tmp enroll/config.json
  echo "wrote enroll/config.json (tenant=$tenant headscale_user_id=$user_id)"
  # The service reads its config at start: restart it if it is already running.
  if [[ -n "$(docker compose ps --status running -q enroll)" ]]; then
    docker compose restart enroll
  fi
else
  echo "enroll/config.json already has '$tenant' and '$tenant-local-ai': nothing to add (no new tokens minted)"
fi

echo "starting all services..."
docker compose up -d --wait --wait-timeout 180

docker compose exec -T enroll idoris-vpn-enroll check --config /etc/idoris/enroll.json

if [[ -n "$members_token" || -n "$ai_token" ]]; then
  echo
  echo "Tenant \"$tenant\" enrollment tokens (hand to the organisation, keep secret):"
  [[ -z "$members_token" ]] || echo "  members          ($tenant):            $members_token"
  [[ -z "$ai_token" ]]      || echo "  Local AI host    ($tenant-local-ai):   $ai_token"
  cat <<MSG

Client config (~/.idoris/vpnd.json) with the token in ~/.idoris/enroll.token:
  members:      {"enroll_url": "https://enroll.example.org", "enroll_token_file": "/Users/me/.idoris/enroll.token"}
  Local AI:     {"enroll_url": "https://enroll.example.org", "enroll_token_file": "/home/me/.idoris/enroll.token", "hostname": "$tenant-local-ai"}
Then:  idoris-vpnd service install --config ~/.idoris/vpnd.json

Always give the Local AI host the tenant-prefixed hostname above: MagicDNS names
are <hostname>.idoris.internal for the whole instance, the tenant is not part of
the name, and a duplicate hostname becomes "<hostname>-1".
MSG
fi
[[ -z "$policy_warning" ]] || { echo; echo "$policy_warning" >&2; }
cat <<MSG

Headplane admin login ($control_url/admin/login) takes a Headscale API key made
for you personally, not the enrollment service key:
  (cd $here && docker compose exec headscale headscale apikeys create --expiration 90d)
MSG
