#!/usr/bin/env bash
# Bootstrap one organisation on the iDoris VPN control plane, or add another.
#
#   bash deploy/vpn/bootstrap.sh init [--org NAME] [--admin NAME]
#       [--lan-cidr CIDR]... [--allow-public-cidr]
#       [--ai-callback-ports PORTS] [--tailnet-admin] [--instance NAME]
#       [--headplane-access tunnel|lan|tailnet|proxy]
#   bash deploy/vpn/bootstrap.sh add-tenant NAME [--lan-cidr CIDR]...
#       [--allow-public-cidr] [--ai-callback-ports PORTS] [--tailnet-admin]
#       [--instance NAME]
#
# init is the default path: one organisation (name "office" if you omit
# --org) plus an admin user (name "admin" if you omit --admin). It creates
# the Headscale users, the enrollment entries, the per-organisation policy
# blocks, checks the policy and reloads Headscale.
#
# add-tenant is the advanced multi-tenant path. Isolation is only as good as
# the policy file. An organisation that needs a harder boundary should run
# its own deploy/vpn stack.
#
# Idempotent. An existing user, API key, cookie secret, enrollment token and
# LAN CIDR is kept. Tokens are printed only when this run mints them.
# Needs: docker with compose v2, python3. No Go toolchain on the host.
set -euo pipefail
umask 077

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

usage() {
  cat <<'EOF'
Usage:
  bash deploy/vpn/bootstrap.sh init [--org NAME] [--admin NAME]
      [--lan-cidr CIDR]... [--allow-public-cidr]
      [--ai-callback-ports PORTS] [--tailnet-admin] [--instance NAME]
      [--headplane-access MODE]
  bash deploy/vpn/bootstrap.sh add-tenant NAME [--lan-cidr CIDR]...
      [--allow-public-cidr] [--ai-callback-ports PORTS] [--tailnet-admin]
      [--instance NAME]

init prepares ONE organisation. The default name is "office" and the default
admin user is "admin". Re-running init is safe.

add-tenant adds another organisation to this same Headscale. That is the
advanced option; the product default is a single organisation.

--lan-cidr CIDR   (repeatable) subnet-router block for that organisation:
                  tag:<org>-gateway, an enrollment entry, autoApprovers for
                  the prefix, and an ACL from <org>@ to the prefix on
                  8740, 8742, 443 and 11434. Overlapping prefixes owned by
                  different organisations are rejected. Private address
                  space only (RFC1918, or IPv6 ULA), unless
                  --allow-public-cidr is also set.

--allow-public-cidr
                  Acknowledge a --lan-cidr that is not private. Prints a
                  warning. Does not allow tailnet, loopback, link-local,
                  multicast, or 169.254.0.0/16. Persisted public prefixes
                  are re-checked on every later run.

--ai-callback-ports PORTS
                  Comma-separated TCP ports (or "none") that this
                  organisation's Local AI host may open towards its own
                  members. Omitted means keep the saved list. Replies to
                  member-initiated connections need no rule. There is no
                  default reverse grant for the AI host or the gateway.

--tailnet-admin   enrollment entry "vpn-server" (tag:vpn-server) for the
                  compose profile tailnet-admin. See docs/14-VPN-OPERATIONS.md.

--headplane-access MODE
                  tunnel (default, SSH to 127.0.0.1), lan (plain HTTP,
                  loud warning), tailnet (compose profile, no host port),
                  or proxy (HTTPS on a hostname that is not server_url).
                  Sets base_url, cookie_secure and HEADPLANE_BIND together.
                  tailnet conflicts with a published mode.

--instance NAME   compose project for this directory. Stored as
                  COMPOSE_PROJECT_NAME in .env (idoris-vpn-NAME unless NAME
                  already starts with idoris-vpn). The default is idoris-vpn.
                  A second copy on the same Docker host must use a different
                  name and different host ports. Refuses a name another
                  directory is already using.

The lines between BEGIN/END markers in headscale/policy.hujson are
regenerated. Hand-written rules outside the markers are kept.
EOF
}

die() { echo "bootstrap: $*" >&2; exit 1; }

# Root's umask 077 files are not readable by uid 65532 until this chown.
# Headplane runs as root in its image and can still read the cookie secret.
chown_enroll_tree() {
  [[ "$(id -u)" == 0 ]] || return 0
  local f
  if [[ -d enroll && ! -L enroll ]]; then
    chown 65532:65532 enroll
    chmod 700 enroll
  fi
  for f in enroll/config.json enroll/headscale.apikey enroll/minted-tokens.txt; do
    if [[ -f "$f" && ! -L "$f" ]]; then
      chown 65532:65532 "$f"
      chmod 600 "$f"
    fi
  done
}
# shellcheck source-path=SCRIPTDIR
# shellcheck source=ops-lib.sh
source "$here/ops-lib.sh"
trap 'echo "bootstrap failed; inspect with: (cd $here && docker compose ps && docker compose logs --tail=50)" >&2' ERR

cmd="${1:-}"
if [[ "$cmd" == "-h" || "$cmd" == "--help" || "$cmd" == "help" ]]; then
  usage
  exit 0
fi
[[ "$cmd" == "init" || "$cmd" == "add-tenant" ]] || {
  usage >&2
  die "expected 'init' or 'add-tenant' (the old 'bootstrap.sh <tenant>' form has been removed)"
}
shift

org=""
admin="admin"
tailnet_admin=0
allow_public_cidr=0
ai_callback_ports=""
ai_callback_set=0
instance=""
headplane_access=""
lan_cidrs=()
if [[ "$cmd" == "add-tenant" && $# -gt 0 && "$1" != --* ]]; then
  org="$1"
  shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org)
      [[ $# -ge 2 ]] || die "--org needs a value"
      org="$2"
      shift 2
      ;;
    --admin)
      [[ "$cmd" == "init" ]] || die "--admin is only valid with init"
      [[ $# -ge 2 ]] || die "--admin needs a value"
      admin="$2"
      shift 2
      ;;
    --lan-cidr)
      [[ $# -ge 2 ]] || die "--lan-cidr needs a value"
      lan_cidrs+=("$2")
      shift 2
      ;;
    --allow-public-cidr)
      allow_public_cidr=1
      shift
      ;;
    --ai-callback-ports)
      [[ $# -ge 2 ]] || die "--ai-callback-ports needs a value (for example 22,8080 or none)"
      ai_callback_ports="$2"
      ai_callback_set=1
      shift 2
      ;;
    --tailnet-admin)
      tailnet_admin=1
      shift
      ;;
    --instance)
      [[ $# -ge 2 ]] || die "--instance needs a value"
      instance="$2"
      shift 2
      ;;
    --headplane-access)
      [[ $# -ge 2 ]] || die "--headplane-access needs tunnel, lan, tailnet or proxy"
      headplane_access="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done
if [[ "$cmd" == "add-tenant" && -z "$org" ]]; then
  die "add-tenant requires an organisation name"
fi

command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v python3 >/dev/null || die "python3 is required"

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

# The enroll image is USER 65532 and must not run as root. A non-root
# operator keeps their own uid so mode 0600 files stay readable. Root is
# rewritten to 65532, and the secret files are chowned before start.
enroll_uid="$(id -u)"
enroll_gid="$(id -g)"
if [[ "$enroll_uid" == 0 ]]; then
  enroll_uid=65532
  enroll_gid=65532
  echo "bootstrap: refusing to run enroll as root; using uid 65532 (the image USER)" >&2
fi
write_env_var ENROLL_UID "$enroll_uid"
write_env_var ENROLL_GID "$enroll_gid"
# Record the compose project before any container is created. A second
# directory on this Docker host must not reuse the name.
assign_instance "$instance"

if [[ ! -s headplane/cookie_secret ]]; then
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > headplane/cookie_secret
  echo "wrote headplane/cookie_secret"
fi
[[ "$(wc -c < headplane/cookie_secret | tr -d ' ')" == 32 ]] || die "headplane/cookie_secret must be exactly 32 bytes"

policy_args=(python3 "$here/policy.py" "$cmd" --policy "$here/headscale/policy.hujson" --state "$here/headscale/managed.json" --admin "$admin")
if [[ -n "$org" ]]; then
  policy_args+=(--org "$org")
fi
if (( tailnet_admin )); then
  policy_args+=(--tailnet-admin)
fi
if (( allow_public_cidr )); then
  policy_args+=(--allow-public-cidr)
fi
if (( ai_callback_set )); then
  policy_args+=(--ai-callback-ports "$ai_callback_ports")
fi
if [[ ${#lan_cidrs[@]} -gt 0 ]]; then
  for cidr in "${lan_cidrs[@]}"; do
    policy_args+=(--lan-cidr "$cidr")
  done
fi

backup="$(mktemp "$here/headscale/policy.hujson.bak.XXXXXX")"
cp headscale/policy.hujson "$backup"
summary="$( "${policy_args[@]}" )" || { rm -f "$backup"; die "policy render failed"; }

# v0.29 `policy check` is a gRPC call to a running server. A one-shot
# container has no socket, so the check runs after Headscale is healthy.
# On failure the previous file is restored and reloaded.
restore_policy() {
  cp "$backup" headscale/policy.hujson
  if [[ -n "$(docker compose ps --status running -q headscale 2>/dev/null || true)" ]]; then
    docker compose kill -s HUP headscale >/dev/null 2>&1 || docker compose restart headscale >/dev/null 2>&1 || true
    sleep 1
  fi
  rm -f "$backup"
}

echo "building enrollment image..."
BUILDX_NO_DEFAULT_ATTESTATIONS=1 docker compose build enroll

echo "starting headscale..."
if ! docker compose up -d --wait --wait-timeout 120 headscale; then
  restore_policy
  docker compose up -d --wait --wait-timeout 120 headscale || true
  die "headscale did not become healthy; restored the previous policy.hujson"
fi

hs() { docker compose exec -T headscale headscale "$@"; }

policy_check() {
  docker compose exec -T headscale headscale policy check -f /etc/headscale/policy.hujson
}

user_id_of() {
  hs users list -o json | python3 -c '
import json, sys
raw = json.load(sys.stdin)
users = raw.get("users", raw) if isinstance(raw, dict) else raw
users = users or []
want = sys.argv[1]
for u in users:
    if u.get("name") == want:
        print(u.get("id", ""))
        break
' "$1"
}

ensure_user() {
  local name id
  name="$1"
  id="$(user_id_of "$name")"
  if [[ -z "$id" ]]; then
    hs users create "$name" >/dev/null
    id="$(user_id_of "$name")"
  fi
  [[ "$id" =~ ^[0-9]+$ ]] || die "could not resolve the Headscale user id of '$name' (got '$id')"
  echo "$id"
}

read_summary() {
  python3 -c '
import json, sys
s = json.loads(sys.argv[1])
print("\t".join(s["admins"]))
print("\t".join(o["name"] for o in s["orgs"]))
for o in s["orgs"]:
    print(o["name"] + "\t" + ",".join(o["lan_cidrs"]))
print("tailnet\t" + ("1" if s["tailnet_admin"] else "0"))
' "$summary"
}

admins=()
org_names=()
declare -a org_cidrs_lines=()
tailnet_flag=0
parsing="admins"
while IFS= read -r line; do
  case "$parsing" in
    admins)
      IFS=$'\t' read -r -a admins <<< "$line"
      parsing="orgs"
      ;;
    orgs)
      if [[ -n "$line" ]]; then
        IFS=$'\t' read -r -a org_names <<< "$line"
      fi
      parsing="cidrs"
      ;;
    cidrs)
      if [[ "$line" == tailnet$'\t'* ]]; then
        tailnet_flag="${line#tailnet$'\t'}"
        parsing="done"
      else
        org_cidrs_lines+=("$line")
      fi
      ;;
  esac
done < <(read_summary)

[[ ${#admins[@]} -gt 0 ]] || die "policy summary has no admin user"
[[ ${#org_names[@]} -gt 0 ]] || die "policy summary has no organisation"

cidrs_of() {
  local want="$1" line name cidrs
  if [[ ${#org_cidrs_lines[@]} -eq 0 ]]; then
    return
  fi
  for line in "${org_cidrs_lines[@]}"; do
    name="${line%%$'\t'*}"
    cidrs="${line#*$'\t'}"
    if [[ "$name" == "$want" ]]; then
      printf '%s' "$cidrs"
      return
    fi
  done
}

declare -a user_names=()
for a in "${admins[@]}"; do
  user_names+=("$a")
done
for o in "${org_names[@]}"; do
  user_names+=("$o")
done

# Create each user once. user_id_of is called again when entries are built;
# bash 3.2 (macOS /bin/bash) has no associative arrays.
for name in "${user_names[@]}"; do
  echo "headscale user '$name' has id $(ensure_user "$name")"
done

# Users named by the policy exist now, so check can resolve them.
if ! policy_check; then
  restore_policy
  die "headscale policy check failed; restored the previous policy.hujson"
fi
rm -f "$backup"
docker compose kill -s HUP headscale >/dev/null
sleep 1
echo "policy checked and reloaded"

if [[ ! -s enroll/headscale.apikey ]]; then
  api_key="$(hs apikeys create --expiration 8760h | tr -d '\r\n')"
  [[ "$api_key" == hskey-api-* ]] || die "unexpected 'apikeys create' output"
  printf '%s' "$api_key" > enroll/headscale.apikey
  echo "wrote enroll/headscale.apikey (expires in 365d; rotate with: ctl.sh apikeys create / expire)"
fi

# Which enrollment entries to have, as name|user|tags|rate|ttl|role
# (tags comma-separated, rate empty = default, role empty = omit).
# role is a field the enroll config already accepts. invite copies it into
# the join code. An empty role makes the code say "member".
wanted=()
for a in "${admins[@]}"; do
  # Personal node of the admin user: no tags, tighter limit, short TTL.
  wanted+=("${a}|$(user_id_of "$a")||5|5m|admin")
done
for o in "${org_names[@]}"; do
  oid="$(user_id_of "$o")"
  wanted+=("${o}|${oid}|||10m|member")
  wanted+=("${o}-local-ai|${oid}|tag:${o}-local-ai|5|10m|local-ai")
  cidrs="$(cidrs_of "$o")"
  if [[ -n "$cidrs" ]]; then
    wanted+=("${o}-gateway|${oid}|tag:${o}-gateway|5|10m|gateway")
  fi
done
if [[ "$tailnet_flag" == "1" ]]; then
  # No join role named vpn-server. The sidecar uses the raw token and acl_tags.
  wanted+=("vpn-server|$(user_id_of "${admins[0]}")|tag:vpn-server|5|10m|")
fi

image="$(docker compose config --format json | python3 -c 'import json, sys; print(json.load(sys.stdin)["services"]["enroll"]["image"])')"
mint() {
  local out tok hash
  out="$(docker run --rm --network none --entrypoint idoris-vpn-enroll "$image" token new)"
  tok="$(grep -oE 'idv1_[0-9a-f]{64}' <<<"$out" | head -n1 || true)"
  hash="$(grep -oE '^[[:space:]]*[0-9a-f]{64}[[:space:]]*$' <<<"$out" | tr -d '[:space:]' | head -n1 || true)"
  [[ -n "$tok" && -n "$hash" ]] || die "could not parse 'idoris-vpn-enroll token new' output"
  printf '%s %s\n' "$tok" "$hash"
}

existing_names=" "
if [[ -e enroll/config.json ]]; then
  existing_names=" $(python3 -c 'import json,sys; print(" ".join(t["name"] for t in json.load(open(sys.argv[1])).get("tenants", [])))' enroll/config.json) "
fi

new_rows=()
printed=()
for spec in "${wanted[@]}"; do
  IFS='|' read -r ename euser etags erate ettl erole <<< "$spec"
  if [[ "$existing_names" == *" $ename "* ]]; then
    continue
  fi
  blabel="bootstrap-${ename}"
  [[ "$blabel" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || die "label '$blabel' is not a valid credential label"
  read -r tok hash < <(mint)
  new_rows+=("${ename}|${euser}|${etags}|${erate}|${ettl}|${hash}|${erole}")
  printed+=("${ename}|${tok}")
done

# Persist plaintext before config rewrite and before compose up. A later
# failure must not be the only copy of a token that already exists as a hash.
if [[ ${#printed[@]} -gt 0 ]]; then
  {
    printf '# minted %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    for row in "${printed[@]}"; do
      printf '%s\t%s\n' "${row%%|*}" "${row#*|}"
    done
  } >> "$here/enroll/minted-tokens.txt"
  chmod 600 "$here/enroll/minted-tokens.txt"
fi

if [[ ${#new_rows[@]} -gt 0 ]]; then
  spec_file="$(mktemp enroll/config.sync.XXXXXX)"
  printf '%s\n' "${new_rows[@]}" > "$spec_file"
  python3 - "$control_url" enroll/config.json "$spec_file" > enroll/config.json.tmp <<'PY'
import datetime, json, os, re, sys
control_url, path, spec_path = sys.argv[1:4]
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
have = {t["name"] for t in cfg.get("tenants", [])}
with open(spec_path) as f:
    for line in f:
        name, user, tags, rate, ttl, digest, role = line.rstrip("\n").split("|")
        if name in have:
            continue
        label = "bootstrap-" + name
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", label):
            raise SystemExit("bootstrap label %r is not a valid credential label" % label)
        created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = {
            "name": name,
            "headscale_user_id": user,
            "token_hashes": [{
                "hash": digest,
                "label": label,
                "created_at": created,
            }],
            "preauth_ttl": ttl or "10m",
        }
        if role:
            entry["role"] = role
        if tags:
            entry["acl_tags"] = tags.split(",")
        if rate:
            entry["rate_per_minute"] = int(rate)
        cfg["tenants"].append(entry)
json.dump(cfg, sys.stdout, indent=2)
print()
PY
  mv enroll/config.json.tmp enroll/config.json
  rm -f "$spec_file"
  echo "wrote enroll/config.json"
  if [[ -n "$(docker compose ps --status running -q enroll)" ]]; then
    docker compose restart enroll >/dev/null
  fi
else
  echo "enrollment entries already present; no new tokens minted"
fi

if [[ ${#printed[@]} -gt 0 ]]; then
  for row in "${printed[@]}"; do
    if [[ "${row%%|*}" == "vpn-server" ]]; then
      export VPN_SERVER_ENROLL_TOKEN="${row#*|}"
    fi
  done
fi
if [[ -n "$headplane_access" && "$headplane_access" != "tunnel" && "$headplane_access" != "lan" && "$headplane_access" != "tailnet" && "$headplane_access" != "proxy" ]]; then
  die "--headplane-access must be tunnel, lan, tailnet or proxy"
fi
if (( tailnet_admin )) && [[ -n "$headplane_access" && "$headplane_access" != "tailnet" ]]; then
  die "--tailnet-admin cannot be combined with --headplane-access $headplane_access"
fi
if (( tailnet_admin )) && [[ -z "$headplane_access" ]]; then
  headplane_access="tailnet"
fi
if [[ -z "$headplane_access" && -f "$here/.env" ]]; then
  headplane_access="$(sed -n 's/^HEADPLANE_ACCESS=//p' "$here/.env" | head -n1 | tr -d '[:space:]')"
fi
headplane_access="${headplane_access:-tunnel}"
apply_headplane_access "$headplane_access"
chown_enroll_tree
echo "starting services for admin mode $(read_admin_mode)..."
start_stack_for_mode "$(read_admin_mode)"
docker compose exec -T enroll idoris-vpn-enroll check --config /etc/idoris/enroll.json

if [[ ${#printed[@]} -gt 0 ]]; then
  echo
  echo "Enrollment tokens minted by this run (also in enroll/minted-tokens.txt, mode 0600):"
  echo "Delete that file after the tokens are stored somewhere else."
  for row in "${printed[@]}"; do
    echo "  ${row%%|*}: label bootstrap-${row%%|*}"
    echo "  ${row%%|*}: ${row#*|}"
  done
  cat <<EOF

Member or admin client (~/.idoris/vpnd.json), token in the enroll_token_file:
  {"enroll_url": "https://enroll.example.org", "enroll_token_file": "/home/me/.idoris/enroll.token"}
Then:  idoris-vpnd service install --config ~/.idoris/vpnd.json
An admin uses the same client and the same command, with the admin token.
The admin device is a personal node of the admin user (no tags).

Local AI host: use the <org>-local-ai token and a prefixed hostname, e.g.
  {"enroll_url": "https://enroll.example.org", "enroll_token_file": "/home/me/.idoris/enroll.token", "hostname": "${org_names[0]}-local-ai"}
MagicDNS is <hostname>.idoris.internal with no organisation in the name.

EOF
  if printf '%s\n' "${printed[@]}" | grep -q -- '-gateway|'; then
    cat <<'EOF'
Gateway token: enroll that Linux host in system mode and set advertise_routes
to the CIDR you passed (see docs/14). Embedded mode rejects that field.
On the host, also:  sudo sysctl -w net.ipv4.ip_forward=1
Manual alternative after enroll:  sudo tailscale set --advertise-routes=<CIDR>

EOF
  fi
elif [[ -s "$here/enroll/minted-tokens.txt" ]]; then
  echo
  echo "No new tokens. Plaintext from the last mint is still in enroll/minted-tokens.txt:"
  cat "$here/enroll/minted-tokens.txt"
fi

cat <<EOF
Headplane ($control_url/admin/login) takes a Headscale API key of your own,
not the enrollment service key:
  bash $here/ctl.sh apikeys create --expiration 90d
Operate the stack with:  bash $here/ctl.sh help
EOF
