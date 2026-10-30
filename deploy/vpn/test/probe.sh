#!/usr/bin/env bash
# Two-organisation isolation probe against the deploy/vpn stack.
#
# Brings Headscale up on a unique compose project and ephemeral ports, enrolls
# real tailscale containers (kernel TUN) for two organisations plus an admin,
# and checks the allow/deny matrix. Also checks subnet-route auto-approval
# and, when the profile comes up, that only the admin can open Headplane on
# the tailnet. Tears the stack down, including volumes.
#
# Lab only: server_url is http://headscale:8080 and embedded DERP is off, so
# this does not exercise the production https:443 re-dial. See docs/14.
#
# Usage: bash deploy/vpn/test/probe.sh
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
lab="$root/test/.lab"

die() { echo "probe: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v python3 >/dev/null || die "python3 is required"

PROJ="idoris-vpn-ctl-$(python3 -c 'import random; print(random.randint(100000, 999999))')"
export COMPOSE_PROJECT_NAME="$PROJ"
ENROLL_UID="$(id -u)"
ENROLL_GID="$(id -g)"
export ENROLL_UID ENROLL_GID
LAN_CIDR="10.88.88.0/24"
LAN_IP="10.88.88.10"
cookie_created=0

free_port() {
  python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
free_udp() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

HEADSCALE_PORT="$(free_port)"
HEADPLANE_PORT="$(free_port)"
ENROLL_PORT="$(free_port)"
DERP_STUN_PORT="$(free_udp)"
export HEADSCALE_PORT HEADPLANE_PORT ENROLL_PORT DERP_STUN_PORT

dc() { docker compose -f "$root/compose.yaml" -f "$lab/override.yaml" "$@"; }

# Copy a lab secret into the deploy tree only when that path is empty.
# Cleanup deletes paths recorded in staged-files.
stage_secret() {
  local dest="$1" src="$2"
  if [[ -e "$dest" || -L "$dest" ]]; then
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
  chmod 600 "$dest"
  printf '%s\n' "$dest" >> "$lab/staged-files"
}

# Re-copy a file this probe created. A credential test rewrites the lab
# config after the first copy; backup must see that later file.
refresh_staged() {
  local dest="$1" src="$2"
  [[ -f "$lab/staged-files" ]] || return 0
  if grep -qxF "$dest" "$lab/staged-files"; then
    cp "$src" "$dest"
    chmod 600 "$dest"
  fi
}

cleanup() {
  local ec=$?
  echo "probe: tearing down project ${PROJ} (exit ${ec})"
  if [[ "$ec" -ne 0 ]]; then
    dc logs --tail 40 | sed -E 's/hskey-[A-Za-z0-9_.:+/=-]+/[redacted]/g; s/idv1_[0-9a-f]+/[redacted]/g' >&2 || true
    docker ps -aq --filter "label=idoris-vpn-probe=${PROJ}" | while read -r id; do
      echo "---- logs $id ----" >&2
      docker logs --tail 30 "$id" | sed -E 's/hskey-[A-Za-z0-9_.:+/=-]+/[redacted]/g; s/idv1_[0-9a-f]+/[redacted]/g' >&2 || true
    done
  fi
  docker ps -aq --filter "label=idoris-vpn-probe=${PROJ}" | while read -r id; do
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
  docker network rm "${PROJ}-lan" >/dev/null 2>&1 || true
  dc --profile tailnet-admin down -v >/dev/null 2>&1 || true
  if [[ -f "$lab/staged-files" ]]; then
    while IFS= read -r staged; do
      [[ -n "$staged" ]] || continue
      rm -f "$staged"
    done < "$lab/staged-files"
  fi
  if [[ -f "$lab/file-modes" ]]; then
    python3 - "$lab/file-modes" <<'PY' || true
import os, sys
for line in open(sys.argv[1]):
    mode, path = line.split(" ", 1)
    path = path.rstrip("\n")
    if os.path.isfile(path) and not os.path.islink(path):
        os.chmod(path, int(mode, 8))
PY
  fi
  rm -rf "$lab"
  if [[ "$cookie_created" == 1 ]]; then
    rm -f "$root/headplane/cookie_secret"
  fi
  rm -f "$root/.admin-mode" "$root/.admin-mode."* "$root/.running."*
  exit "$ec"
}
trap cleanup EXIT

rm -rf "$lab"
mkdir -p "$lab"

if [[ ! -s "$root/headplane/cookie_secret" ]]; then
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > "$root/headplane/cookie_secret"
  cookie_created=1
fi

python3 - "$root/headscale/config.yaml" "$lab/config.yaml" <<'PY'
import sys
src, dst = sys.argv[1:]
text = open(src).read()
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
open(dst, "w").write(text)
PY

cp "$root/headscale/policy.hujson" "$lab/policy.hujson"
python3 "$root/policy.py" init \
  --policy "$lab/policy.hujson" --state "$lab/managed.json" \
  --org acme --admin admin --tailnet-admin --lan-cidr "$LAN_CIDR" >/dev/null
python3 "$root/policy.py" add-tenant \
  --policy "$lab/policy.hujson" --state "$lab/managed.json" \
  --org globex >/dev/null

# Placeholder enroll files so compose can create the container later.
# credentials.sh and ctl.sh share this directory with the running service.
mkdir -p "$lab/enroll-home"
printf '%s\n' '{"control_url":"http://headscale:8080","headscale_url":"http://headscale:8080","headscale_api_key_file":"/etc/idoris/headscale.apikey","tenants":[{"name":"placeholder","headscale_user_id":"1","token_hashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}]}' > "$lab/enroll-home/config.json"
printf '%s' 'placeholder' > "$lab/enroll-home/headscale.apikey"
chmod 600 "$lab/enroll-home/config.json" "$lab/enroll-home/headscale.apikey"

cat > "$lab/override.yaml" <<'EOF'
services:
  headscale:
    volumes: !override
      - ./test/.lab/config.yaml:/etc/headscale/config.yaml:ro
      - ./test/.lab/policy.hujson:/etc/headscale/policy.hujson:ro
      - headscale-data:/var/lib/headscale
      - headscale-run:/var/run/headscale
  enroll:
    volumes: !override
      - ./test/.lab/enroll-home/config.json:/etc/idoris/enroll.json:ro
      - ./test/.lab/enroll-home/headscale.apikey:/etc/idoris/headscale.apikey:ro
EOF

echo "probe: project=${PROJ} headscale=${HEADSCALE_PORT} enroll=${ENROLL_PORT} stun=${DERP_STUN_PORT}"
dc config -q
merged="$(dc config)"
grep -q 'test/.lab/config.yaml' <<<"$merged" || die "lab headscale config was not mounted"
grep -q 'server_url: http://headscale:8080' "$lab/config.yaml" || die "lab server_url was not rewritten"

echo "probe: building enroll image"
BUILDX_NO_DEFAULT_ATTESTATIONS=1 dc build enroll

echo "probe: starting headscale"
dc up -d --wait --wait-timeout 120 headscale

for user in admin acme globex; do
  dc exec -T headscale headscale users create "$user" >/dev/null
done
# policy check resolves user references against the live database.
dc exec -T headscale headscale policy check -f /etc/headscale/policy.hujson
dc kill -s HUP headscale >/dev/null
sleep 1

python3 -c '
import json, sys
raw = json.load(sys.stdin)
users = raw.get("users", raw) if isinstance(raw, dict) else raw
want = {"admin", "acme", "globex"}
got = {u["name"]: str(u["id"]) for u in users}
missing = want - set(got)
if missing:
    raise SystemExit("missing users: %s" % ",".join(sorted(missing)))
for name in ("admin", "acme", "globex"):
    print("%s %s" % (name, got[name]))
' > "$lab/users.txt" < <(dc exec -T headscale headscale users list -o json)

api_key="$(dc exec -T headscale headscale apikeys create --expiration 24h | tr -d '\r\n')"
[[ "$api_key" == hskey-api-* ]] || die "apikeys create did not return an API key"
printf '%s' "$api_key" > "$lab/enroll-home/headscale.apikey"
chmod 600 "$lab/enroll-home/headscale.apikey"
unset api_key

image="$(dc config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["enroll"]["image"])')"
mint() {
  local out tok hash
  out="$(docker run --rm --network none --entrypoint idoris-vpn-enroll "$image" token new)"
  tok="$(grep -oE 'idv1_[0-9a-f]{64}' <<<"$out" | head -n1 || true)"
  hash="$(grep -oE '^[[:space:]]*[0-9a-f]{64}[[:space:]]*$' <<<"$out" | tr -d '[:space:]' | head -n1 || true)"
  [[ -n "$tok" && -n "$hash" ]] || die "could not parse token new"
  printf '%s %s\n' "$tok" "$hash"
}

# name user tags rate ttl
entries=(
  "admin|admin||5|5m"
  "acme|acme|||10m"
  "acme-local-ai|acme|tag:acme-local-ai|5|10m"
  "acme-gateway|acme|tag:acme-gateway|5|10m"
  "globex|globex|||10m"
  "globex-local-ai|globex|tag:globex-local-ai|5|10m"
  "vpn-server|admin|tag:vpn-server|5|10m"
)
: > "$lab/tokens.tsv"
for spec in "${entries[@]}"; do
  IFS='|' read -r ename euser etags erate ettl <<< "$spec"
  read -r tok hash < <(mint)
  printf '%s\t%s\n' "$ename" "$tok" >> "$lab/tokens.tsv"
  printf '%s\n' "${ename}|${euser}|${etags}|${erate}|${ettl}|${hash}" >> "$lab/enroll.spec"
done

python3 - "$lab/users.txt" "$lab/enroll.spec" "$lab/enroll-home/config.json" <<'PY'
import json, sys
users = {}
for line in open(sys.argv[1]):
    name, uid = line.split()
    users[name] = uid
cfg = {
    "control_url": "http://headscale:8080",
    "headscale_url": "http://headscale:8080",
    "headscale_api_key_file": "/etc/idoris/headscale.apikey",
    "tenants": [],
}
for line in open(sys.argv[2]):
    name, user, tags, rate, ttl, digest = line.rstrip("\n").split("|")
    entry = {
        "name": name,
        "headscale_user_id": users[user],
        "token_hashes": [digest],
        "preauth_ttl": ttl,
    }
    if tags:
        entry["acl_tags"] = tags.split(",")
    if rate:
        entry["rate_per_minute"] = int(rate)
    cfg["tenants"].append(entry)
with open(sys.argv[3], "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
rm -f "$lab/enroll.spec"

echo "probe: starting enroll"
dc up -d --wait --wait-timeout 180 enroll
dc exec -T enroll idoris-vpn-enroll check --config /etc/idoris/enroll.json

token_of() {
  awk -F '\t' -v n="$1" '$1==n {print $2}' "$lab/tokens.tsv"
}

enroll_key() {
  local name="$1" hostname="$2" token
  token="$(token_of "$name")"
  [[ -n "$token" ]] || die "no token for $name"
  python3 - "$token" "$hostname" "http://127.0.0.1:${ENROLL_PORT}/v1/enroll" <<'PY'
import json, sys, urllib.request
token, hostname, url = sys.argv[1:]
body = json.dumps({"hostname": hostname, "os": "linux"}).encode()
req = urllib.request.Request(url, data=body, headers={
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json",
})
with urllib.request.urlopen(req, timeout=20) as resp:
    data = json.load(resp)
key = data.get("auth_key") or ""
if not key.startswith("hskey-auth-"):
    raise SystemExit("enroll for %s did not return an auth key" % hostname)
sys.stdout.write(key)
PY
}

net_name() {
  local cid
  cid="$(dc ps -q headscale)"
  docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$cid" | head -n1
}

echo "probe: joining tailnet nodes"
NET="$(net_name)"
[[ -n "$NET" ]] || die "could not find the compose network"

start_node() {
  local cname="$1" key="$2" hostname="$3" routes="$4" extra="$5" sysctl="$6"
  local ts_extra="--login-server=http://headscale:8080"
  # containerboot already turns TS_HOSTNAME and TS_ACCEPT_DNS into flags.
  # A second --hostname / --accept-dns makes `tailscale up` exit 2.
  if [[ -n "$extra" ]]; then
    ts_extra="${ts_extra} ${extra}"
  fi
  local -a args
  args=(docker run -d --name "$cname"
    --label "idoris-vpn-probe=${PROJ}"
    --cap-add NET_ADMIN --cap-add NET_RAW
    --device /dev/net/tun:/dev/net/tun
    --network "$NET"
    -e "TS_AUTHKEY=${key}"
    -e TS_AUTH_ONCE=true
    -e TS_USERSPACE=false
    -e TS_STATE_DIR=/var/lib/tailscale
    -e "TS_HOSTNAME=${hostname}"
    -e TS_ACCEPT_DNS=false
    -e "TS_EXTRA_ARGS=${ts_extra}"
    --entrypoint /usr/local/bin/containerboot)
  if [[ -n "$routes" ]]; then
    args+=(-e "TS_ROUTES=${routes}")
  fi
  if [[ -n "$sysctl" ]]; then
    args+=(--sysctl "$sysctl")
  fi
  args+=(tailscale/tailscale:v1.104.2)
  "${args[@]}" >/dev/null
}

# hostname -> container name
declare -a NODES=(
  "acme-member|acme|acme-member||--accept-routes|"
  "acme-ai|acme-local-ai|acme-local-ai|||"
  "globex-member|globex|globex-member||--accept-routes|"
  "globex-ai|globex-local-ai|globex-local-ai|||"
  "admin-node|admin|admin-node|||"
  "acme-gateway|acme-gateway|acme-gateway|${LAN_CIDR}||net.ipv4.ip_forward=1"
)

for spec in "${NODES[@]}"; do
  IFS='|' read -r host entry hostname routes extra sysctl <<< "$spec"
  key="$(enroll_key "$entry" "$hostname")"
  start_node "${PROJ}-${host}" "$key" "$hostname" "$routes" "$extra" "$sysctl"
  unset key
done

echo "probe: waiting for nodes"
running_count() {
  local host cname n=0
  for spec in "${NODES[@]}"; do
    host="${spec%%|*}"
    cname="${PROJ}-${host}"
    if docker exec "$cname" tailscale status --json 2>/dev/null | python3 -c 'import json,sys
try:
    s=json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if s.get("BackendState")=="Running" else 1)'; then
      n=$((n + 1))
    fi
  done
  printf '%s' "$n"
}

ok_nodes=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  ok_nodes="$(running_count || true)"
  echo "probe: ${ok_nodes}/${#NODES[@]} running"
  [[ "$ok_nodes" == "${#NODES[@]}" ]] && break
  sleep 3
done
[[ "$ok_nodes" == "${#NODES[@]}" ]] || die "tailscale nodes did not reach Running"

nodes_json="$(dc exec -T headscale headscale nodes list -o json)"
for tag in tag:acme-local-ai tag:globex-local-ai tag:acme-gateway; do
  grep -q "$tag" <<<"$nodes_json" || die "headscale did not record $tag on a node"
done

listen_on() {
  local cname="$1"
  docker exec -d "$cname" /bin/sh -c 'for p in 22 443 3000 8080 8740 8742 11434; do nc -lk -p "$p" -e /bin/cat & done; wait'
}

for spec in "${NODES[@]}"; do
  host="${spec%%|*}"
  # The gateway's listeners are on its tailnet address; the LAN box is separate.
  listen_on "${PROJ}-${host}"
done

# Confirm a listener is actually accepting on loopback before blaming the ACL.
sleep 1
docker exec "${PROJ}-acme-ai" nc -z -w 2 127.0.0.1 8740 || die "nc listener did not bind inside acme-ai"

ip_of() {
  docker exec "${PROJ}-$1" tailscale ip -4 | head -n1 | tr -d '\r'
}

pass=0
fail=0
report() {
  local src="$1" dst="$2" port="$3" expect="$4" result="$5"
  if [[ "$result" == ok ]]; then
    pass=$((pass + 1))
    printf '  ok   %s -> %s:%s %s\n' "$src" "$dst" "$port" "$expect"
  else
    fail=$((fail + 1))
    printf '  FAIL %s -> %s:%s expected %s\n' "$src" "$dst" "$port" "$expect" >&2
  fi
}

try_tcp() {
  local src="$1" ip="$2" port="$3"
  local out
  out="$(docker exec "${PROJ}-${src}" /bin/sh -c "printf 'ping\n' | nc -w 2 -n ${ip} ${port}" 2>/dev/null || true)"
  [[ "$out" == *ping* ]]
}

# src dst port expect
MATRIX=(
  "acme-member acme-ai 8740 allow"
  "acme-member acme-ai 8742 allow"
  "acme-member acme-ai 443 allow"
  "acme-member acme-ai 8080 deny"
  "acme-member acme-ai 22 deny"
  "acme-member globex-ai 8740 deny"
  "acme-member globex-ai 8742 deny"
  "acme-member globex-ai 443 deny"
  "acme-member globex-ai 22 deny"
  "acme-member globex-member 22 deny"
  "acme-member globex-member 8740 deny"
  "acme-member admin-node 22 deny"
  "globex-member globex-ai 8740 allow"
  "globex-member globex-ai 8742 allow"
  "globex-member globex-ai 443 allow"
  "globex-member globex-ai 8080 deny"
  "globex-member globex-ai 22 deny"
  "globex-member acme-ai 8740 deny"
  "globex-member acme-ai 443 deny"
  "globex-member acme-ai 22 deny"
  "globex-member acme-member 22 deny"
  "globex-member acme-member 8740 deny"
  "acme-ai acme-member 22 deny"
  "acme-ai acme-member 8740 deny"
  "acme-ai globex-member 22 deny"
  "acme-ai globex-ai 8740 deny"
  "globex-ai globex-member 22 deny"
  "globex-ai globex-member 8740 deny"
  "globex-ai acme-member 22 deny"
  "globex-ai acme-ai 8740 deny"
  "admin-node acme-ai 22 allow"
  "admin-node acme-ai 8740 deny"
  "admin-node acme-ai 8080 deny"
  "admin-node acme-ai 443 deny"
  "admin-node globex-ai 22 allow"
  "admin-node globex-ai 8740 deny"
  "admin-node acme-member 22 deny"
  "admin-node globex-member 22 deny"
)

echo "probe: isolation matrix (${#MATRIX[@]} probes)"
for row in "${MATRIX[@]}"; do
  read -r src dst port expect <<< "$row"
  ip="$(ip_of "$dst")"
  if [[ "$expect" == allow ]]; then
    got=0
    for _ in 1 2 3 4 5; do
      if try_tcp "$src" "$ip" "$port"; then
        got=1
        break
      fi
      sleep 2
    done
    if [[ "$got" == 1 ]]; then
      report "$src" "$dst" "$port" allow ok
    else
      report "$src" "$dst" "$port" allow bad
    fi
  else
    if try_tcp "$src" "$ip" "$port"; then
      report "$src" "$dst" "$port" deny bad
    else
      report "$src" "$dst" "$port" deny ok
    fi
  fi
done

echo "probe: subnet route auto-approval"
approved=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if dc exec -T headscale headscale nodes list-routes -o json | python3 -c '
import json, sys
cidr = sys.argv[1]
data = json.load(sys.stdin)
hits = []
def walk(o):
    if isinstance(o, dict):
        approved = []
        for k, v in o.items():
            if "approv" in k.lower():
                approved.append(v)
            else:
                walk(v)
        blob = " ".join(str(x) for x in approved)
        if cidr in blob:
            hits.append(str(o.get("name") or o.get("hostname") or o.get("given_name") or o.get("givenName") or "?"))
    elif isinstance(o, list):
        for i in o:
            walk(i)
walk(data)
sys.stderr.write("approved-on: %s\n" % ",".join(hits))
raise SystemExit(0 if hits else 1)
' "$LAN_CIDR"; then
    approved=1
    break
  fi
  sleep 3
done
if [[ "$approved" == 1 ]]; then
  pass=$((pass + 1))
  echo "  ok   autoApprovers approved ${LAN_CIDR} for the gateway tag"
else
  fail=$((fail + 1))
  echo "  FAIL autoApprovers did not approve ${LAN_CIDR}" >&2
  dc exec -T headscale headscale nodes list-routes >&2 || true
fi

echo "probe: LAN data plane via the gateway"
# The office LAN is a second Docker network. Docker Desktop will also route
# that subnet between bridges, which is not the tailnet. The box therefore
# accepts TCP only from the gateway's address on this network (Tailscale
# subnet-router SNAT). Headscale must not install the route on globex at all.
docker network create --subnet "$LAN_CIDR" "${PROJ}-lan" >/dev/null
docker run -d --name "${PROJ}-lanbox" \
  --label "idoris-vpn-probe=${PROJ}" \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --network "${PROJ}-lan" --ip "$LAN_IP" \
  --entrypoint /bin/sh \
  tailscale/tailscale:v1.104.2 \
  -c 'nc -lk -p 8740 -e /bin/cat & nc -lk -p 22 -e /bin/cat & wait' >/dev/null
docker network connect "${PROJ}-lan" "${PROJ}-acme-gateway"
gw_lan="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJ}-lan\").IPAddress}}" "${PROJ}-acme-gateway")"
[[ -n "$gw_lan" ]] || die "gateway has no address on the lab LAN"
docker exec "${PROJ}-lanbox" iptables -P INPUT DROP
docker exec "${PROJ}-lanbox" iptables -A INPUT -i lo -j ACCEPT
docker exec "${PROJ}-lanbox" iptables -A INPUT -s "$gw_lan" -j ACCEPT

acme_route="$(docker exec "${PROJ}-acme-member" ip route get "$LAN_IP" || true)"
globex_route="$(docker exec "${PROJ}-globex-member" ip route get "$LAN_IP" || true)"
if [[ "$acme_route" == *tailscale0* ]]; then
  pass=$((pass + 1))
  echo "  ok   acme-member route to ${LAN_IP} is via tailscale0"
else
  fail=$((fail + 1))
  echo "  FAIL acme-member route to ${LAN_IP} is not via tailscale0 (${acme_route})" >&2
fi
if [[ "$globex_route" == *tailscale0* ]]; then
  fail=$((fail + 1))
  echo "  FAIL globex-member was given acme's LAN route (${globex_route})" >&2
else
  pass=$((pass + 1))
  echo "  ok   globex-member has no tailscale route to ${LAN_IP}"
fi

lan_ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if try_tcp acme-member "$LAN_IP" 8740; then
    lan_ok=1
    break
  fi
  sleep 3
done
if [[ "$lan_ok" == 1 ]]; then
  pass=$((pass + 1))
  echo "  ok   acme-member -> ${LAN_IP}:8740 allow"
else
  fail=$((fail + 1))
  echo "  FAIL acme-member -> ${LAN_IP}:8740 expected allow" >&2
fi
if try_tcp acme-member "$LAN_IP" 22; then
  fail=$((fail + 1))
  echo "  FAIL acme-member -> ${LAN_IP}:22 expected deny" >&2
else
  pass=$((pass + 1))
  echo "  ok   acme-member -> ${LAN_IP}:22 deny"
fi
if try_tcp globex-member "$LAN_IP" 8740; then
  fail=$((fail + 1))
  echo "  FAIL globex-member -> ${LAN_IP}:8740 expected deny" >&2
else
  pass=$((pass + 1))
  echo "  ok   globex-member -> ${LAN_IP}:8740 deny"
fi

echo "probe: tailnet-admin profile"
vpn_token="$(token_of vpn-server)"
export VPN_SERVER_ENROLL_TOKEN="$vpn_token"
dc --profile tailnet-admin up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet
unset VPN_SERVER_ENROLL_TOKEN

vip=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  vip="$(dc exec -T vpn-sidecar tailscale ip -4 2>/dev/null | head -n1 | tr -d '\r' || true)"
  [[ -n "$vip" ]] && break
  sleep 3
done
[[ -n "$vip" ]] || die "vpn-sidecar has no tailnet IPv4"

http_ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  body="$(docker exec "${PROJ}-admin-node" /bin/sh -c "printf 'GET /admin HTTP/1.0\r\nHost: vpn-server\r\n\r\n' | nc -w 3 -n ${vip} 3000" 2>/dev/null || true)"
  if [[ "$body" == *HTTP/* ]]; then
    http_ok=1
    break
  fi
  sleep 3
done
if [[ "$http_ok" == 1 ]]; then
  pass=$((pass + 1))
  echo "  ok   admin-node fetched Headplane on ${vip}:3000"
else
  fail=$((fail + 1))
  echo "  FAIL admin-node could not fetch Headplane on ${vip}:3000" >&2
fi
member_body="$(docker exec "${PROJ}-acme-member" /bin/sh -c "printf 'GET /admin HTTP/1.0\r\nHost: vpn-server\r\n\r\n' | nc -w 3 -n ${vip} 3000" 2>/dev/null || true)"
if [[ "$member_body" == *HTTP/* ]]; then
  fail=$((fail + 1))
  echo "  FAIL acme-member reached Headplane on the tailnet" >&2
else
  pass=$((pass + 1))
  echo "  ok   acme-member denied Headplane on ${vip}:3000"
fi
globex_body="$(docker exec "${PROJ}-globex-member" /bin/sh -c "printf 'GET /admin HTTP/1.0\r\nHost: vpn-server\r\n\r\n' | nc -w 3 -n ${vip} 3000" 2>/dev/null || true)"
if [[ "$globex_body" == *HTTP/* ]]; then
  fail=$((fail + 1))
  echo "  FAIL globex-member reached Headplane on the tailnet" >&2
else
  pass=$((pass + 1))
  echo "  ok   globex-member denied Headplane on ${vip}:3000"
fi

echo "probe: credential lifecycle"
# compose run (ctl.sh) also bind-mounts deploy/vpn/enroll/*. Those files have
# to exist. The credential commands write ENROLL_DIR, which is the file the
# running enroll process reloads.
stage_secret "$root/enroll/config.json" "$lab/enroll-home/config.json"
stage_secret "$root/enroll/headscale.apikey" "$lab/enroll-home/headscale.apikey"
if ENROLL_DIR="$lab/enroll-home" PROJ="$PROJ" bash "$root/test/credentials.sh"; then
  pass=$((pass + 1))
  echo "  ok   credential lifecycle"
else
  fail=$((fail + 1))
  echo "  FAIL credential lifecycle" >&2
fi

echo "probe: backup/restore keeps the published Headplane stopped"
printf 'mode=tailnet-admin\n' > "$root/.admin-mode"
chmod 600 "$root/.admin-mode"
# ctl.sh backup reads host files. The lab keeps the live copies under test/.lab
# so a developer tree without secrets can still take the bundle. Only paths
# this probe created are deleted on the way out.
if [[ ! -e "$root/.env" && ! -L "$root/.env" ]]; then
  cat > "$root/.env" <<EOF
COMPOSE_PROJECT_NAME=${PROJ}
ENROLL_UID=${ENROLL_UID}
ENROLL_GID=${ENROLL_GID}
HEADSCALE_PORT=${HEADSCALE_PORT}
HEADPLANE_PORT=${HEADPLANE_PORT}
ENROLL_PORT=${ENROLL_PORT}
DERP_STUN_PORT=${DERP_STUN_PORT}
EOF
  chmod 600 "$root/.env"
  printf '%s\n' "$root/.env" >> "$lab/staged-files"
fi
refresh_staged "$root/enroll/config.json" "$lab/enroll-home/config.json"
refresh_staged "$root/enroll/headscale.apikey" "$lab/enroll-home/headscale.apikey"
stage_secret "$root/enroll/config.json" "$lab/enroll-home/config.json"
stage_secret "$root/enroll/headscale.apikey" "$lab/enroll-home/headscale.apikey"
stage_secret "$root/headscale/managed.json" "$lab/managed.json"
python3 - "$lab/file-modes" \
  "$root/headscale/config.yaml" "$root/headscale/policy.hujson" \
  "$root/headplane/config.yaml" "$root/compose.yaml" <<'PY'
import os, sys
out = sys.argv[1]
with open(out, "w") as fh:
    for path in sys.argv[2:]:
        fh.write("%o %s\n" % (os.stat(path).st_mode & 0o777, path))
PY
bash "$root/ctl.sh" backup "$lab/mode-backup"
[[ -f "$lab/mode-backup/state/enroll/config.json" ]] || die "backup missed enroll config"
[[ -f "$lab/mode-backup/state/dotenv" ]] || die "backup missed .env"
[[ -f "$lab/mode-backup/manifest.json" ]] || die "backup missed manifest"
if grep -qE 'idv1_|hskey-|ENROLL_TOKEN' "$lab/mode-backup/manifest.json"; then
  die "backup manifest contains a secret"
fi
pub_running="$(docker compose --project-name "$PROJ" ps --status running -q headplane || true)"
tail_running="$(docker compose --project-name "$PROJ" --profile tailnet-admin ps --status running -q headplane-tailnet || true)"
if [[ -z "$pub_running" && -n "$tail_running" ]]; then
  pass=$((pass + 1))
  echo "  ok   after backup, published headplane is stopped and headplane-tailnet is running"
else
  fail=$((fail + 1))
  echo "  FAIL after backup published='$pub_running' tailnet='$tail_running'" >&2
fi
if python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(1)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)
sys.exit(1)' "$HEADPLANE_PORT"; then
  pass=$((pass + 1))
  echo "  ok   after backup, 127.0.0.1:${HEADPLANE_PORT} is closed"
else
  fail=$((fail + 1))
  echo "  FAIL after backup, 127.0.0.1:${HEADPLANE_PORT} accepted a connection" >&2
fi
bash "$root/ctl.sh" restore "$lab/mode-backup" --force
pub_running="$(docker compose --project-name "$PROJ" ps --status running -q headplane || true)"
tail_running="$(docker compose --project-name "$PROJ" --profile tailnet-admin ps --status running -q headplane-tailnet || true)"
if [[ -z "$pub_running" && -n "$tail_running" ]]; then
  pass=$((pass + 1))
  echo "  ok   after restore, published headplane is stopped and headplane-tailnet is running"
else
  fail=$((fail + 1))
  echo "  FAIL after restore published='$pub_running' tailnet='$tail_running'" >&2
fi
if python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(1)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)
sys.exit(1)' "$HEADPLANE_PORT"; then
  pass=$((pass + 1))
  echo "  ok   after restore, 127.0.0.1:${HEADPLANE_PORT} is closed"
else
  fail=$((fail + 1))
  echo "  FAIL after restore, 127.0.0.1:${HEADPLANE_PORT} accepted a connection" >&2
fi
rm -f "$root/.admin-mode"

echo "probe: ${pass} passed, ${fail} failed"
[[ "$fail" == 0 ]] || die "${fail} probe(s) failed"
echo "probe: ok"
