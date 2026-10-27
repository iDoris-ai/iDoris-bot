#!/usr/bin/env bash
# --headplane-access tailnet is one decision, made before policy or tokens.
# Docker is a stub so this can prove call order without starting Headscale.
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$root/../.." && pwd)"
src="$repo/deploy/.flag-src"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/idoris-flags.XXXXXX")"
cleanup() {
  rm -rf "$src" "$tmp"
}
trap cleanup EXIT

rm -rf "$src"
mkdir -p "$src"
rsync -a \
  --exclude 'test/.lab/' \
  --exclude 'backups/' \
  --exclude '.env' \
  --exclude '.admin-mode' \
  --exclude 'enroll/config.json' \
  --exclude 'enroll/headscale.apikey' \
  --exclude 'enroll/minted-tokens.txt' \
  --exclude 'headplane/cookie_secret' \
  --exclude 'headscale/managed.json' \
  "$root/" "$src/"

python3 - "$src/headscale/config.yaml" "$src/headplane/config.yaml" <<'PY'
import sys
for path in sys.argv[1:]:
    text = open(path).read().replace("vpn.example.org", "flags.example.test")
    if "vpn.example.org" in text:
        raise SystemExit("placeholder remains in %s" % path)
    open(path, "w").write(text)
PY

cat > "$src/.env" <<'EOF'
COMPOSE_PROJECT_NAME=idoris-vpn-r2d-flags
ENROLL_UID=65532
ENROLL_GID=65532
HEADSCALE_PORT=18080
HEADPLANE_PORT=13000
ENROLL_PORT=18787
DERP_STUN_PORT=13478
HEADPLANE_BIND=127.0.0.1
EOF
chmod 600 "$src/.env"

mkdir -p "$tmp/bin"
export DOCKER_LOG="$tmp/docker.log"
export FLAG_ROOT="$src"
: > "$DOCKER_LOG"
cat > "$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${DOCKER_LOG:?}"
verb=""
if [[ "${1:-}" == "compose" ]]; then
  i=2
  while [[ $i -le $# ]]; do
    arg="${!i}"
    case "$arg" in
      -p|--project-directory|--project-name|-f|--profile|--format)
        i=$((i + 2))
        ;;
      *)
        verb="$arg"
        break
        ;;
    esac
  done
elif [[ "${1:-}" == "run" ]]; then
  verb="run"
fi
case "$verb" in
  ls)
    printf '[]\n'
    ;;
  exec)
    if [[ "$*" == *"users list"* ]]; then
      printf '%s\n' '{"users":[{"name":"admin","id":"1"},{"name":"office","id":"2"}]}'
    elif [[ "$*" == *"apikeys create"* ]]; then
      printf '%s\n' 'hskey-api-stubkeystubkeystubkey'
    fi
    ;;
  config)
    python3 - <<'PY'
import json, os
bind = os.environ.get("HEADPLANE_BIND") or "127.0.0.1"
port = os.environ.get("HEADPLANE_PORT") or "3000"
print(json.dumps({"services": {
    "enroll": {"image": "idoris-vpn-enroll:local"},
    "headplane": {"ports": [{"target": 3000, "published": port, "host_ip": bind}]},
    "headplane-tailnet": {},
    "vpn-sidecar": {},
}}))
PY
    ;;
  build)
    python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); assert s.get("tailnet_admin") is True, s' \
      "${FLAG_ROOT:?}/headscale/managed.json"
    ;;
  run)
    nfile="${DOCKER_LOG}.n"
    n=0
    if [[ -f "$nfile" ]]; then
      n="$(cat "$nfile")"
    fi
    n=$((n + 1))
    printf '%s\n' "$n" > "$nfile"
    hash="$(printf '%064x' "$n")"
    printf 'idv1_%s\n%s\n' "$hash" "$hash"
    ;;
  version|up|ps|kill|restart|stop|"")
    ;;
  *)
    echo "docker stub: unhandled verb $verb ($*)" >&2
    exit 1
    ;;
esac
exit 0
EOF
chmod 700 "$tmp/bin/docker"
export PATH="$tmp/bin:$PATH"
export COMPOSE_PROJECT_NAME="idoris-vpn-r2d-flags"

policy="$src/headscale/policy.hujson"
before="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$policy")"
echo "flags: conflicting access dies before policy or docker"
set +e
conflict="$(bash "$src/bootstrap.sh" init --org office --admin admin --lan-cidr 192.168.1.0/24 --tailnet-admin --headplane-access tunnel 2>&1)"
conflict_ec=$?
set -e
[[ "$conflict_ec" -ne 0 ]] || { echo "conflict was accepted" >&2; exit 1; }
grep -q 'cannot be combined' <<<"$conflict" || { echo "conflict text: $conflict" >&2; exit 1; }
after="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$policy")"
[[ "$before" == "$after" ]] || { echo "conflict rewrote policy" >&2; exit 1; }
[[ ! -s "$DOCKER_LOG" ]] || { echo "conflict called docker: $(cat "$DOCKER_LOG")" >&2; exit 1; }
[[ ! -e "$src/headscale/managed.json" ]] || { echo "conflict wrote managed.json" >&2; exit 1; }

echo "flags: --headplane-access tailnet provisions vpn-server and gateway prefixes"
bash "$src/bootstrap.sh" init --org office --admin admin --lan-cidr 192.168.1.0/24 --headplane-access tailnet >/dev/null
python3 - "$src/headscale/managed.json" "$src/enroll/config.json" "$policy" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
cfg = json.load(open(sys.argv[2]))
policy = open(sys.argv[3]).read()
if state.get("tailnet_admin") is not True:
    raise SystemExit("managed tailnet_admin is not set")
if "tag:vpn-server" not in policy:
    raise SystemExit("policy has no tag:vpn-server")
names = {t["name"]: t for t in cfg["tenants"]}
if "vpn-server" not in names:
    raise SystemExit("no vpn-server enrollment entry")
gw = names.get("office-gateway")
if gw is None:
    raise SystemExit("no office-gateway entry")
if gw.get("lan_cidrs") != ["192.168.1.0/24"]:
    raise SystemExit("gateway lan_cidrs %s" % gw.get("lan_cidrs"))
if "token_hashes" not in gw:
    raise SystemExit("gateway has no token hash")
PY
hash_of() {
  python3 -c 'import json,sys
cfg=json.load(open(sys.argv[1]))
name=sys.argv[2]
t=next(x for x in cfg["tenants"] if x["name"]==name)
print(json.dumps(t["token_hashes"], sort_keys=True))' "$src/enroll/config.json" "$1"
}
gw_hash="$(hash_of office-gateway)"
vpn_hash="$(hash_of vpn-server)"
mints="$(grep -c 'token new' "$DOCKER_LOG" || true)"

echo "flags: a later CIDR updates lan_cidrs and keeps the token hash"
bash "$src/bootstrap.sh" add-tenant office --lan-cidr 192.168.2.0/24 --headplane-access tailnet >/dev/null
[[ "$(hash_of office-gateway)" == "$gw_hash" ]] || { echo "gateway hash changed" >&2; exit 1; }
[[ "$(hash_of vpn-server)" == "$vpn_hash" ]] || { echo "vpn-server hash changed" >&2; exit 1; }
mints_after="$(grep -c 'token new' "$DOCKER_LOG" || true)"
[[ "$mints_after" == "$mints" ]] || { echo "second run minted a token" >&2; exit 1; }
python3 -c 'import json,sys
cfg=json.load(open(sys.argv[1]))
gw=next(t for t in cfg["tenants"] if t["name"]=="office-gateway")
want=["192.168.1.0/24","192.168.2.0/24"]
if gw.get("lan_cidrs")!=want:
    raise SystemExit("lan_cidrs %s" % gw.get("lan_cidrs"))' "$src/enroll/config.json"
echo "access flags ok"
