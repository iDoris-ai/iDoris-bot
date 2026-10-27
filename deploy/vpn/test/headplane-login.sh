#!/usr/bin/env bash
# Prove HEADPLANE_ACCESS=tunnel|lan|tailnet|proxy with a real API-key login.
#
# Copies deploy/vpn to deploy/.hp-src (gitignored), starts Headscale and
# Headplane on a private compose project, POSTs /admin/login, and follows the
# session cookie to a loader that rejects the same request without the cookie.
# A 302 by itself is not success. Tears the project down, including volumes.
#
# Tailnet mode is the profile: published Headplane is stopped, its host port
# stays closed, and the login is sent to 127.0.0.1:3000 inside the sidecar
# network namespace (headplane-tailnet has no host port). The sidecar
# entrypoint is overridden to sleep so this proof does not mint an enrollment
# key or need /dev/net/tun.
#
# Usage: bash deploy/vpn/test/headplane-login.sh
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$root/../.." && pwd)"
src="$repo/deploy/.hp-src"
work=""

die() { echo "hp-login: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v python3 >/dev/null || die "python3 is required"
command -v curl >/dev/null || die "curl not found"

PROJ="idorishp$(python3 -c 'import random; print(random.randint(100000, 999999))')"
export COMPOSE_PROJECT_NAME="$PROJ"

free_port() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
free_udp() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

HEADSCALE_PORT="$(free_port)"
HEADPLANE_PORT="$(free_port)"
ENROLL_PORT="$(free_port)"
DERP_STUN_PORT="$(free_udp)"
export HEADSCALE_PORT HEADPLANE_PORT ENROLL_PORT DERP_STUN_PORT

CURL_IMAGE="${HP_CURL_IMAGE:-curlimages/curl:8.16.0}"
HP_NET=""
API_KEY=""

dc() { docker compose -f "$src/compose.yaml" "$@"; }

cleanup() {
  local ec=$?
  # Refusal checks run in a subshell. Do not tear the lab down from there.
  if [[ "${BASH_SUBSHELL:-0}" != 0 ]]; then
    return 0
  fi
  echo "hp-login: tearing down project ${PROJ} (exit ${ec})"
  if [[ "$ec" -ne 0 && -d "$src" ]]; then
    dc --profile tailnet-admin logs --tail 40 2>/dev/null \
      | sed -E 's/hskey-[A-Za-z0-9_.:+/=-]+/[redacted]/g' >&2 || true
  fi
  if [[ -d "$src" ]]; then
    dc --profile tailnet-admin down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$src" ${work:+"$work"}
  exit "$ec"
}
trap cleanup EXIT

rm -rf "$src"
# token-labels.json is an obsolete sidecar. Ignore it when a tree still has
# one. The copy must not require the file, and must not fail when it is absent.
python3 - "$root" "$src" <<'PY'
import shutil, sys
shutil.copytree(
    sys.argv[1],
    sys.argv[2],
    symlinks=False,
    ignore=shutil.ignore_patterns(
        "cookie_secret",
        "config.json",
        "headscale.apikey",
        "minted-tokens.txt",
        "token-labels.json",
        ".env",
        ".admin-mode",
        "managed.json",
        ".lab",
        ".probe.log",
        ".cleanroom.log",
        "__pycache__",
    ),
)
PY

if grep -n 'vpn\.example\.org/admin' "$src/compose.yaml"; then
  die "compose header still publishes /admin on the public VPN hostname"
fi

here="$src"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../ops-lib.sh
source "$src/ops-lib.sh"
write_env_var COMPOSE_PROJECT_NAME "$PROJ"

work="$(mktemp -d "${TMPDIR:-/tmp}/hp-login.XXXXXX")"
chmod 700 "$work"

echo "hp-login: static refusals"
if (
  trap - EXIT
  HEADPLANE_BASE_URL=https://vpn.example.org apply_headplane_access proxy
) >"$work/fail.out" 2>"$work/fail.err"; then
  die "proxy on the public VPN hostname was accepted"
fi
grep -q 'public VPN hostname' "$work/fail.err" || die "refusal text missing"
echo "  ok   proxy on the public VPN hostname"
if (
  trap - EXIT
  HEADPLANE_BIND=127.0.0.1 apply_headplane_access lan
) >"$work/fail.out" 2>"$work/fail.err"; then
  die "lan bound to 127.0.0.1 was accepted"
fi
echo "  ok   lan bound to 127.0.0.1"

echo "hp-login: public-admin override warns"
HEADPLANE_ALLOW_PUBLIC_ADMIN=1 HEADPLANE_BASE_URL=https://vpn.example.org \
  apply_headplane_access proxy >"$work/allow.out" 2>"$work/allow.err"
grep -q 'HEADPLANE_ALLOW_PUBLIC_ADMIN=1' "$work/allow.err" || die "public-admin warning missing"
grep -q 'cookie_secure=true' "$work/allow.out" || die "public-admin did not set cookie_secure"
unset HEADPLANE_ALLOW_PUBLIC_ADMIN

assert_config() {
  local base="$1" secure="$2" mode="$3"
  python3 - "$src/headplane/config.yaml" "$base" "$secure" "$src/.admin-mode" "$mode" <<'PY'
import sys
path, want_base, want_secure, mode_path, want_mode = sys.argv[1:]
base = secure = None
for line in open(path):
    stripped = line.lstrip()
    if stripped.startswith("base_url:"):
        base = stripped.split(":", 1)[1].strip().strip('"').strip("'")
    elif stripped.startswith("cookie_secure:"):
        secure = stripped.split(":", 1)[1].strip()
if base != want_base or secure != want_secure:
    raise SystemExit("config base=%s secure=%s, want %s %s" % (base, secure, want_base, want_secure))
text = open(mode_path).read()
if "mode=%s" % want_mode not in text:
    raise SystemExit("admin mode file is %r, want %s" % (text, want_mode))
PY
}

# Split a curl -D file. Prints: status, cookie header (name=value; ...), secure 0/1, location.
parse_login() {
  python3 - "$1" "$2" <<'PY'
import sys
hdr_path, expect = sys.argv[1:]
status = None
cookies = []
secure_any = False
insecure_any = False
location = ""
for raw in open(hdr_path, errors="replace"):
    line = raw.strip()
    if line.startswith("HTTP/"):
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        continue
    low = line.lower()
    if low.startswith("set-cookie:"):
        val = line.split(":", 1)[1].strip()
        pair = val.split(";", 1)[0].strip()
        if "=" not in pair or not pair.split("=", 1)[0]:
            continue
        attrs = [p.strip().lower() for p in val.split(";")[1:]]
        is_secure = any(a == "secure" for a in attrs)
        cookies.append(pair)
        secure_any = secure_any or is_secure
        insecure_any = insecure_any or not is_secure
    elif low.startswith("location:"):
        location = line.split(":", 1)[1].strip()
if status not in (301, 302, 303, 307, 308):
    raise SystemExit("login status %s, want a redirect" % status)
if not cookies:
    raise SystemExit("login redirect had no Set-Cookie")
if expect == "1":
    if not secure_any:
        raise SystemExit("proxy cookie was not marked Secure")
else:
    if secure_any:
        raise SystemExit("non-proxy cookie was marked Secure")
sys.stdout.write("%s\n%s\n%s\n" % (status, "; ".join(cookies), location))
PY
}

fetch() {
  # $1 body file, $2 header file, then curl args. Honours HP_NET.
  local body="$1" hdr="$2"
  shift 2
  if [[ -z "$HP_NET" ]]; then
    curl -sS --max-redirs 0 --max-time 20 -D "$hdr" -o "$body" "$@"
    return
  fi
  docker run --rm --network "$HP_NET" --entrypoint /bin/sh \
    -e API_KEY -e HP_COOKIE \
    "$CURL_IMAGE" -c '
      set -eu
      curl -sS --max-redirs 0 --max-time 20 -D /tmp/h -o /tmp/b "$@"
      printf "__HP_HDR__\n"
      cat /tmp/h
      printf "__HP_BODY__\n"
      cat /tmp/b
    ' -- "$@" >"$work/raw"
  python3 - "$work/raw" "$hdr" "$body" <<'PY'
import sys
raw, hdr, body = sys.argv[1:]
text = open(raw, errors="replace").read()
hmark = "__HP_HDR__\n"
bmark = "__HP_BODY__\n"
hi = text.find(hmark)
bi = text.find(bmark)
if hi < 0 or bi < 0 or bi < hi:
    raise SystemExit("curl container output had no header/body markers")
open(hdr, "w").write(text[hi + len(hmark):bi])
open(body, "w").write(text[bi + len(bmark):])
PY
}

prove_session() {
  local origin="$1" expect_secure="$2" label="$3"
  local login_url="${origin}/admin/login"
  fetch "$work/post.body" "$work/post.hdr" \
    -X POST "$login_url" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "api_key=${API_KEY}"
  local parsed status cookie location path
  parsed="$(parse_login "$work/post.hdr" "$expect_secure")" || {
    python3 -c 'import sys; t=open(sys.argv[1], errors="replace").read(); t=t.replace(sys.argv[2], "[redacted]"); print(t[-400:])' \
      "$work/post.body" "$API_KEY" >&2 || true
    die "$label login was not an authenticated redirect"
  }
  status="$(printf '%s\n' "$parsed" | sed -n '1p')"
  cookie="$(printf '%s\n' "$parsed" | sed -n '2p')"
  location="$(printf '%s\n' "$parsed" | sed -n '3p')"
  path="$(python3 -c 'import sys; from urllib.parse import urlparse; u=sys.argv[1]; p=urlparse(u).path if "://" in u else u.split("?",1)[0]; print(p or "/")' "$location")"
  export HP_COOKIE="$cookie"
  local candidate anon auth proved=0
  local candidates=("$path" "${path}.data" "/admin/machines" "/admin/machines.data" "/machines" "/machines.data")
  for candidate in "${candidates[@]}"; do
    [[ -n "$candidate" ]] || continue
    fetch "$work/anon.body" "$work/anon.hdr" "$origin$candidate"
    anon="$(python3 -c 'import sys
s=None
for line in open(sys.argv[1], errors="replace"):
    if line.startswith("HTTP/"):
        p=line.split()
        if len(p)>1 and p[1].isdigit(): s=p[1]
print(s or "0")' "$work/anon.hdr")"
    if [[ -n "$HP_NET" ]]; then
      fetch "$work/auth.body" "$work/auth.hdr" \
        -H "Cookie: ${HP_COOKIE}" "$origin$candidate"
    else
      fetch "$work/auth.body" "$work/auth.hdr" \
        -H "Cookie: ${cookie}" "$origin$candidate"
    fi
    auth="$(python3 -c 'import sys
s=None
for line in open(sys.argv[1], errors="replace"):
    if line.startswith("HTTP/"):
        p=line.split()
        if len(p)>1 and p[1].isdigit(): s=p[1]
print(s or "0")' "$work/auth.hdr")"
    if [[ "$auth" == "200" && "$anon" != "200" ]]; then
      if python3 -c 'import sys; t=open(sys.argv[1], errors="replace").read().lower(); raise SystemExit(0 if ("api key" in t and "machine" not in t) else 1)' "$work/auth.body"; then
        continue
      fi
      proved=1
      echo "  ok   $label login $status -> $candidate (anonymous $anon, session 200, secure=$expect_secure)"
      break
    fi
  done
  unset HP_COOKIE
  if [[ "$proved" != 1 ]]; then
    echo "hp-login: $label session was not accepted (location $location)" >&2
    die "$label did not reach an authenticated page"
  fi
}

restart_published() {
  export HEADPLANE_BIND
  dc up -d --force-recreate --no-deps headplane >/dev/null
  local code
  code="000"
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${HEADPLANE_PORT}/admin/login" || true)"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 2
  done
  dc logs --tail 30 headplane 2>/dev/null | sed -E 's/hskey-[A-Za-z0-9_.:+/=-]+/[redacted]/g' >&2 || true
  die "published Headplane did not serve /admin/login (last http $code)"
}

echo "hp-login: project=${PROJ} headscale=${HEADSCALE_PORT} headplane=${HEADPLANE_PORT}"
od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > "$src/headplane/cookie_secret"
chmod 600 "$src/headplane/cookie_secret"
[[ "$(wc -c < "$src/headplane/cookie_secret" | tr -d ' ')" == 32 ]] || die "cookie secret length"

echo "hp-login: starting headscale"
dc up -d --wait --wait-timeout 180 headscale
API_KEY="$(dc exec -T headscale headscale apikeys create --expiration 24h | tr -d '\r\n')"
[[ "$API_KEY" == hskey-api-* ]] || die "apikeys create did not return an API key"
export API_KEY

echo "hp-login: tunnel"
unset HEADPLANE_BIND HEADPLANE_LAN_HOST HEADPLANE_BASE_URL || true
apply_headplane_access tunnel >/dev/null
assert_config "http://127.0.0.1:${HEADPLANE_PORT}" false published
HEADPLANE_BIND="127.0.0.1"
restart_published
HP_NET=""
prove_session "http://127.0.0.1:${HEADPLANE_PORT}" 0 tunnel

echo "hp-login: lan"
export HEADPLANE_BIND="0.0.0.0"
export HEADPLANE_LAN_HOST="127.0.0.1"
apply_headplane_access lan >/dev/null
assert_config "http://127.0.0.1:${HEADPLANE_PORT}" false published
restart_published
prove_session "http://127.0.0.1:${HEADPLANE_PORT}" 0 lan

echo "hp-login: proxy"
unset HEADPLANE_BIND || true
export HEADPLANE_BASE_URL="https://admin.hp-login.example"
apply_headplane_access proxy >/dev/null
assert_config "https://admin.hp-login.example" true published
HEADPLANE_BIND="127.0.0.1"
restart_published
prove_session "http://127.0.0.1:${HEADPLANE_PORT}" 1 proxy

echo "hp-login: tailnet (no host port)"
dc stop headplane >/dev/null
unset HEADPLANE_BASE_URL || true
apply_headplane_access tailnet >/dev/null
assert_config "http://vpn-server.idoris.internal:3000" false tailnet-admin
python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(0.4)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)
raise SystemExit("published headplane port is still open")' "$HEADPLANE_PORT"

cat > "$src/test/login-override.yaml" <<'EOF'
services:
  vpn-sidecar:
    entrypoint: ["sleep", "infinity"]
    depends_on: !override
      headscale:
        condition: service_healthy
    devices: !reset []
    cap_add: !reset []
    healthcheck:
      test: ["CMD-SHELL", "true"]
      interval: 2s
      timeout: 2s
      retries: 5
      start_period: 1s
EOF

docker compose -f "$src/compose.yaml" -f "$src/test/login-override.yaml" \
  --profile tailnet-admin config --format json >"$work/merged.json"
python3 - "$work/merged.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
dep = data["services"]["vpn-sidecar"].get("depends_on") or {}
keys = list(dep) if isinstance(dep, dict) else list(dep)
if keys != ["headscale"]:
    raise SystemExit("vpn-sidecar still depends on %s" % ",".join(keys))
PY
docker compose -f "$src/compose.yaml" -f "$src/test/login-override.yaml" \
  --profile tailnet-admin up -d --wait --wait-timeout 180 vpn-sidecar headplane-tailnet >/dev/null
sid="$(dc --profile tailnet-admin ps -q vpn-sidecar)"
[[ -n "$sid" ]] || die "vpn-sidecar did not start"
pub="$(dc ps --status running -q headplane || true)"
[[ -z "$pub" ]] || die "published headplane is running beside the tailnet profile"
HP_NET="container:${sid}"
origin="http://127.0.0.1:3000"
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if fetch "$work/ready.body" "$work/ready.hdr" "$origin/admin/login"; then
    code="$(python3 -c 'import sys
s="0"
for line in open(sys.argv[1], errors="replace"):
    if line.startswith("HTTP/"):
        p=line.split()
        if len(p)>1 and p[1].isdigit(): s=p[1]
print(s)' "$work/ready.hdr")"
    if [[ "$code" == "200" ]]; then
      ready=1
      break
    fi
  fi
  sleep 2
done
[[ "$ready" == 1 ]] || die "tailnet Headplane did not serve /admin/login inside the sidecar netns"
prove_session "$origin" 0 tailnet

echo "hp-login: four modes accepted a session cookie"
