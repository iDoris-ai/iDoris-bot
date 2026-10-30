#!/usr/bin/env bash
# Credential lifecycle against the enroll service the probe already started.
#
# Required in the environment: COMPOSE_PROJECT_NAME, ENROLL_PORT, ENROLL_DIR,
# PROJ. ENROLL_UID and ENROLL_GID are read by ctl.sh. ENROLL_DIR holds
# config.json, which is the file the running enroll container has mounted.
# ctl.sh writes that file and restarts enroll. A file bind does not follow
# the CLI's rename, so SIGHUP would keep the previous config. Tokens stay
# in shell variables and in ENROLL_DIR/minted-tokens.txt (removed with the lab).
set -euo pipefail
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

die() { echo "credentials: $*" >&2; exit 1; }

[[ -n "${COMPOSE_PROJECT_NAME:-}" ]] || die "COMPOSE_PROJECT_NAME is required"
[[ -n "${ENROLL_PORT:-}" ]] || die "ENROLL_PORT is required"
[[ -n "${ENROLL_DIR:-}" ]] || die "ENROLL_DIR is required"
[[ -n "${PROJ:-}" ]] || die "PROJ is required"
[[ "$ENROLL_DIR" == /* && -d "$ENROLL_DIR" && ! -L "$ENROLL_DIR" ]] || die "ENROLL_DIR must be a real absolute directory"
[[ -f "$ENROLL_DIR/config.json" && ! -L "$ENROLL_DIR/config.json" ]] || die "enroll config is missing"

export ENROLL_DIR COMPOSE_PROJECT_NAME

cname="${PROJ}-cred-laptop-b"
cleanup_cred() {
  docker rm -f "$cname" >/dev/null 2>&1 || true
}
trap cleanup_cred EXIT

redact_stream() {
  sed -E 's/idv1_[0-9a-f]+/[redacted]/g; s/idoris-join-v1\.[A-Za-z0-9_.%=+-]+/[redacted]/g'
}

dc() { docker compose --project-directory "$root" --project-name "$COMPOSE_PROJECT_NAME" "$@"; }

enroll_url="http://127.0.0.1:${ENROLL_PORT}/v1/enroll"

# Run ctl.sh. On success the command's stdout is this function's stdout.
# On failure, stderr is redacted and nothing from stdout is printed.
run_ctl() {
  local err rc
  err="$(mktemp "$ENROLL_DIR/err.XXXXXX")"
  set +e
  out="$(bash "$root/ctl.sh" "$@" 2>"$err")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    redact_stream < "$err" >&2 || true
    rm -f "$err"
    return "$rc"
  fi
  rm -f "$err"
  printf '%s\n' "$out"
}

field() {
  printf '%s\n' "$1" | python3 -c '
import sys
want = sys.argv[1]
for line in sys.stdin:
    if ":" not in line:
        continue
    key, value = line.split(":", 1)
    if key.strip() == want:
        sys.stdout.write(value.strip())
        raise SystemExit(0)
raise SystemExit(1)
' "$2"
}

post_enroll() {
  local token="$1" hostname="$2" expect="$3" keyfile="${4:-}" try
  try=0
  while [[ "$try" -lt 30 ]]; do
    try=$((try + 1))
    if python3 - "$token" "$enroll_url" "$hostname" "$expect" "$keyfile" <<'PY'
import json, sys, urllib.error, urllib.request
token, url, hostname, expect, keyfile = sys.argv[1:]
expect = int(expect)
body = json.dumps({"hostname": hostname, "os": "linux"}).encode()
req = urllib.request.Request(url, data=body, headers={
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json",
})
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        code = resp.status
        data = json.load(resp)
except urllib.error.HTTPError as err:
    code = err.code
    data = {}
if code != expect:
    sys.exit(1)
if expect == 200:
    key = data.get("auth_key") or ""
    if not key.startswith("hskey-auth-"):
        sys.exit("enroll did not return an auth key")
    if keyfile:
        with open(keyfile, "w") as fh:
            fh.write(key)
sys.exit(0)
PY
    then
      return 0
    fi
    sleep 1
  done
  return 1
}

list_rows() {
  if ! listed="$(run_ctl token list --entry acme)"; then
    die "token list failed"
  fi
  printf '%s\n' "$listed"
}

echo "credentials: selectors require exactly one of --label or --hash-prefix"
set +e
both="$(bash "$root/ctl.sh" token revoke --entry acme --label laptop-a --hash-prefix abcd12 2>&1)"
both_ec=$?
set -e
[[ "$both_ec" -ne 0 ]] || die "revoke accepted both --label and --hash-prefix"
grep -q 'exactly one' <<<"$both" || die "revoke did not say exactly one selector"
set +e
none="$(bash "$root/ctl.sh" offboard --entry acme 2>&1)"
none_ec=$?
set -e
[[ "$none_ec" -ne 0 ]] || die "offboard ran with no selector"
grep -q 'exactly one' <<<"$none" || die "offboard did not say exactly one selector"

echo "credentials: legacy hash is listed as -"
rows="$(list_rows)"
printf '%s\n' "$rows" | python3 -c '
import sys
rows = [line.rstrip("\n").split("\t") for line in sys.stdin if line.strip()]
if not any(len(r) == 3 and r[0] == "-" for r in rows):
    raise SystemExit("no unlabeled credential")
if any(len(part) == 64 for row in rows for part in row):
    raise SystemExit("token list printed a full hash")
'

before=0
if [[ -f "$ENROLL_DIR/minted-tokens.txt" ]]; then
  before="$(grep -c 'idoris-join-v1' "$ENROLL_DIR/minted-tokens.txt" || true)"
fi

echo "credentials: token new --label laptop-a"
if ! mint="$(run_ctl token new --entry acme --label laptop-a --enroll-url "http://127.0.0.1:${ENROLL_PORT}")"; then
  die "token new laptop-a failed"
fi
token_a="$(field "$mint" token)" || die "token new laptop-a did not print a token"
hash_a="$(field "$mint" hash)" || die "token new laptop-a did not print a hash prefix"
join_a="$(field "$mint" join)" || die "token new laptop-a did not print a join code"
[[ "$hash_a" =~ ^[0-9a-f]{12}$ ]] || die "hash prefix is not 12 lowercase hex digits"
[[ "$token_a" == idv1_* ]] || die "token does not start with idv1_"
[[ "$join_a" == idoris-join-v1.* ]] || die "join code does not start with idoris-join-v1."
rows="$(list_rows)"
printf '%s\n' "$rows" | python3 -c '
import sys
prefix, label = sys.argv[1], sys.argv[2]
hits = []
for line in sys.stdin:
    parts = line.rstrip("\n").split("\t")
    if len(parts) == 3 and parts[0] == label:
        hits.append(parts[1].lower())
if hits != [prefix]:
    raise SystemExit("listed prefix does not match the printed prefix")
' "$hash_a" laptop-a

if ! post_enroll "$token_a" cred-laptop-a 200; then
  die "laptop-a was not accepted"
fi
echo "credentials: laptop-a enrolled"

echo "credentials: token new --label laptop-b"
if ! mint="$(run_ctl token new --entry acme --label laptop-b --enroll-url "http://127.0.0.1:${ENROLL_PORT}")"; then
  die "token new laptop-b failed"
fi
token_b="$(field "$mint" token)" || die "token new laptop-b did not print a token"
[[ "$token_b" == idv1_* ]] || die "laptop-b token was not printed"

echo "credentials: duplicate label is refused"
set +e
dup="$(bash "$root/ctl.sh" token new --entry acme --label laptop-b --enroll-url "http://127.0.0.1:${ENROLL_PORT}" 2>&1)"
dup_ec=$?
set -e
[[ "$dup_ec" -ne 0 ]] || die "duplicate label was accepted"
grep -q 'already exists' <<<"$dup" || die "duplicate label was not reported"
after="$(grep -c 'idoris-join-v1' "$ENROLL_DIR/minted-tokens.txt" || true)"
[[ "$after" -eq $((before + 2)) ]] || die "a refused invite was written to minted-tokens.txt"

echo "credentials: revoke laptop-a"
if ! revoked="$(run_ctl token revoke --entry acme --label laptop-a)"; then
  die "revoke laptop-a failed"
fi
printf '%s\n' "$revoked" | python3 -c '
import sys
line = ""
for candidate in sys.stdin:
    candidate = candidate.rstrip("\n")
    if candidate.startswith("revoked "):
        line = candidate
parts = line.split()
if len(parts) != 4 or parts[0] != "revoked" or parts[1] != "acme" or parts[2] != "laptop-a":
    raise SystemExit("revoke line is not 4 fields for laptop-a")
if len(parts[3]) != 12:
    raise SystemExit("revoke prefix is not 12 hex digits")
'
if ! post_enroll "$token_a" cred-laptop-a-revoked 401; then
  die "revoked laptop-a was not rejected with 401"
fi
echo "credentials: revoked laptop-a is rejected"

keyfile="$(mktemp "$ENROLL_DIR/key.XXXXXX")"
chmod 600 "$keyfile"
if ! post_enroll "$token_b" cred-laptop-b 200 "$keyfile"; then
  rm -f "$keyfile"
  die "laptop-b was not accepted after laptop-a was revoked"
fi
authkey="$(cat "$keyfile")"
rm -f "$keyfile"
echo "credentials: laptop-b still enrolls"

cid="$(dc ps -q headscale)"
[[ -n "$cid" ]] || die "headscale container is missing"
net="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$cid" | head -n1)"
[[ -n "$net" ]] || die "could not find the compose network"
docker run -d --name "$cname" \
  --label "idoris-vpn-probe=${PROJ}" \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  --network "$net" \
  -e "TS_AUTHKEY=${authkey}" \
  -e TS_AUTH_ONCE=true \
  -e TS_USERSPACE=false \
  -e TS_STATE_DIR=/var/lib/tailscale \
  -e TS_HOSTNAME=cred-laptop-b \
  -e TS_ACCEPT_DNS=false \
  -e "TS_EXTRA_ARGS=--login-server=http://headscale:8080" \
  --entrypoint /usr/local/bin/containerboot \
  tailscale/tailscale:v1.104.2 >/dev/null
unset authkey

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if docker exec "$cname" tailscale status --json 2>/dev/null | python3 -c 'import json,sys
s=json.load(sys.stdin)
raise SystemExit(0 if s.get("BackendState")=="Running" else 1)'; then
    ready=1
    break
  fi
  sleep 3
done
[[ "$ready" == 1 ]] || die "cred-laptop-b did not reach Running"

node_id="$(dc exec -T headscale headscale nodes list -o json | python3 -c '
import json, sys
host = "cred-laptop-b"
raw = json.load(sys.stdin)

def names(o):
    found = []
    for key in ("givenName", "given_name", "name", "hostname"):
        value = o.get(key)
        if isinstance(value, str) and value:
            found.append(value)
    return found

def walk(o):
    if isinstance(o, dict):
        ident = o.get("id")
        if ident is not None:
            for name in names(o):
                if name == host or name.startswith(host + "."):
                    return str(ident)
        for value in o.values():
            found = walk(value)
            if found:
                return found
    elif isinstance(o, list):
        for item in o:
            found = walk(item)
            if found:
                return found
    return ""

found = walk(raw)
if not found:
    raise SystemExit("node id not found")
sys.stdout.write(found)
')"
[[ "$node_id" =~ ^[0-9]+$ ]] || die "node id is not decimal"

echo "credentials: offboard laptop-b revokes before expire and delete"
set +e
off="$(bash "$root/ctl.sh" offboard --entry acme --label laptop-b --node-id "$node_id" 2>&1)"
off_ec=$?
set -e
if [[ "$off_ec" -ne 0 ]]; then
  printf '%s\n' "$off" | redact_stream >&2
  die "offboard failed"
fi
printf '%s\n' "$off" | python3 -c '
import sys
text = sys.stdin.read()
marks = ("step 1:", "revoked acme laptop-b ", "step 2:", "step 3:", "step 4:")
pos = -1
for mark in marks:
    found = text.find(mark)
    if found < 0 or found <= pos:
        raise SystemExit("offboard order missing %s" % mark)
    pos = found
if "offboarded entry acme" not in text:
    raise SystemExit("offboard did not finish")
'
rows="$(list_rows)"
printf '%s\n' "$rows" | python3 -c '
import sys
for line in sys.stdin:
    parts = line.rstrip("\n").split("\t")
    if len(parts) == 3 and parts[0] in ("laptop-a", "laptop-b"):
        raise SystemExit("%s is still listed" % parts[0])
'
still="$(dc exec -T headscale headscale nodes list -o json | python3 -c '
import json, sys
host = "cred-laptop-b"
try:
    raw = json.load(sys.stdin)
except Exception as exc:
    sys.stderr.write("nodes list: %s\n" % exc)
    sys.stdout.write("error")
    raise SystemExit(0)

def walk(o):
    if isinstance(o, dict):
        for key in ("givenName", "given_name", "name", "hostname"):
            value = o.get(key)
            if isinstance(value, str) and (value == host or value.startswith(host + ".")):
                return True
        return any(walk(v) for v in o.values())
    if isinstance(o, list):
        return any(walk(i) for i in o)
    return False

sys.stdout.write("yes" if walk(raw) else "no")
')"
[[ "$still" == "no" ]] || die "offboard left cred-laptop-b in the node list (${still})"
docker rm -f "$cname" >/dev/null

echo "credentials: the last credential is kept"
remain="$(printf '%s\n' "$rows" | python3 -c '
import sys
keep = []
for line in sys.stdin:
    parts = line.rstrip("\n").split("\t")
    if len(parts) == 3:
        keep.append(parts)
if len(keep) != 1 or keep[0][0] != "-":
    raise SystemExit("expected one unlabeled credential to remain")
sys.stdout.write(keep[0][1])
')"
[[ "$remain" =~ ^[0-9a-f]{12}$ ]] || die "remaining prefix is not 12 hex digits"
set +e
last="$(bash "$root/ctl.sh" token revoke --entry acme --hash-prefix "$remain" 2>&1)"
last_ec=$?
set -e
[[ "$last_ec" -ne 0 ]] || die "revoke removed the last credential"
grep -q 'refusing to remove the last token hash' <<<"$last" || grep -q 'refusing to remove the last token' <<<"$last" || die "last revoke did not refuse"
rows="$(list_rows)"
printf '%s\n' "$rows" | python3 -c '
import sys
prefix = sys.argv[1]
hits = [line for line in sys.stdin if line.startswith("-\t" + prefix + "\t")]
if len(hits) != 1:
    raise SystemExit("last credential was removed")
' "$remain"

set +e
last_off="$(bash "$root/ctl.sh" offboard --entry acme --hash-prefix "$remain" --node-id "$node_id" 2>&1)"
last_off_ec=$?
set -e
[[ "$last_off_ec" -ne 0 ]] || die "offboard removed the last credential"
grep -q 'not expired or deleted' <<<"$last_off" || die "failed offboard did not say the node was left alone"
grep -q 'step 3:' <<<"$last_off" && die "failed offboard reached expire"
grep -q 'step 4:' <<<"$last_off" && die "failed offboard reached delete"
rows="$(list_rows)"
printf '%s\n' "$rows" | python3 -c '
import sys
prefix = sys.argv[1]
hits = [line for line in sys.stdin if line.startswith("-\t" + prefix + "\t")]
if len(hits) != 1:
    raise SystemExit("failed offboard removed the last credential")
' "$remain"

[[ ! -e "$ENROLL_DIR/token-labels.json" && ! -L "$ENROLL_DIR/token-labels.json" ]] || die "ctl.sh wrote token-labels.json"
echo "credentials: ok"
