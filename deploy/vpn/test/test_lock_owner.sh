#!/usr/bin/env bash
# Enrollment lock ownership and a cross-container revoke, inside Linux.
#
# Docker Desktop bind mounts do not keep Linux owners, and a macOS process
# does not share a flock with a container. This script uses a named volume
# and runs both writers in containers on the Docker VM's Linux kernel.
# It does not prove a native Linux host bind-mount.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/../.." && pwd)"
img="python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
rand="$(openssl rand -hex 4)"
vol="r4o-lock-${rand}"
hold="r4o-hold-${rand}"
work="$(mktemp -d)"

cleanup() {
  docker rm -f "$hold" >/dev/null 2>&1 || true
  docker volume rm -f "$vol" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

die() { echo "test_lock_owner: $*" >&2; exit 1; }

arch="$(docker info -f '{{.Architecture}}')"
case "$arch" in
  aarch64|arm64) goarch=arm64 ;;
  x86_64|amd64) goarch=amd64 ;;
  *) die "unsupported docker architecture $arch" ;;
esac

echo "building linux/$goarch idoris-vpn-enroll"
(
  cd "$repo/vpn"
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -o "$work/idoris-vpn-enroll" ./cmd/idoris-vpn-enroll
)

docker volume create "$vol" >/dev/null
docker run --rm --user 0 \
  -v "$vol":/work \
  -v "$work/idoris-vpn-enroll":/src/idoris-vpn-enroll:ro \
  -v "$here/enroll_lock.py":/src/enroll_lock.py:ro \
  -v "$here/test/lock_owner_inner.py":/src/lock_owner_inner.py:ro \
  "$img" \
  sh -c 'cp /src/idoris-vpn-enroll /work/idoris-vpn-enroll && cp /src/enroll_lock.py /work/enroll_lock.py && cp /src/lock_owner_inner.py /work/lock_owner_inner.py && chmod 755 /work/idoris-vpn-enroll && chmod 700 /work && chmod 644 /work/enroll_lock.py /work/lock_owner_inner.py && chown 65532:65532 /work /work/idoris-vpn-enroll /work/enroll_lock.py /work/lock_owner_inner.py'

echo "ownership: root list, root-owned lock, runtime chown"
docker run --rm --user 0 -v "$vol":/work "$img" python3 /work/lock_owner_inner.py

cat > "$work/holder.py" <<'PY'
import sys
sys.path.insert(0, "/work")
from enroll_lock import locked_update

def mutate(cfg):
    cfg["control_url"] = "https://r4o.example"
    return cfg

locked_update("/work/config.json", mutate, runtime_uid=65532, runtime_gid=65532)
PY

docker run --rm --user 0 -v "$vol":/work -v "$work/holder.py":/src/holder.py:ro "$img" \
  sh -c 'cp /src/holder.py /work/holder.py && chmod 644 /work/holder.py'

echo "concurrency: root reconcile holds the lock, uid 65532 revokes"
docker run -d --name "$hold" --user 0 \
  -e IDORIS_ENROLL_LOCK_HOLD_SECONDS=15 \
  -e IDORIS_ENROLL_LOCK_SIGNAL=/work/signal \
  -v "$vol":/work \
  "$img" python3 /work/holder.py >/dev/null

ready=0
for _ in $(seq 1 50); do
  if docker exec "$hold" test -f /work/signal; then
    ready=1
    break
  fi
  sleep 0.2
done
[[ "$ready" -eq 1 ]] || die "holder did not take the lock"
[[ "$(docker inspect -f '{{.State.Running}}' "$hold")" == "true" ]] || die "holder finished before revoke started"

prefix="$(docker run --rm -v "$vol":/work "$img" sh -c 'cut -c1-8 /work/stolen.hash')"
docker run --rm --user 65532:65532 -v "$vol":/work "$img" \
  /work/idoris-vpn-enroll revoke --config /work/config.json --entry acme --hash-prefix "$prefix"
hold_rc="$(docker wait "$hold")"
[[ "$hold_rc" -eq 0 ]] || die "holder exited $hold_rc ($(docker logs "$hold" 2>&1 || true))"

docker run --rm -i -v "$vol":/work "$img" python3 - <<'PY'
import json
cfg = json.load(open("/work/config.json", encoding="utf-8"))
if cfg.get("control_url") != "https://r4o.example":
    raise SystemExit("control_url %r" % cfg.get("control_url"))

def hashes(items):
    out = []
    for item in items:
        out.append(item["hash"] if isinstance(item, dict) else item)
    return out

got = hashes(cfg["tenants"][0]["token_hashes"])
keep = open("/work/keep.hash", encoding="utf-8").read().strip()
stolen = open("/work/stolen.hash", encoding="utf-8").read().strip()
if stolen in got:
    raise SystemExit("revoked hash was resurrected")
if keep not in got:
    raise SystemExit("keep hash missing")
print("concurrency=ok")
PY

echo "test_lock_owner: ok"
