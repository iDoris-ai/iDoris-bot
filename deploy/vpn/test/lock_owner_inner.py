#!/usr/bin/env python3
"""Ownership checks for the enrollment lock. Run as root inside Linux.

The shell test copies this onto a named volume. Bind-mount ownership is not
what this file proves.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys

sys.path.insert(0, "/work")

from enroll_lock import locked_update  # noqa: E402

RUNTIME = 65532
KEEP = "aa" * 32
STOLEN = "bb" * 32


def run_as(uid: int, args: list[str]) -> subprocess.CompletedProcess[str]:
    def drop() -> None:
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    return subprocess.run(args, preexec_fn=drop, capture_output=True, text=True)


def write_config(path: str) -> None:
    doc = {
        "control_url": "https://vpn.example.org",
        "tenants": [{
            "name": "acme",
            "headscale_user_id": "1",
            "token_hashes": [KEEP, STOLEN],
        }],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)
    os.chown(path, RUNTIME, RUNTIME)


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("lock_owner_inner must run as root")
    write_config("/work/list.json")
    listed = subprocess.run(
        ["/work/idoris-vpn-enroll", "list-credentials", "--config", "/work/list.json", "--entry", "acme"],
        capture_output=True, text=True,
    )
    if listed.returncode != 0:
        sys.exit("root list failed: %s" % listed.stderr)
    if os.path.exists("/work/list.json.lock"):
        sys.exit("root list created /work/list.json.lock")
    print("list_created_lock=no")

    write_config("/work/deny.json")
    fd = os.open("/work/deny.json.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    denied_list = run_as(RUNTIME, [
        "/work/idoris-vpn-enroll", "list-credentials", "--config", "/work/deny.json", "--entry", "acme",
    ])
    if denied_list.returncode != 0:
        sys.exit("uid 65532 list failed on a root-owned lock: %s" % denied_list.stderr)
    st = os.stat("/work/deny.json.lock")
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        sys.exit("reader changed the root-owned lock: uid %s mode %o" % (st.st_uid, stat.S_IMODE(st.st_mode)))
    print("deny_list=ok")
    denied_revoke = run_as(RUNTIME, [
        "/work/idoris-vpn-enroll", "revoke", "--config", "/work/deny.json",
        "--entry", "acme", "--hash-prefix", STOLEN[:8],
    ])
    if denied_revoke.returncode == 0:
        sys.exit("uid 65532 revoke opened a root-owned 0600 lock")
    print("deny_revoke=refused")

    write_config("/work/config.json")

    def mark(cfg):
        cfg["headscale_url"] = "http://headscale:8080"
        return cfg

    locked_update("/work/config.json", mark, runtime_uid=RUNTIME, runtime_gid=RUNTIME)
    lock_st = os.stat("/work/config.json.lock")
    cfg_st = os.stat("/work/config.json")
    if lock_st.st_uid != RUNTIME or lock_st.st_gid != RUNTIME or stat.S_IMODE(lock_st.st_mode) != 0o600:
        sys.exit("lock owner uid=%s gid=%s mode=%o" % (lock_st.st_uid, lock_st.st_gid, stat.S_IMODE(lock_st.st_mode)))
    if cfg_st.st_uid != RUNTIME or cfg_st.st_gid != RUNTIME or stat.S_IMODE(cfg_st.st_mode) != 0o600:
        sys.exit("config owner uid=%s gid=%s mode=%o" % (cfg_st.st_uid, cfg_st.st_gid, stat.S_IMODE(cfg_st.st_mode)))
    print("root_chown_lock=65532")

    user = run_as(RUNTIME, [
        sys.executable, "-c",
        "import sys; sys.path.insert(0, '/work')\n"
        "from enroll_lock import locked_update\n"
        "def mutate(cfg):\n"
        "    cfg['control_url'] = 'https://owner.example'\n"
        "    return cfg\n"
        "locked_update('/work/config.json', mutate)\n",
    ])
    if user.returncode != 0:
        sys.exit("uid 65532 update failed: %s" % (user.stderr or user.stdout))
    cfg_st = os.stat("/work/config.json")
    if cfg_st.st_uid != RUNTIME or stat.S_IMODE(cfg_st.st_mode) != 0o600:
        sys.exit("65532 update changed ownership")
    with open("/work/config.json", encoding="utf-8") as handle:
        cfg = json.load(handle)
    if cfg["control_url"] != "https://owner.example":
        sys.exit("65532 update did not land")
    print("user_update=ok")
    with open("/work/keep.hash", "w", encoding="utf-8") as handle:
        handle.write(KEEP + "\n")
    with open("/work/stolen.hash", "w", encoding="utf-8") as handle:
        handle.write(STOLEN + "\n")
    os.chmod("/work/keep.hash", 0o644)
    os.chmod("/work/stolen.hash", 0o644)


if __name__ == "__main__":
    main()
