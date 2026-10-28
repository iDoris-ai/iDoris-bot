#!/usr/bin/env python3
"""Enrollment-config writers share the Go flock on <config>.lock.

Go takes an exclusive flock(2) on ``<config>.lock``. fcntl.flock on that
same file is the same lock, so a revoke that runs while bootstrap or
policy reconciles cannot be overwritten by a stale snapshot.

The lock is mode 0600. Root chowns it to the enrollment runtime uid (the
image USER, normally 65532, or the operator uid recorded as ENROLL_UID)
so that user can join the transaction. A rewrite uses a unique temp file
in the same directory and keeps the existing owner and mode.

IDORIS_ENROLL_LOCK_HOLD_SECONDS and IDORIS_ENROLL_LOCK_SIGNAL widen the
window for tests. They are unset in production. The hold is capped at
30 seconds and runs only while the lock is already held.
"""

from __future__ import annotations

import datetime
import errno
import fcntl
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path

_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_HOLD_ENV = "IDORIS_ENROLL_LOCK_HOLD_SECONDS"
_SIGNAL_ENV = "IDORIS_ENROLL_LOCK_SIGNAL"


class LeaveUnchanged:
    """Returned by mutate when the locked document must not be replaced."""


def locked_update(path, mutate, *, runtime_uid=None, runtime_gid=None):
    """Load path under <path>.lock, let mutate replace it, and write it back.

    mutate receives the loaded object, or None when the file does not exist.
    Return LeaveUnchanged to skip the write. Return a dict to replace the
    file. The lock is released on every exit, including SystemExit.
    """
    target = Path(path)
    runtime = _runtime_ids(runtime_uid, runtime_gid)
    _prepare_target(target)
    lock_fd = _open_lock(Path(str(target) + ".lock"), runtime)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            st = _prepare_target(target)
            cfg = None
            if st is not None:
                with target.open("r", encoding="utf-8") as handle:
                    cfg = json.load(handle)
                if not isinstance(cfg, dict):
                    raise ValueError("enroll config is not an object")
            _hold_for_tests()
            result = mutate(cfg)
            if result is LeaveUnchanged or isinstance(result, LeaveUnchanged):
                return
            if not isinstance(result, dict):
                raise TypeError("mutate must return a dict or LeaveUnchanged")
            mode = stat.S_IMODE(st.st_mode) if st is not None else 0o600
            owner = None
            if os.geteuid() == 0:
                if st is not None:
                    owner = (st.st_uid, st.st_gid)
                elif runtime is not None:
                    owner = runtime
            if os.path.islink(target):
                raise OSError("refusing to update a symlink: %s" % target)
            _replace(target, (json.dumps(result, indent=2) + "\n").encode("utf-8"), mode, owner)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def merge_bootstrap_rows(cfg, control_url, spec_text):
    """Append bootstrap spec rows that are not already in cfg.

    cfg is the document loaded under the lock. Existing token hashes are
    left as they are, so a revoke that landed before this load stays gone.
    spec_text lines are name|user|tags|rate|ttl|hash|role.
    """
    if cfg is None:
        cfg = {
            "control_url": control_url,
            "headscale_url": "http://headscale:8080",
            "headscale_api_key_file": "/etc/idoris/headscale.apikey",
            "tenants": [],
        }
    if not isinstance(cfg, dict):
        raise ValueError("enroll config is not an object")
    tenants = cfg.setdefault("tenants", [])
    if not isinstance(tenants, list):
        raise ValueError("enroll config has no tenants list")
    have = set()
    for tenant in tenants:
        if isinstance(tenant, dict) and isinstance(tenant.get("name"), str):
            have.add(tenant["name"])
    for line in spec_text.splitlines():
        if line == "":
            continue
        parts = line.split("|")
        if len(parts) != 7:
            raise ValueError("bootstrap spec row is malformed")
        name, user, tags, rate, ttl, digest, role = parts
        if name in have:
            continue
        label = "bootstrap-" + name
        if _LABEL_RE.fullmatch(label) is None:
            raise ValueError("bootstrap label %r is not a valid credential label" % label)
        if _HASH_RE.fullmatch(digest) is None:
            raise ValueError("bootstrap hash is not a hex SHA-256")
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
        tenants.append(entry)
        have.add(name)
    return cfg


def _runtime_ids(uid, gid):
    if uid is None and gid is None:
        return None
    if uid is None:
        raise ValueError("runtime_gid requires runtime_uid")
    uid = int(uid)
    gid = int(uid if gid is None else gid)
    if uid < 1 or gid < 1 or uid > 0xFFFFFFFF or gid > 0xFFFFFFFF:
        raise ValueError("runtime uid and gid must be non-zero 32-bit ids")
    return uid, gid


def _prepare_target(path: Path):
    """Return the file stat, or None when the file is absent. Refuse a symlink."""
    if os.path.islink(path):
        raise OSError("refusing to update a symlink: %s" % path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(st.st_mode):
        raise OSError("refusing to update a non-regular file: %s" % path)
    if os.geteuid() != 0 and st.st_uid != os.geteuid():
        raise PermissionError("refusing to replace %s owned by uid %s" % (path, st.st_uid))
    return st


def _open_lock(lock_path: Path, runtime):
    """Open <config>.lock without following a symlink. Root gives it to runtime."""
    created = False
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
    except FileExistsError:
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise OSError("refusing to lock through a symlink: %s" % lock_path) from exc
            raise
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise OSError("refusing to lock through a symlink: %s" % lock_path) from exc
        raise
    try:
        if os.geteuid() == 0 and runtime is not None:
            os.fchown(fd, runtime[0], runtime[1])
        try:
            os.fchmod(fd, 0o600)
        except PermissionError:
            if created or os.geteuid() == 0:
                raise
        return fd
    except Exception:
        os.close(fd)
        if created:
            try:
                os.unlink(lock_path)
            except OSError:
                pass
        raise


def _replace(path: Path, data: bytes, mode: int, owner) -> None:
    directory = str(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".enroll-", suffix=".tmp", dir=directory)
    tmp_left = tmp
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fchmod(fd, mode)
        if owner is not None and os.geteuid() == 0:
            os.fchown(fd, owner[0], owner[1])
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        tmp_left = ""
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp_left:
            try:
                os.unlink(tmp_left)
            except FileNotFoundError:
                pass


def _hold_for_tests() -> None:
    signal = os.environ.get(_SIGNAL_ENV, "")
    if signal:
        fd = os.open(signal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    raw = os.environ.get(_HOLD_ENV, "")
    if not raw:
        return
    seconds = float(raw)
    if seconds < 0 or seconds > 30:
        raise ValueError("IDORIS_ENROLL_LOCK_HOLD_SECONDS must be between 0 and 30")
    if seconds:
        time.sleep(seconds)
