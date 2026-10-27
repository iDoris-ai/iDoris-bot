#!/usr/bin/env python3
"""Validate a restore bundle. A bundle is data, not code.

The checkout's compose.yaml is never installed from the bundle. .env may
carry only the keys listed here (project name, ports, bind addresses, uid/gid,
URLs). Image overrides and unknown keys are rejected. Symlinks, special files,
absolute paths and '..' components are rejected anywhere in the staged tree.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tarfile

ALLOWED = {
    "COMPOSE_PROJECT_NAME": "label",
    "HEADSCALE_PORT": "port",
    "HEADPLANE_PORT": "port",
    "ENROLL_PORT": "port",
    "DERP_STUN_PORT": "port",
    "HEADPLANE_BIND": "ipv4",
    "ENROLL_UID": "uid",
    "ENROLL_GID": "uid",
    "ENROLL_PUBLIC_URL": "url",
    "HEADPLANE_BASE_URL": "url",
    "VPN_SERVER_LOGIN_SERVER": "url",
    "HEADPLANE_LAN_HOST": "host",
    "HEADPLANE_ACCESS": "access",
    "HEADPLANE_ALLOW_PUBLIC_ADMIN": "bit",
}

IMAGE_OVERRIDE_KEYS = ("ENROLL_IMAGE", "IDORIS_VPN_VERSION")

REQUIRED = (
    "manifest.json",
    "headscale/db.sqlite",
    "headscale/noise_private.key",
    "state/enroll/config.json",
    "state/enroll/headscale.apikey",
    "state/headplane/cookie_secret",
    "state/dotenv",
    "state/headscale/managed.json",
    "state/headscale/config.yaml",
    "state/headscale/policy.hujson",
    "state/headplane/config.yaml",
    "state/compose.yaml",
)

_LABEL = re.compile(r"^[a-z0-9][a-z0-9_-]{0,50}$")
_UID = re.compile(r"^[1-9][0-9]{0,9}$")
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_ACCESS = {"tunnel", "lan", "tailnet", "proxy"}


def die(message: str) -> None:
    print("bundle: %s" % message, file=sys.stderr)
    raise SystemExit(1)


def _check_component(name: str) -> None:
    if name in (".", "..") or "/" in name or "\\" in name or name.startswith("/"):
        die("illegal path component %r" % name)


def _check_rel(rel: str) -> None:
    if os.path.isabs(rel) or rel.startswith("\\"):
        die("absolute path in bundle: %s" % rel)
    parts = rel.split("/")
    if any(part in ("", ".", "..") for part in parts):
        die("illegal path in bundle: %s" % rel)


def _inside(root: str, path: str) -> None:
    real_root = os.path.realpath(root)
    real = os.path.realpath(path)
    if real != real_root and not real.startswith(real_root + os.sep):
        die("path escapes the bundle: %s" % path)


def _kind(key: str, value: str) -> None:
    kind = ALLOWED[key]
    if kind == "label":
        if not _LABEL.match(value):
            die("%s is not a safe project label" % key)
        return
    if kind == "port":
        if not value.isdigit() or not 1 <= int(value) <= 65535:
            die("%s must be a port 1-65535" % key)
        return
    if kind == "ipv4":
        parts = value.split(".")
        if len(parts) != 4 or any(not p.isdigit() or int(p) > 255 for p in parts):
            die("%s must be an IPv4 address" % key)
        return
    if kind == "uid":
        if not _UID.match(value):
            die("%s must be a non-zero numeric id" % key)
        return
    if kind == "url":
        if not (value.startswith("http://") or value.startswith("https://")):
            die("%s must be an http(s) URL" % key)
        if any(ch.isspace() for ch in value):
            die("%s must not contain whitespace" % key)
        return
    if kind == "host":
        if not (_HOST.match(value) or _kind_ipv4_ok(value)):
            die("%s must be a hostname or IPv4 address" % key)
        return
    if kind == "access":
        if value not in _ACCESS:
            die("HEADPLANE_ACCESS must be tunnel, lan, tailnet or proxy")
        return
    if kind == "bit":
        if value not in ("0", "1"):
            die("%s must be 0 or 1" % key)
        return
    die("internal: unknown kind for %s" % key)


def _kind_ipv4_ok(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and int(p) <= 255 for p in parts)


def parse_dotenv(text: str) -> dict:
    if text.startswith("\ufeff"):
        die("dotenv has a BOM")
    if "\x00" in text:
        die("dotenv contains NUL")
    out: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        if raw.strip() == "" or raw.lstrip().startswith("#"):
            continue
        if raw.startswith("export ") or raw.startswith("export\t"):
            die("dotenv line %d: export form is not allowed" % lineno)
        if "=" not in raw:
            die("dotenv line %d: expected KEY=value" % lineno)
        key, value = raw.split("=", 1)
        if not re.match(r"^[A-Z_][A-Z0-9_]*$", key):
            die("dotenv line %d: bad key" % lineno)
        if key in out:
            die("dotenv duplicate key %s" % key)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if value == "":
            die("dotenv empty value for %s" % key)
        if any(ch in value for ch in ("$", "`", "\n", "\r")):
            die("dotenv unsafe value for %s" % key)
        if key not in ALLOWED:
            if key in IMAGE_OVERRIDE_KEYS:
                die("dotenv rejects image override %s" % key)
            die("dotenv key %s is not allowed" % key)
        _kind(key, value)
        out[key] = value
    return out


def validate_tar(path: str) -> None:
    if os.path.islink(path) or not os.path.isfile(path):
        die("sidecar state must be a regular file")
    try:
        tf = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError) as exc:
        die("sidecar state is not a tar archive: %s" % exc)
    with tf:
        for member in tf.getmembers():
            name = member.name
            if name.startswith("/") or name.startswith("\\") or os.path.isabs(name):
                die("sidecar tar has an absolute member")
            parts = name.replace("\\", "/").split("/")
            if any(part in ("", "..") for part in parts):
                die("sidecar tar member escapes: %s" % name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                die("sidecar tar member is not a regular file: %s" % name)
            if not (member.isfile() or member.isdir()):
                die("sidecar tar member is not a regular file: %s" % name)


def validate_tree(root: str) -> dict:
    if os.path.islink(root) or not os.path.isdir(root):
        die("backup root must be a real directory")
    root = os.path.abspath(root)
    ignored = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames):
            _check_component(name)
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            _check_rel(rel)
            if os.path.islink(path):
                die("symlink in bundle: %s" % rel)
            if not os.path.isdir(path):
                die("special file in bundle: %s" % rel)
            _inside(root, path)
        for name in filenames:
            _check_component(name)
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            _check_rel(rel)
            if os.path.islink(path):
                die("symlink in bundle: %s" % rel)
            if not os.path.isfile(path):
                die("special file in bundle: %s" % rel)
            _inside(root, path)
            if rel == "state/enroll/token-labels.json":
                ignored.append(rel)
    for rel in REQUIRED:
        path = os.path.join(root, rel)
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) == 0:
            die("backup is missing %s" % rel)
    derp = os.path.join(root, "headscale", "derp_server_private.key")
    if os.path.lexists(derp):
        if os.path.islink(derp) or not os.path.isfile(derp) or os.path.getsize(derp) == 0:
            die("backup DERP key is empty")
    sidecar = os.path.join(root, "sidecar", "state.tar")
    if os.path.lexists(sidecar):
        validate_tar(sidecar)
    admin_mode = None
    admin_path = os.path.join(root, "admin-mode")
    if os.path.lexists(admin_path):
        if os.path.islink(admin_path) or not os.path.isfile(admin_path):
            die("backup admin-mode must be a regular file")
        text = open(admin_path, encoding="utf-8").read()
        mode = ""
        for line in text.splitlines():
            if line.startswith("mode="):
                mode = line[len("mode="):].strip()
                break
        if mode not in ("published", "tailnet-admin"):
            die("backup admin-mode is %r" % mode)
        admin_mode = mode
    dotenv = parse_dotenv(open(os.path.join(root, "state", "dotenv"), encoding="utf-8").read())
    return {"dotenv": dotenv, "admin_mode": admin_mode, "ignored": ignored}


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in ("tree", "dotenv"):
        die("usage: bundle.py tree DIR | dotenv FILE")
    if sys.argv[1] == "tree":
        info = validate_tree(sys.argv[2])
    else:
        info = parse_dotenv(open(sys.argv[2], encoding="utf-8").read())
    json.dump(info, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
