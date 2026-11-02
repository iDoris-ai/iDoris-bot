#!/usr/bin/env python3
"""Unit checks for deploy/vpn/enroll_lock.py. No Docker."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from enroll_lock import LeaveUnchanged, locked_update, merge_bootstrap_rows  # noqa: E402


def _config(digest: str) -> dict:
    return {
        "control_url": "https://vpn.example.org",
        "tenants": [{
            "name": "office",
            "headscale_user_id": "1",
            "token_hashes": [{"hash": digest, "label": "bootstrap-office"}],
        }],
    }


class LockedUpdateTest(unittest.TestCase):
    def test_leave_unchanged_keeps_bytes_and_inode(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "config.json"
        path.write_text('{"control_url":"https://vpn.example.org"}\n')
        before = path.stat()

        def mutate(cfg):
            cfg["control_url"] = "https://r4o.example"
            return LeaveUnchanged()

        locked_update(path, mutate)
        after = path.stat()
        self.assertEqual(path.read_text(), '{"control_url":"https://vpn.example.org"}\n')
        self.assertEqual(after.st_ino, before.st_ino)
        lock = Path(str(path) + ".lock")
        self.assertTrue(lock.is_file())
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_rewrite_preserves_mode_and_leaves_no_temp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "config.json"
        path.write_text("{}\n")
        os.chmod(path, 0o640)

        def mutate(cfg):
            cfg["control_url"] = "https://r4o.example"
            return cfg

        locked_update(path, mutate)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertEqual(json.loads(path.read_text())["control_url"], "https://r4o.example")
        leftovers = [name for name in os.listdir(tmp.name) if name.startswith(".enroll-")]
        self.assertEqual(leftovers, [])

    def test_symlink_is_refused(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        target = directory / "real.json"
        target.write_text("{}\n")
        link = directory / "config.json"
        link.symlink_to(target)

        def mutate(cfg):
            return {"control_url": "https://r4o.example"}

        with self.assertRaises(OSError):
            locked_update(link, mutate)
        self.assertEqual(target.read_text(), "{}\n")

    def test_merge_keeps_loaded_hashes(self) -> None:
        digest = "ab" * 32
        extra = "cd" * 32
        cfg = _config(digest)
        merged = merge_bootstrap_rows(
            cfg,
            "https://vpn.example.org",
            "extra|2|tag:member||10m|%s|member\n" % extra,
        )
        self.assertEqual(merged["tenants"][0]["token_hashes"][0]["hash"], digest)
        self.assertEqual(merged["tenants"][1]["name"], "extra")
        self.assertEqual(merged["tenants"][1]["token_hashes"][0]["hash"], extra)
        self.assertEqual(merged["control_url"], "https://vpn.example.org")


if __name__ == "__main__":
    unittest.main()
