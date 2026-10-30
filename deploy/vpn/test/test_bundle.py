#!/usr/bin/env python3
"""Bundle tree and dotenv checks. These call bundle.py, not a mock of it."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "bundle.py"


def run_bundle(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(BUNDLE), *args], capture_output=True, text=True)


def seed(root: Path) -> None:
    files = {
        "manifest.json": "{}\n",
        "headscale/db.sqlite": "sqlite-bytes",
        "headscale/noise_private.key": "noise",
        "state/enroll/config.json": "{}\n",
        "state/enroll/headscale.apikey": "hskey-api-test",
        "state/headplane/cookie_secret": "0123456789abcdef0123456789abcdef",
        "state/dotenv": "COMPOSE_PROJECT_NAME=idoris-vpn-r2d\nHEADPLANE_PORT=3000\n",
        "state/headscale/managed.json": "{}\n",
        "state/headscale/config.yaml": "server_url: https://vpn.example.test\n",
        "state/headscale/policy.hujson": "{}\n",
        "state/headplane/config.yaml": "server:\n  base_url: http://127.0.0.1:3000\n",
        "state/compose.yaml": "name: idoris-vpn\n",
        "admin-mode": "mode=published\n",
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


class BundleTreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "bundle"
        self.root.mkdir()
        seed(self.root)

    def test_accepts_a_regular_tree(self) -> None:
        got = run_bundle("tree", str(self.root))
        self.assertEqual(got.returncode, 0, got.stderr)
        info = json.loads(got.stdout)
        self.assertEqual(info["dotenv"]["COMPOSE_PROJECT_NAME"], "idoris-vpn-r2d")
        self.assertEqual(info["admin_mode"], "published")

    def test_rejects_symlink(self) -> None:
        os.symlink("/etc/passwd", self.root / "state" / "escape")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("symlink", got.stderr)

    def test_rejects_fifo(self) -> None:
        fifo = self.root / "state" / "pipe"
        os.mkfifo(fifo)
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("special", got.stderr)

    def test_rejects_empty_derp_key(self) -> None:
        (self.root / "headscale" / "derp_server_private.key").write_text("")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("DERP", got.stderr)

    def test_rejects_image_override_and_unknown_key(self) -> None:
        dotenv = self.root / "state" / "dotenv"
        dotenv.write_text(dotenv.read_text() + "ENROLL_IMAGE=evil:latest\n")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("image override", got.stderr)
        dotenv.write_text("COMPOSE_PROJECT_NAME=idoris-vpn-r2d\nNOT_A_KEY=1\n")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("not allowed", got.stderr)

    def test_token_labels_regular_file_is_ignored(self) -> None:
        path = self.root / "state" / "enroll" / "token-labels.json"
        path.write_text("{}\n")
        got = run_bundle("tree", str(self.root))
        self.assertEqual(got.returncode, 0, got.stderr)
        info = json.loads(got.stdout)
        self.assertIn("state/enroll/token-labels.json", info["ignored"])

    def test_token_labels_symlink_is_rejected(self) -> None:
        os.symlink("/tmp", self.root / "state" / "enroll" / "token-labels.json")
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("symlink", got.stderr)

    def test_rejects_uid_zero(self) -> None:
        (self.root / "state" / "dotenv").write_text(
            "COMPOSE_PROJECT_NAME=idoris-vpn-r2d\nENROLL_UID=0\nENROLL_GID=65532\n"
        )
        got = run_bundle("tree", str(self.root))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("ENROLL_UID", got.stderr)


class DotenvTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(
                "\n# comment\nHEADPLANE_BIND=127.0.0.1\n"
                "HEADPLANE_ACCESS=tunnel\nENROLL_PUBLIC_URL=https://enroll.example.test\n"
            )
            name = fh.name
        self.addCleanup(lambda: os.unlink(name))
        got = run_bundle("dotenv", name)
        self.assertEqual(got.returncode, 0, got.stderr)
        info = json.loads(got.stdout)
        self.assertEqual(info["HEADPLANE_BIND"], "127.0.0.1")
        self.assertEqual(info["HEADPLANE_ACCESS"], "tunnel")


if __name__ == "__main__":
    unittest.main()
