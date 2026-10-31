#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["PyYAML==6.0.3"]
# ///
"""Regression tests for external metadata and local build selection."""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import ctf


class ExternalChallengeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "challenges/forensics/external-example"
        self.path.mkdir(parents=True)
        flag = "ccsCTF{fixture}"
        self.meta = {
            "name": "External Example", "author": "fixture", "category": "forensics",
            "description": "An external challenge.", "type": "dynamic", "value": 1000,
            "extra": {"initial": 1000, "minimum": 100},
            "flags": [{"type": "static", "content": flag, "data": "case_sensitive"}],
            "tags": ["easy"], "files": [], "hints": [], "state": "hidden",
            "connection_info": "https://example.org/challenge?file=handout",
        }
        self.deploy = {
            "mode": "external", "protocol": "https", "architecture": "linux/amd64",
            "service": None, "internal_port": None, "public_port": None,
            "solver": "external", "readiness": "Check external site", "reset": "External",
            "state": "External", "ttl_minutes": None, "egress": "HTTPS", "notes": "External",
        }
        (self.path / "flag.txt").write_text(flag + "\n")
        (self.path / "README.md").write_text("External challenge fixture.\n")

    def check(self):
        (self.path / "challenge.yml").write_text(yaml.safe_dump(self.meta))
        (self.path / "deployment.yml").write_text(yaml.safe_dump(self.deploy))
        report = ctf.Report("fixture")
        ctf.check_challenge(self.path, report)
        return report.errors

    def test_external_metadata_needs_no_local_package(self):
        self.assertEqual(self.check(), [])

    def test_external_still_checks_flags_and_handouts(self):
        self.meta["flags"][0]["content"] = "ccsCTF{wrong}"
        self.meta["files"] = ["dist/missing.zip"]
        self.assertGreaterEqual(len(self.check()), 2)

    def test_external_requires_valid_url(self):
        for url in (None, "relative/path", "ftp://example.org", "http://example.org",
                    "https://user:pass@example.org", "https://CHALLENGE_HOST",
                    "https://example.org:bad", "https://example.org/{{secret}}"):
            with self.subTest(url=url):
                self.meta["connection_info"] = url
                self.assertTrue(any("connection_info" in e for e in self.check()))

    def test_external_cannot_declare_local_runtime(self):
        self.deploy.update(service="chall", public_port=35000, solver="automated")
        self.assertGreaterEqual(len(self.check()), 3)

    def test_local_package_requirements_remain(self):
        self.deploy.update(mode="static", protocol="none", solver="automated")
        self.meta.pop("connection_info")
        errors = self.check()
        for name in ("Dockerfile", ".dockerignore", "solve/WRITEUP.md", "solve/solve.py"):
            self.assertIn(f"missing {name}", errors)

    def test_external_skips_local_build_and_solver(self):
        self.assertEqual(self.check(), [])
        args = argparse.Namespace(challenge=str(self.path))
        with patch("ctf.docker", side_effect=AssertionError("Docker called")), \
                patch("ctf.run_solver", side_effect=AssertionError("solver called")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ctf.cmd_dist(args), 0)
            self.assertEqual(ctf.cmd_test(args), 0)

    def test_changed_excludes_only_external(self):
        self.assertEqual(self.check(), [])
        local = self.path.with_name("local-example")
        local.mkdir()
        (local / "deployment.yml").write_text("mode: static\n")
        output = io.StringIO()
        with patch("ctf.ROOT", Path(self.tmp.name)), \
                patch("ctf.all_challenges", return_value=[self.path, local]), \
                contextlib.redirect_stdout(output):
            self.assertEqual(ctf.cmd_changed(argparse.Namespace(base=None)), 0)
        self.assertEqual([row["name"] for row in json.loads(output.getvalue())],
                         ["forensics/local-example"])


if __name__ == "__main__":
    unittest.main()
