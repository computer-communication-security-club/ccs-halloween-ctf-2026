#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["PyYAML==6.0.3"]
# ///
"""Regression coverage for partial deployment after challenge test failures."""

import tempfile
import unittest
from pathlib import Path

from select_konata import select_challenges


class SelectionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.run = {"head_sha": "abc", "head_branch": "main",
                    "head_repository": {"full_name": "org/repo"}, "event": "push",
                    "status": "completed", "conclusion": "failure"}
        self.pages = [{"jobs": []}]
        self.job("Check metadata and handouts")
        self.job("Select changed challenges")

    def job(self, name, conclusion="success", status="completed"):
        self.pages[-1]["jobs"].append({"name": name, "conclusion": conclusion,
                                      "status": status,
                                      "id": sum(len(p["jobs"]) for p in self.pages) + 1})

    def challenge(self, slug, mode="static"):
        path = self.root / "challenges/web" / slug
        path.mkdir(parents=True)
        (path / "kona.yaml").touch()
        (path / "deployment.yml").write_text(f"mode: {mode}\n")
        return f"challenges/web/{slug}"

    def select(self):
        return select_challenges(self.root, self.run, self.pages, "abc", "org/repo")

    def test_mixed_results_and_pagination(self):
        good = self.challenge("good")
        bad = self.challenge("bad")
        self.job("Test web/bad", "failure")
        self.pages.append({"jobs": []})
        self.job("Test web/good")
        self.assertEqual(self.select(), ([good], [bad]))

    def test_unsuccessful_or_missing_tests_are_skipped(self):
        paths = []
        for conclusion in ("failure", "cancelled", "skipped", "timed_out", "neutral"):
            paths.append(self.challenge(conclusion))
            self.job(f"Test web/{conclusion}", conclusion)
        paths.append(self.challenge("missing"))
        paths.append(self.challenge("running"))
        self.job("Test web/running", None, "in_progress")
        self.assertEqual(self.select(), ([], sorted(paths)))

    def test_external_challenges_need_no_solver_but_failures_are_not_ignored(self):
        external = self.challenge("external", "external")
        bad = self.challenge("bad", "external")
        self.job("Test web/bad", "failure")
        self.assertEqual(self.select(), ([external], [bad]))

    def test_shared_checks_must_pass(self):
        for name in ("Check metadata and handouts", "Select changed challenges"):
            with self.subTest(name=name):
                self.job(name, "failure")
                with self.assertRaisesRegex(ValueError, "Required shared check"):
                    self.select()
                self.job(name)

    def test_missing_shared_checks_block_sync(self):
        self.pages = [{"jobs": []}]
        with self.assertRaisesRegex(ValueError, "Required shared check"):
            self.select()

    def test_latest_attempt_wins(self):
        path = self.challenge("retry")
        self.job("Test web/retry")
        self.job("Test web/retry", "failure")
        self.assertEqual(self.select(), ([], [path]))
        self.job("Test web/retry")
        self.assertEqual(self.select(), ([path], []))

    def test_invalid_run_cannot_authorize_sync(self):
        for key, value in (("head_sha", "old"), ("head_branch", "feature"),
                           ("head_repository", {"full_name": "fork/repo"}),
                           ("event", "pull_request"), ("status", "in_progress"),
                           ("conclusion", "cancelled")):
            with self.subTest(key=key):
                original = self.run[key]
                self.run[key] = value
                with self.assertRaisesRegex(ValueError, "Require completed"):
                    self.select()
                self.run[key] = original


if __name__ == "__main__":
    unittest.main()
