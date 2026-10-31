#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["PyYAML==6.0.3"]
# ///
"""Select Konata configs using trusted GitHub Actions job results."""

import json
import os
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def select_challenges(root, run, pages, sha, repository):
    if (run.get("head_sha") != sha or run.get("head_branch") != "main"
            or (run.get("head_repository") or {}).get("full_name") != repository
            or run.get("event") not in {"push", "workflow_dispatch"}
            or run.get("status") != "completed"
            or run.get("conclusion") not in {"success", "failure"}):
        raise ValueError("Require completed Challenges checks for this repository's main commit")

    jobs = {}
    for page in pages:
        for job in page["jobs"]:
            # Keep the newest result if the API includes more than one attempt.
            if job["name"] not in jobs or job["id"] > jobs[job["name"]]["id"]:
                jobs[job["name"]] = job

    def passed(name):
        job = jobs.get(name, {})
        return job.get("status") == "completed" and job.get("conclusion") == "success"

    for name in ("Check metadata and handouts", "Select changed challenges"):
        if not passed(name):
            raise ValueError(f"Required shared check did not pass: {name}")

    selected, skipped = [], []
    for config in sorted(root.glob("challenges/*/*/kona.yaml")):
        path = config.parent.relative_to(root).as_posix()
        if not re.fullmatch(r"challenges/[a-z0-9_-]+/[a-z0-9_-]+", path):
            raise ValueError(f"Unsupported challenge path: {path}")
        deployment = yaml.safe_load((config.parent / "deployment.yml").read_text()) or {}
        name = "Test " + path.removeprefix("challenges/")
        # External challenges deliberately have no local build/solver job.
        # Shared validation checks their metadata, flags, and handouts.
        external = deployment.get("mode") == "external" and name not in jobs
        (selected if passed(name) or external else skipped).append(path)
    return selected, skipped


def main():
    run = json.loads(Path(sys.argv[1]).read_text())
    pages = json.loads(Path(sys.argv[2]).read_text())
    selected, skipped = select_challenges(ROOT, run, pages, os.environ["TARGET_SHA"],
                                          os.environ["GH_REPO"])
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write("challenges=" + json.dumps(selected) + "\n")
    print(f"Selected {len(selected)} challenges for sync.")
    for path in skipped:
        print(f"Skipping {path}: no successful build and solver job in this run.")


if __name__ == "__main__":
    main()
