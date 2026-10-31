#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["PyYAML==6.0.3"]
# ///
"""Challenge repository tooling for CCS Halloween CTF 2026.

  uv run tools/ctf.py check [CHALLENGE ...]        static checks from docs/RULES.md
  uv run tools/ctf.py dist CHALLENGE [--verify]    export dist/, or compare a fresh export with it
  uv run tools/ctf.py test CHALLENGE [--port N]    run the solver and compare with flag.txt
  uv run tools/ctf.py changed [--base REF]         list challenges changed since REF (JSON)

CHALLENGE is a path such as challenges/web/piggyback. Flags are never printed.
"""

import argparse
from datetime import datetime
import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is missing: run this tool with `uv run tools/ctf.py ...`")

ROOT = Path(__file__).resolve().parents[1]
CHALLENGES = ROOT / "challenges"

CATEGORIES = ("pwn", "web", "crypto", "rev", "forensics", "misc", "osint")
PORT_RANGES = {
    "pwn": (31000, 31999),
    "web": (32000, 32999),
    "crypto": (33000, 33999),
    "rev": (34000, 34999),
    "misc": (35000, 35999),
    "forensics": (35000, 35999),
    "osint": (35000, 35999),
}
DIFFICULTIES = ("baby", "easy", "medium", "hard", "insane")
SCORING = {"initial": 1000, "minimum": 100}
FLAG_RE = re.compile(r"^ccsCTF\{[A-Za-z0-9_!?@#$%^&*.\-]+\}$")
SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
DIST_LIMIT = 50 * 1024 * 1024
DIST_IGNORED = {".gitkeep"}
DEPLOYMENT_KEYS = ("mode", "protocol", "architecture", "service", "internal_port", "public_port",
                   "solver", "readiness", "reset", "state", "ttl_minutes", "egress", "notes")
SOLVE_TIMEOUT = 60


class Report:
    def __init__(self, name):
        self.name = name
        self.errors = []
        self.warnings = []

    def error(self, msg):
        self.errors.append(msg)

    def warn(self, msg):
        self.warnings.append(msg)


def die(msg):
    sys.exit(f"error: {msg}")


def all_challenges():
    return sorted(p.parent for p in CHALLENGES.glob("*/*/challenge.yml"))


def resolve_challenge(arg):
    path = Path(arg).resolve()
    if not (path / "challenge.yml").is_file():
        die(f"{arg} is not a challenge directory (no challenge.yml)")
    return path


def rel(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_yaml(path, report):
    try:
        data = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        report.error(f"{path.name}: cannot parse ({exc.__class__.__name__})")
        return None
    if not isinstance(data, dict):
        report.error(f"{path.name}: expected a mapping")
        return None
    return data


def read_flag(chall):
    path = chall / "flag.txt"
    if not path.is_file():
        return None
    lines = path.read_text().splitlines()
    return lines[0].strip() if len(lines) == 1 else None


def dist_files(chall):
    dist = chall / "dist"
    if not dist.is_dir():
        return []
    return sorted(p for p in dist.rglob("*") if p.is_file() and p.name not in DIST_IGNORED)


def archive_members(path):
    """Yield (name, bytes) for members of zip/tar archives, one level deep."""
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if not info.is_dir():
                        yield info.filename, zf.read(info)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                for member in tf.getmembers():
                    if member.isfile():
                        fh = tf.extractfile(member)
                        if fh:
                            yield member.name, fh.read()
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
        return


# --------------------------------------------------------------------------- check


def check_challenge(chall, report):
    category, slug = chall.parent.name, chall.name
    if category not in CATEGORIES:
        report.error(f"unknown category directory '{category}'")
    if not SLUG_RE.match(slug):
        report.error(f"slug '{slug}' must be lowercase words separated by hyphens")

    meta = load_yaml(chall / "challenge.yml", report)
    deploy = load_yaml(chall / "deployment.yml", report) if (chall / "deployment.yml").is_file() else None
    if deploy is None and not (chall / "deployment.yml").is_file():
        report.error("missing deployment.yml")

    mode = (deploy or {}).get("mode")
    solver = (deploy or {}).get("solver")
    required = ["README.md", "Dockerfile", ".dockerignore", "flag.txt", "solve/WRITEUP.md"]
    if solver != "manual":
        required.append("solve/solve.py")
    if mode in ("shared", "per-team"):
        required.append("docker-compose.yml")
    for name in required:
        if not (chall / name).is_file():
            report.error(f"missing {name}")

    flag = read_flag(chall)
    if (chall / "flag.txt").is_file():
        if flag is None:
            report.error("flag.txt must contain exactly one line")
        elif not FLAG_RE.match(flag):
            report.error("flag.txt does not match the ccsCTF{...} flag format")

    check_dockerignore(chall, report)
    check_dockerfile(chall, report)
    if meta is not None:
        check_metadata(chall, meta, deploy, flag, report)
    if deploy is not None:
        check_deployment(chall, deploy, report)
        if mode in ("shared", "per-team") and (chall / "docker-compose.yml").is_file():
            check_compose(chall, deploy, report)
    check_dist(chall, meta, report)
    check_private_leaks(chall, flag, report)
    return meta, deploy


def check_dockerignore(chall, report):
    path = chall / ".dockerignore"
    if not path.is_file():
        return
    entries = {line.strip().strip("/") for line in path.read_text().splitlines()}
    for needed in ("solve", ".git"):
        if needed not in entries:
            report.error(f".dockerignore must exclude {needed}/")


def check_dockerfile(chall, report):
    path = chall / "Dockerfile"
    if not path.is_file():
        return
    text = path.read_text()
    if not re.search(r"^FROM\s+\S+\s+AS\s+dist\s*$", text, re.M | re.I):
        report.error("Dockerfile has no 'AS dist' stage")
    stages = set(re.findall(r"^FROM\s+\S+\s+AS\s+(\S+)", text, re.M | re.I))
    for image in re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M | re.I):
        if image == "scratch" or image in stages:
            continue
        if "@sha256:" not in image:
            report.error(f"Dockerfile base image '{image}' is not pinned by @sha256 digest")


def check_metadata(chall, meta, deploy, flag, report):
    category = chall.parent.name
    for key in ("name", "author", "category", "description", "type", "value",
                "flags", "tags", "state"):
        if key not in meta:
            report.error(f"challenge.yml: missing '{key}'")
    if meta.get("category") != category:
        report.error(f"challenge.yml: category '{meta.get('category')}' does not match directory '{category}'")
    if meta.get("state") not in ("hidden", "visible"):
        report.error("challenge.yml: state must be 'hidden' or 'visible'")
    if meta.get("state") == "visible" and not meta.get("release_time"):
        report.error("challenge.yml: visible challenges require an organizer-set release_time")
    if meta.get("release_time"):
        try:
            release = meta["release_time"]
            release = datetime.fromisoformat(release) if isinstance(release, str) else release
            if not isinstance(release, datetime) or release.tzinfo is None:
                raise ValueError
        except (TypeError, ValueError):
            report.error("challenge.yml: release_time must be an ISO datetime with a timezone")
    if meta.get("type") != "dynamic":
        report.error("challenge.yml: type must be 'dynamic'")
    extra = meta.get("extra") or {}
    if "decay" in extra or "function" in extra:
        report.error("challenge.yml: configure decay in rCTF's server scoreProvider, not extra")
    for key, expected in SCORING.items():
        if extra.get(key) != expected:
            report.warn(f"challenge.yml: extra.{key} is {extra.get(key)!r}, event policy is {expected}")
    if meta.get("value") != SCORING["initial"]:
        report.warn(f"challenge.yml: value should equal extra.initial ({SCORING['initial']})")

    tags = meta.get("tags") or []
    difficulty = [t for t in tags if t in DIFFICULTIES]
    if len(difficulty) != 1:
        report.error(f"challenge.yml: needs exactly one difficulty tag from {', '.join(DIFFICULTIES)}")

    flags = meta.get("flags") or []
    if not flags:
        report.error("challenge.yml: no flags")
    has_regex = False
    static_values = []
    for entry in flags:
        if isinstance(entry, str):
            entry = {"type": "static", "content": entry}
        kind = entry.get("type", "static")
        content = str(entry.get("content", ""))
        if kind == "static":
            static_values.append(content)
            if not FLAG_RE.match(content):
                report.error("challenge.yml: a static flag does not match the ccsCTF{...} flag format")
            if entry.get("data") != "case_sensitive":
                report.warn("challenge.yml: static flags should use data: case_sensitive")
        elif kind == "regex":
            has_regex = True
            if not (content.startswith("^") and content.endswith("$")):
                report.error("challenge.yml: regex flags must be anchored with ^ and $")
            elif flag is not None and not re.match(content, flag):
                report.error("challenge.yml: regex flag does not accept the value in flag.txt")
        else:
            report.error(f"challenge.yml: unsupported flag type '{kind}'")
    if flag is not None and static_values and flag not in static_values:
        report.error("challenge.yml: no static flag matches flag.txt")
    if flag is not None and not static_values and not has_regex:
        report.error("challenge.yml: flag.txt is not accepted by any flag entry")

    files = meta.get("files") or []
    seen = set()
    for name in files:
        if name in seen:
            report.error(f"challenge.yml: '{name}' listed twice in files")
        seen.add(name)
        if not str(name).startswith("dist/"):
            report.error(f"challenge.yml: file '{name}' is not under dist/")
        elif not (chall / name).is_file():
            report.error(f"challenge.yml: file '{name}' does not exist (build and commit dist/)")
    listed = {(chall / n).resolve() for n in files}
    for path in dist_files(chall):
        if path.resolve() not in listed:
            report.error(f"dist/: '{rel(path)}' is not listed in challenge.yml files")

    if deploy is not None:
        check_connection_info(meta, deploy, report)


def check_connection_info(meta, deploy, report):
    info = meta.get("connection_info")
    protocol, port = deploy.get("protocol"), deploy.get("public_port")
    if deploy.get("mode") == "static":
        if info:
            report.error("challenge.yml: static challenges must omit connection_info")
        return
    expected = {
        "http": f"http://CHALLENGE_HOST:{port}",
        "https": f"https://CHALLENGE_HOST:{port}",
        "tcp": f"CHALLENGE_HOST:{port}" if deploy.get("service") == "minecraft" else f"nc CHALLENGE_HOST {port}",
    }.get(protocol)
    if deploy.get("mode") == "per-team":
        if not info:
            report.warn("challenge.yml: per-team challenges should explain how to start an instance")
    elif expected and info != expected:
        report.error(f"challenge.yml: connection_info should be '{expected}'")


def check_deployment(chall, deploy, report):
    for key in DEPLOYMENT_KEYS:
        if key not in deploy:
            report.error(f"deployment.yml: missing '{key}'")
    mode, protocol = deploy.get("mode"), deploy.get("protocol")
    if mode not in ("static", "shared", "per-team"):
        report.error("deployment.yml: mode must be static, shared, or per-team")
    if protocol not in ("none", "tcp", "http", "https"):
        report.error("deployment.yml: protocol must be none, tcp, http, or https")
    if deploy.get("solver") not in ("automated", "manual"):
        report.error("deployment.yml: solver must be automated or manual")
    if deploy.get("architecture") != "linux/amd64":
        report.warn("deployment.yml: architecture other than linux/amd64 needs infra approval")
    if mode == "static":
        if protocol != "none":
            report.error("deployment.yml: static challenges use protocol: none")
        for key in ("service", "internal_port", "public_port"):
            if deploy.get(key) is not None:
                report.error(f"deployment.yml: static challenges use {key}: null")
    elif mode in ("shared", "per-team"):
        if protocol == "none":
            report.error("deployment.yml: hosted challenges need protocol tcp, http, or https")
        for key in ("service", "internal_port", "public_port"):
            if deploy.get(key) is None:
                report.error(f"deployment.yml: hosted challenges need {key}")
        port = deploy.get("public_port")
        low, high = PORT_RANGES.get(chall.parent.name, (0, 0))
        if isinstance(port, int) and not low <= port <= high:
            report.error(f"deployment.yml: public_port {port} outside {chall.parent.name} range {low}-{high}")
    if mode == "per-team" and not isinstance(deploy.get("ttl_minutes"), int):
        report.error("deployment.yml: per-team challenges need an integer ttl_minutes")


def check_compose(chall, deploy, report):
    compose = load_yaml(chall / "docker-compose.yml", report)
    if compose is None:
        return
    services = compose.get("services") or {}
    service = deploy.get("service")
    if service not in services:
        report.error(f"docker-compose.yml: service '{service}' from deployment.yml not found")
    expected_port = (f"${{BIND_ADDR:-127.0.0.1}}:${{PUBLIC_PORT:-{deploy.get('public_port')}}}"
                     f":{deploy.get('internal_port')}")
    published = []
    jail = chall.parent.name == "pwn"
    for name, svc in services.items():
        svc = svc or {}
        for port in svc.get("ports") or []:
            published.append((name, str(port)))
        for key in ("container_name",):
            if key in svc:
                report.error(f"docker-compose.yml: {name} must not set {key}")
        if svc.get("network_mode") == "host" or svc.get("pid") == "host":
            report.error(f"docker-compose.yml: {name} must not use the host network or PID namespace")
        if svc.get("privileged") and not jail:
            report.error(f"docker-compose.yml: {name} is privileged; only redpwn/jail may be")
        for volume in svc.get("volumes") or []:
            source = volume.get("source", "") if isinstance(volume, dict) else str(volume).split(":")[0]
            if source.startswith(("/", ".", "~")) or "docker.sock" in str(volume):
                report.error(f"docker-compose.yml: {name} uses a bind mount ({source})")
        for key in ("mem_limit", "cpus", "pids_limit"):
            if key not in svc:
                report.error(f"docker-compose.yml: {name} has no {key}")
        if not svc.get("privileged"):
            if svc.get("user") in (None, "0", "root", "0:0"):
                report.warn(f"docker-compose.yml: {name} should run as a non-root user")
            if "ALL" not in (svc.get("cap_drop") or []):
                report.warn(f"docker-compose.yml: {name} should cap_drop ALL")
            if "no-new-privileges:true" not in (svc.get("security_opt") or []):
                report.warn(f"docker-compose.yml: {name} should set no-new-privileges")
    for key in ("networks", "volumes"):
        for name, spec in (compose.get(key) or {}).items():
            if isinstance(spec, dict) and (spec.get("external") or spec.get("name")):
                report.error(f"docker-compose.yml: {key[:-1]} '{name}' must be project-scoped (no external/name)")
    if len(published) != 1:
        report.error(f"docker-compose.yml: expected exactly one published port, found {len(published)}")
    elif published[0][0] != service or published[0][1] != expected_port:
        report.error(f"docker-compose.yml: published port should be \"{expected_port}\" on service '{service}'")


def check_dist(chall, meta, report):
    files = dist_files(chall)
    total = sum(p.stat().st_size for p in files)
    if total > DIST_LIMIT:
        report.error(f"dist/: {total // (1024 * 1024)} MB exceeds the 50 MB handout limit")
    flag = read_flag(chall)
    private = [chall / "solve" / "solve.py", chall / "solve" / "WRITEUP.md", chall / "README.md"]
    private_bytes = {p.name: p.read_bytes() for p in private if p.is_file() and p.stat().st_size > 64}
    for path in files:
        name = rel(path)
        if path.name in ("solve.py", "WRITEUP.md") or "/.git/" in name:
            report.error(f"dist/: '{name}' looks like private material")
        data = path.read_bytes()
        if flag and flag.encode() in data:
            report.error(f"dist/: '{name}' contains the real flag in plaintext")
        for pname, pdata in private_bytes.items():
            if pdata == data:
                report.error(f"dist/: '{name}' is a copy of private {pname}")
        for member, mdata in archive_members(path):
            if flag and flag.encode() in mdata:
                report.error(f"dist/: '{name}' member '{member}' contains the real flag in plaintext")
            if Path(member).name in ("solve.py", "WRITEUP.md"):
                report.error(f"dist/: '{name}' member '{member}' looks like private material")


def check_private_leaks(chall, flag, report):
    if not flag:
        return
    for name in ("solve/solve.py", "solve/WRITEUP.md", "README.md", "deployment.yml", "docker-compose.yml"):
        path = chall / name
        if path.is_file() and flag in path.read_text(errors="replace"):
            report.error(f"{name} contains the real flag; keep it only in flag.txt and challenge.yml")
    for path in chall.rglob("Dockerfile*"):
        if "dist" in path.relative_to(chall).parts:
            continue
        if flag in path.read_text(errors="replace"):
            report.error(f"{rel(path)} contains the real flag; COPY flag.txt instead")


def repo_files():
    listing = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=ROOT, capture_output=True, text=True)
    if listing.returncode == 0:
        return [Path(p) for p in listing.stdout.splitlines() if (ROOT / p).exists()]
    return [p.relative_to(ROOT) for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]


def check_layout(report):
    """Challenge files must live in challenges/<category>/<slug>/ and every such directory needs challenge.yml."""
    markers = ("challenge.yml", "deployment.yml", "docker-compose.yml", "flag.txt", "Dockerfile")
    misplaced = set()
    for path in repo_files():
        parts = path.parts
        # Deployment and instance-manager files are infrastructure, not challenges.
        if parts[0] == "deployment":
            continue
        in_challenge = len(parts) >= 4 and parts[0] == "challenges" and parts[1] in CATEGORIES
        if parts[0] in CATEGORIES or (len(parts) >= 2 and parts[0] == "challenges" and parts[1] not in CATEGORIES):
            misplaced.add(Path(*parts[:2]) if parts[0] == "challenges" else Path(parts[0]))
        elif path.name in markers and not in_challenge:
            misplaced.add(path)
    for path in sorted(misplaced):
        report.error(f"'{path}' is outside challenges/<category>/<slug>/ (categories: {', '.join(CATEGORIES)})")
    for category in CATEGORIES:
        for chall in sorted((CHALLENGES / category).glob("*/")):
            if not (chall / "challenge.yml").is_file() and any(p.name != ".gitkeep" for p in chall.rglob("*") if p.is_file()):
                report.error(f"'{rel(chall)}' has files but no challenge.yml, so nothing else is checked")


def cmd_check(args):
    targets = [resolve_challenge(a) for a in args.challenges] or all_challenges()
    if not targets:
        die("no challenges found")
    layout = Report("repository layout")
    check_layout(layout)
    reports, ports, names = [layout], {}, {}
    for chall in targets:
        report = Report(rel(chall))
        meta, deploy = check_challenge(chall, report)
        reports.append(report)
        if deploy and isinstance(deploy.get("public_port"), int):
            ports.setdefault(deploy["public_port"], []).append(report)
        names.setdefault(chall.name, []).append(report)
        if meta and meta.get("name"):
            names.setdefault(f"name:{meta['name']}", []).append(report)
    # Uniqueness is repository-wide, so compare against every challenge, not just the targets.
    if args.challenges:
        for chall in all_challenges():
            if chall in targets:
                continue
            deploy = yaml.safe_load((chall / "deployment.yml").read_text()) if (chall / "deployment.yml").is_file() else {}
            if isinstance((deploy or {}).get("public_port"), int):
                ports.setdefault(deploy["public_port"], []).append(Report(rel(chall)))
            names.setdefault(chall.name, []).append(Report(rel(chall)))
    for port, owners in ports.items():
        if len(owners) > 1:
            for report in owners:
                report.error(f"public_port {port} also used by " + ", ".join(o.name for o in owners if o is not report))
    for key, owners in names.items():
        if len(owners) > 1:
            what = "name" if key.startswith("name:") else "slug"
            for report in owners:
                report.error(f"{what} is not unique: also " + ", ".join(o.name for o in owners if o is not report))

    failed = 0
    for report in reports:
        status = "FAIL" if report.errors else ("WARN" if report.warnings else "ok")
        print(f"[{status:>4}] {report.name}")
        for msg in report.errors:
            print(f"       error: {msg}")
            if os.environ.get("GITHUB_ACTIONS"):
                where = f"file={report.name}/challenge.yml," if report is not layout else ""
                print(f"::error {where}title=ctf.py check::{msg}")
        for msg in report.warnings:
            print(f"       warn:  {msg}")
        failed += bool(report.errors)
    print(f"\n{len(reports) - 1} challenge(s) checked, {failed} failed")
    return 1 if failed else 0


# --------------------------------------------------------------------------- dist


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], **kwargs)


def build_dist(chall, dest):
    result = docker("build", "--platform", "linux/amd64", "--target", "dist",
                    "--output", f"type=local,dest={dest}", ".", cwd=chall)
    if result.returncode:
        die(f"docker build failed for {rel(chall)}")


def cmd_dist(args):
    chall = resolve_challenge(args.challenge)
    dist = chall / "dist"
    with tempfile.TemporaryDirectory(prefix="ctf-dist-") as tmp:
        build_dist(chall, tmp)
        fresh = Path(tmp)
        fresh_files = {p.relative_to(fresh) for p in fresh.rglob("*") if p.is_file()}
        committed = {p.relative_to(dist) for p in dist_files(chall)}
        if args.verify:
            problems = []
            for name in sorted(fresh_files - committed):
                problems.append(f"missing from committed dist/: {name}")
            for name in sorted(committed - fresh_files):
                problems.append(f"stale in committed dist/: {name}")
            for name in sorted(fresh_files & committed):
                if not filecmp.cmp(fresh / name, dist / name, shallow=False):
                    problems.append(f"differs from a fresh build: {name}")
            for msg in problems:
                print(f"error: {msg}")
            print(f"{rel(chall)}: dist/ {'is out of date' if problems else 'matches a fresh build'}")
            return 1 if problems else 0
        for name in sorted(committed - fresh_files):
            (dist / name).unlink()
            print(f"removed stale dist/{name}")
        for name in sorted(fresh_files):
            target = dist / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(fresh / name, target)
            print(f"wrote dist/{name}")
    for directory in sorted((p for p in dist.rglob("*") if p.is_dir()), reverse=True):
        if not any(directory.iterdir()):
            directory.rmdir()
    print("Inspect dist/ before committing, then run: uv run tools/ctf.py check " + rel(chall))
    return 0


# --------------------------------------------------------------------------- test


def accepts(meta, value):
    for entry in meta.get("flags") or []:
        if isinstance(entry, str):
            entry = {"type": "static", "content": entry}
        content = str(entry.get("content", ""))
        if entry.get("type", "static") == "static" and value == content:
            return True
        if entry.get("type") == "regex" and re.match(content, value):
            return True
    return False


def run_solver(chall, extra_args, flag, meta):
    solver = chall / "solve" / "solve.py"
    try:
        # Solvers declare their dependencies inline (PEP 723); uv installs them in a cached env.
        result = subprocess.run(["uv", "run", "--quiet", "--script", str(solver), *extra_args], cwd=chall / "solve",
                                capture_output=True, text=True, timeout=SOLVE_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"FAIL: solver exceeded {SOLVE_TIMEOUT} seconds")
        return False
    found = re.findall(r"ccsCTF\{[^}\s]+\}", result.stdout)
    redact = (lambda s: s.replace(flag, "<flag>")) if flag else (lambda s: s)
    if result.returncode != 0:
        print(f"FAIL: solver exited {result.returncode}")
        print(redact(result.stderr[-2000:]))
        return False
    if not found:
        print("FAIL: solver printed no ccsCTF{...} flag")
        print(redact(result.stderr[-2000:]))
        return False
    if flag and found[-1] == flag or not flag and accepts(meta, found[-1]):
        print("PASS: solver recovered the expected flag")
        return True
    print("FAIL: solver printed a flag that does not match flag.txt")
    return False


def cmd_test(args):
    chall = resolve_challenge(args.challenge)
    report = Report(rel(chall))
    meta = load_yaml(chall / "challenge.yml", report)
    deploy = load_yaml(chall / "deployment.yml", report)
    if report.errors:
        die("; ".join(report.errors))
    if deploy.get("solver") == "manual":
        print("SKIP: solver: manual; follow solve/WRITEUP.md")
        return 0
    flag = read_flag(chall)
    if flag and os.environ.get("GITHUB_ACTIONS"):
        print(f"::add-mask::{flag}")
    if deploy.get("mode") == "static":
        return 0 if run_solver(chall, [], flag, meta) else 1

    port = args.port or deploy.get("public_port")
    project = f"ccs-test-{chall.parent.name}-{chall.name}"
    env = dict(os.environ, PUBLIC_PORT=str(port), BIND_ADDR="127.0.0.1")
    compose = ["compose", "-p", project]
    ok = False
    try:
        up = docker(*compose, "up", "-d", "--build", "--wait", "--wait-timeout", str(args.wait), cwd=chall, env=env)
        if up.returncode:
            print("FAIL: services did not become healthy")
            docker(*compose, "logs", "--tail=50", cwd=chall, env=env)
            return 1
        ok = run_solver(chall, ["127.0.0.1", str(port)], flag, meta)
        if not ok:
            logs = docker(*compose, "logs", "--tail=50", cwd=chall, env=env, capture_output=True, text=True)
            print(logs.stdout.replace(flag, "<flag>") if flag else logs.stdout)
    finally:
        if not args.keep:
            docker(*compose, "down", "--volumes", "--remove-orphans", cwd=chall, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0 if ok else 1


# --------------------------------------------------------------------------- changed


def cmd_changed(args):
    base = args.base
    if base and set(base) != {"0"}:
        diff = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"], cwd=ROOT,
                              capture_output=True, text=True)
        if diff.returncode == 0:
            paths = diff.stdout.split()
        else:
            print(f"warning: cannot diff against {base}; selecting all challenges", file=sys.stderr)
            paths = None
    else:
        paths = None

    challs = all_challenges()
    if paths is not None and any(p.startswith(("tools/", ".github/workflows/")) for p in paths):
        paths = None
    if paths is not None:
        touched = {Path(*Path(p).parts[:3]) for p in paths if p.startswith("challenges/") and len(Path(p).parts) > 3}
        challs = [c for c in challs if c.relative_to(ROOT) in touched]

    rows = []
    for chall in challs:
        deploy = yaml.safe_load((chall / "deployment.yml").read_text()) if (chall / "deployment.yml").is_file() else {}
        compose = chall / "docker-compose.yml"
        jail = compose.is_file() and "privileged: true" in compose.read_text()
        rows.append({
            "path": str(chall.relative_to(ROOT)),
            "name": f"{chall.parent.name}/{chall.name}",
            "mode": (deploy or {}).get("mode"),
            "jail": jail,
        })
    print(json.dumps(rows))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="static checks from docs/RULES.md")
    p.add_argument("challenges", nargs="*")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("dist", help="export dist/ with the Dockerfile's dist stage")
    p.add_argument("challenge")
    p.add_argument("--verify", action="store_true", help="compare a fresh export with committed dist/")
    p.set_defaults(func=cmd_dist)

    p = sub.add_parser("test", help="start the challenge and run its solver")
    p.add_argument("challenge")
    p.add_argument("--port", type=int, help="host port to publish (default: public_port)")
    p.add_argument("--wait", type=int, default=180, help="seconds to wait for healthy services")
    p.add_argument("--keep", action="store_true", help="leave the Compose project running")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("changed", help="JSON list of challenges changed since --base")
    p.add_argument("--base", help="git ref to diff against; omitted selects all")
    p.set_defaults(func=cmd_changed)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
