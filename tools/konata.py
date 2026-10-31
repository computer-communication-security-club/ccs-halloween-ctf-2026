#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["konata==0.0.33", "PyYAML==6.0.3"]
# ///
"""Generate (--write) or check Konata configs against the canonical challenge.yml files.

Checks use Konata's schema, flag resolver, attachment resolver, and templates
offline. They never connect to rCTF, build images, or print flags.
"""

import argparse
import sys
import tempfile
from pathlib import Path

import yaml
from kona.core.provide import resolve_attachments
from kona.schema.models import KonaChallengeConfig, KonaGlobalConfig, KonaSecret, kona_global_state
from kona.schema.parsers import load_schema
from kona.util.jinja import render_template

ROOT = Path(__file__).resolve().parents[1]
HEADER = "# Generated from challenge.yml by uv run tools/konata.py --write. Do not edit.\n"
HOST_TEMPLATE = "{{ config.secrets['challenge_host'].loaded }}"


class Dumper(yaml.SafeDumper):
    pass


def represent_string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


Dumper.add_representer(str, represent_string)


def build_config(path):
    meta = yaml.safe_load((path / "challenge.yml").read_text())
    # Do not silently discard semantics unsupported by this adapter.
    if meta["type"] != "dynamic" or meta["hints"] or meta["state"] not in ("hidden", "visible"):
        raise ValueError("unsupported challenge type, hints, or visibility")
    flags = meta["flags"]
    if len(flags) != 1 or flags[0]["type"] != "static" or flags[0].get("data") != "case_sensitive":
        raise ValueError("expected one case-sensitive static flag")
    if flags[0]["content"] != (path / "flag.txt").read_text().strip():
        raise ValueError("flag.txt and challenge.yml differ")
    extra = meta["extra"]
    if "decay" in extra or "function" in extra:
        raise ValueError("configure the decay algorithm in rCTF's server scoreProvider, not challenge.yml")
    challenge = {
        "name": meta["name"],
        "author": meta["author"],
        "category": meta["category"],
        "description": meta["description"],
        "hidden": meta["state"] == "hidden",
        "tags": meta["tags"],
        "scoring": {
            "initial_value": extra["initial"],
            "minimum_value": extra["minimum"],
            "rctf": {"kind": "decay", "eligible_for_tiebreaks": True},
        },
        "flags": {"rctf": [{"provider": "flags/static", "config": {"flag": {"file": "flag.txt"}}}]},
        # pre_compressed passes files through verbatim, including raw binaries.
        "attachments": {"pre_compressed": meta["files"]},
    }
    connection = meta.get("connection_info")
    if connection:
        deploy = yaml.safe_load((path / "deployment.yml").read_text())
        protocol = deploy["protocol"]
        port = deploy["public_port"]
        expected = f"nc CHALLENGE_HOST {port}" if protocol == "tcp" else f"{protocol}://CHALLENGE_HOST:{port}"
        if protocol not in ("tcp", "http", "https") or connection != expected:
            raise ValueError("connection_info does not match the deployment protocol and port")
        challenge["endpoints"] = [{
            "type": "nc" if protocol == "tcp" else protocol,
            "endpoint": HOST_TEMPLATE,
            "port": port,
        }]
    return {"challenges": [challenge]}


def check_resolved(path, config):
    group = load_schema(path, model=KonaChallengeConfig)
    challenge = group.challenges[0]
    challenge.resolve_flags(path)
    if challenge.rctf_flag_entries[0].config["flag"] != (path / "flag.txt").read_text().strip():
        raise ValueError("Konata resolved a different flag")
    meta = yaml.safe_load((path / "challenge.yml").read_text())
    with tempfile.TemporaryDirectory(prefix="ccs-konata-") as tmp:
        attachments = resolve_attachments(
            path, Path(tmp), challenge.attachments, config.attachment_format, challenge.default_archive_name,
        )
        expected = [path / name for name in meta["files"]]
        if attachments != expected:
            raise ValueError("Konata attachments differ from the approved handout list")
        for attachment in attachments:
            if not attachment.resolve().is_relative_to((path / "dist").resolve()):
                raise ValueError("attachment escapes dist/")
    for endpoint in challenge.endpoints:
        endpoint.endpoint = render_template(endpoint.endpoint, config=config)
    endpoints = render_template(config.templates.endpoints_text.rctf, challenge=challenge, config=config)
    description = render_template(
        config.templates.challenge_description.rctf,
        challenge=challenge, config=config, endpoints_rendered=endpoints,
    )
    if "CHALLENGE_HOST" in description or "{{" in description:
        raise ValueError("unresolved template in the player description")
    if meta.get("connection_info"):
        connection = meta["connection_info"].replace("CHALLENGE_HOST", "192.0.2.1")
        if connection not in description:
            raise ValueError("rendered description is missing the connection information")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate each challenge's kona.yaml")
    args = parser.parse_args()
    paths = sorted(path.parent for path in (ROOT / "challenges").glob("*/*/challenge.yml"))
    failed = False
    for path in paths:
        try:
            expected = build_config(path)
            target = path / "kona.yaml"
            if args.write:
                target.write_text(HEADER + yaml.dump(expected, Dumper=Dumper, sort_keys=False, allow_unicode=True))
            if not target.exists() or yaml.safe_load(target.read_text()) != expected:
                raise ValueError("kona.yaml is missing or stale; run uv run tools/konata.py --write")
            # A fresh config per challenge keeps offline dummy values out of other commands.
            config = load_schema(ROOT, model=KonaGlobalConfig)
            if config.rctf is None or config.ctfd is not None:
                raise ValueError("root config must enable rCTF only")
            config.secrets["challenge_host"] = KonaSecret(value="192.0.2.1")
            kona_global_state.root_path = ROOT
            kona_global_state.global_config = config
            check_resolved(path, config)
            print(f"[  ok] {path.relative_to(ROOT)}/kona.yaml")
        except Exception as exc:
            # Upstream validation errors can include input values, including flags.
            print(f"[FAIL] {path.relative_to(ROOT)}: {type(exc).__name__}", file=sys.stderr)
            if type(exc) is ValueError:
                print(f"       {exc}", file=sys.stderr)
            failed = True
    print(f"{len(paths)} Konata config(s) checked offline")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
