#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["konata==0.0.33", "PyYAML==6.0.3"]
# ///
"""Exercise real Konata discovery and rCTF sync against an offline HTTP transport."""

import hashlib
from datetime import datetime
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import yaml
from kona.core.sync import sync
from kona.schema.models import KonaGlobalConfig, KonaSecret, kona_global_state
from kona.schema.parsers import load_schema

ROOT = Path(__file__).resolve().parents[1]


class KonataTests(unittest.IsolatedAsyncioTestCase):
    async def test_rctf_discovery_payloads_and_idempotency(self):
        config = load_schema(ROOT, model=KonaGlobalConfig)
        self.assertIsNotNone(config.rctf)
        self.assertIsNone(config.ctfd)
        config.secrets["challenge_host"] = KonaSecret(value="192.0.2.1")
        config.secrets["rctf_token"] = KonaSecret(value="offline-test-token")
        kona_global_state.root_path = ROOT
        kona_global_state.global_config = config

        sources = {}
        uploads = {}
        for path in (ROOT / "challenges").glob("*/*/challenge.yml"):
            meta = yaml.safe_load(path.read_text())
            challenge_id = path.parent.relative_to(ROOT).as_posix().replace("/", "_")
            sources[challenge_id] = (path.parent, meta)
            for name in meta["files"]:
                file = path.parent / name
                digest = hashlib.sha256(file.read_bytes()).hexdigest()
                uploads[(file.name, digest)] = {
                    "name": file.name, "url": f"https://uploads.example/{digest}/{file.name}",
                    "size": file.stat().st_size,
                }

        remote = {}
        puts = []
        logins = []

        def handle(request):
            path = request.url.path
            if request.method == "POST" and path == "/api/v1/auth/login":
                logins.append(json.loads(request.content))
                return httpx.Response(200, json={"data": {"authToken": "offline-bearer"}})
            self.assertEqual(request.headers.get("Authorization"), "Bearer offline-bearer")
            if request.method == "GET" and path == "/api/v2/admin/flags/providers":
                return httpx.Response(200, json={"data": [{"id": "flags/static"}]})
            if request.method == "GET" and path == "/api/v2/admin/challs":
                return httpx.Response(200, json={"data": list(remote.values())})
            if request.method == "POST" and path == "/api/v2/admin/upload/query":
                queried = json.loads(request.content)["uploads"]
                data = [uploads[(entry["name"], entry["sha256"])] for entry in queried]
                return httpx.Response(200, json={"data": data})
            if request.method == "PUT" and path.startswith("/api/v2/admin/challs/"):
                challenge_id = path.rsplit("/", 1)[1]
                self.assertIn(challenge_id, sources)
                payload = json.loads(request.content)["data"]
                remote[challenge_id] = {"id": challenge_id, **payload}
                puts.append(challenge_id)
                return httpx.Response(200, json={"data": remote[challenge_id]})
            self.fail(f"unexpected request: {request.method} {path}")

        transport = httpx.MockTransport(handle)

        def client(**kwargs):
            return httpx.AsyncClient(transport=transport, **kwargs)

        try:
            with patch("kona.external.rctf.AsyncClient", side_effect=client), \
                    patch("docker.from_env", side_effect=AssertionError("unexpected Docker access")):
                for _ in range(2):
                    result = await sync(ROOT, config)
                    result.cleanup()
            self.assertEqual(logins, [{"teamToken": "offline-test-token"}] * 2)
            self.assertEqual(set(remote), set(sources))
            # A second sync must reuse the same IDs and skip unchanged challenges.
            self.assertEqual(len(puts), len(sources))
            for challenge_id, payload in remote.items():
                with self.subTest(challenge=challenge_id):
                    path, meta = sources[challenge_id]
                    self.assertEqual(payload["hidden"], meta["state"] == "hidden")
                    release = meta.get("release_time")
                    release = datetime.fromisoformat(release) if isinstance(release, str) else release
                    self.assertEqual(payload["releaseTime"], int(release.timestamp() * 1000) if release else None)
                    if meta["state"] == "visible" and release:
                        self.assertFalse(payload["hidden"], "hidden would prevent scheduled release")
                    self.assertEqual(payload["scoring"], {"kind": "decay"})
                    self.assertEqual(payload["points"], {
                        "max": meta["extra"]["initial"], "min": meta["extra"]["minimum"],
                    })
                    self.assertTrue(payload["tiebreakEligible"])
                    for field in ("name", "author", "category", "tags"):
                        self.assertEqual(payload[field], meta[field])
                    description = payload["description"]
                    self.assertIn(meta["description"].strip().replace("CHALLENGE_HOST", "192.0.2.1"),
                                  description)
                    self.assertNotIn("CHALLENGE_HOST", description)
                    self.assertNotIn("{{", description)
                    runtime = json.loads((ROOT / "deployment/challenges/instances.json").read_text())
                    if path.name in runtime:
                        expected = runtime[path.name]
                        self.assertEqual(payload["instancerConfig"]["config"], expected["config"])
                        self.assertEqual(payload["instancerConfig"]["challengeIntegrationId"], path.name)
                        self.assertNotIn("> [!CONNECTION]", description)
                    elif "connection_info" in meta:
                        self.assertIn(meta["connection_info"].replace("CHALLENGE_HOST", "192.0.2.1"), description)
                        self.assertIn("> [!CONNECTION]", description)
                    else:
                        self.assertNotIn("> [!CONNECTION]", description)
                    expected_files = []
                    for name in meta["files"]:
                        file = path / name
                        digest = hashlib.sha256(file.read_bytes()).hexdigest()
                        expected_files.append(uploads[(file.name, digest)])
                    self.assertEqual(payload["files"], expected_files)
                    self.assertEqual(len(payload["flags"]), 1)
                    flag = payload["flags"][0]
                    self.assertEqual(flag["provider"], "flags/static")
                    # Avoid including either flag in a failing assertion.
                    self.assertTrue(flag["config"] == {"flag": (path / "flag.txt").read_text().strip()},
                                    "resolved flag differs from flag.txt")
        finally:
            kona_global_state.global_config = None


if __name__ == "__main__":
    unittest.main()
