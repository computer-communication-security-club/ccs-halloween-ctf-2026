#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["konata==0.0.33", "PyYAML==6.0.3"]
# ///
"""Exercise real Konata discovery and CTFd payload generation without network access."""

import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from kona.core.sync import SyncResult, try_discover_challenges
from kona.external.ctfd import CTFDProvider, flag_to_ctfd
from kona.schema.models import KonaGlobalConfig, KonaSecret, kona_global_state
from kona.schema.parsers import load_schema

ROOT = Path(__file__).resolve().parents[1]


class RecordingCTFd(CTFDProvider):
    async def setup(self):
        pass

    async def _create_challenge(self, challenge, attachments, payload):
        self.records.append((challenge, attachments, payload))


class KonataTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_and_ctfd_payloads(self):
        config = load_schema(ROOT, model=KonaGlobalConfig)
        config.secrets["challenge_host"] = KonaSecret(value="192.0.2.1")
        config.secrets["ctfd_token"] = KonaSecret(value="offline-test-token")
        kona_global_state.root_path = ROOT
        kona_global_state.global_config = config
        provider = RecordingCTFd(config, config.ctfd)
        provider.records = []
        result = SyncResult()
        try:
            # Any unexpected external operation must fail the test immediately.
            with patch("httpx.AsyncClient.send", side_effect=AssertionError("unexpected HTTP request")), \
                    patch("docker.from_env", side_effect=AssertionError("unexpected Docker access")):
                await try_discover_challenges(
                    result, ROOT, config, is_root=True, external_providers=[provider],
                )

            sources = {}
            for path in (ROOT / "challenges").glob("*/*/challenge.yml"):
                meta = yaml.safe_load(path.read_text())
                sources[(meta["category"], meta["name"])] = (path.parent, meta)
            self.assertEqual(len(provider.records), len(sources))
            self.assertEqual(
                {(item.category, item.name) for item, _, _ in provider.records}, set(sources),
            )
            for item, attachments, payload in provider.records:
                with self.subTest(challenge=item.name):
                    path, meta = sources[(item.category, item.name)]
                    self.assertEqual(payload["state"], meta["state"])
                    self.assertEqual(payload["type"], "dynamic")
                    self.assertEqual(payload["initial"], meta["extra"]["initial"])
                    self.assertEqual(payload["minimum"], meta["extra"]["minimum"])
                    self.assertEqual(payload["decay"], meta["extra"]["decay"])
                    self.assertEqual(payload["function"], "logarithmic")
                    self.assertEqual(item.tags, meta["tags"])
                    self.assertIn(meta["author"], payload["attribution"])
                    self.assertIn(meta["description"].strip().replace("CHALLENGE_HOST", "192.0.2.1"),
                                  payload["description"])
                    self.assertNotIn("CHALLENGE_HOST", payload["description"])
                    self.assertNotIn("{{", payload["description"])
                    if "connection_info" in meta:
                        self.assertIn(meta["connection_info"].replace("CHALLENGE_HOST", "192.0.2.1"),
                                      payload["description"])
                    else:
                        self.assertEqual(item.endpoints, [])
                    self.assertEqual(attachments, [path / name for name in meta["files"]])
                    self.assertEqual(len(item.flags.ctfd), 1)
                    flag = flag_to_ctfd(1, item.flags.ctfd[0])
                    self.assertEqual(flag["type"], "static")
                    # assertTrue avoids disclosing either flag in a failing assertion.
                    self.assertTrue(flag["content"] == (path / "flag.txt").read_text().strip(),
                                    "resolved flag differs from flag.txt")
        finally:
            result.cleanup()
            kona_global_state.global_config = None


if __name__ == "__main__":
    unittest.main()
