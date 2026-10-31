#!/usr/bin/env python3
"""Render rCTF's native UI configuration from the editable landing page."""
import json
from pathlib import Path

root = Path(__file__).resolve().parent
config = {
    "homeContent": (root / "home.html").read_text(),
    "logoLightUrl": "/halloween/wordmark.svg",
    "logoDarkUrl": "/halloween/wordmark.svg",
    "faviconUrl": "/halloween/mark.svg",
}
(root / "theme.json").write_text(json.dumps(config, indent=2) + "\n")
