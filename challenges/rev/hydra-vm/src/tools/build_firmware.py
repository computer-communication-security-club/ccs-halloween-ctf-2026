#!/usr/bin/env python3
"""Assemble the HYDRA firmware and encrypt it to firmware/firmware.enc."""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import firmware_src  # noqa: E402
import fw_key  # noqa: E402
from hydra_common import NONCE_ADDR, mac, proof  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--out", default=None,
                    help="output path (default: firmware/firmware.enc)")
    ap.add_argument("--vectors", action="store_true",
                    help="print MAC test vectors after building")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    out = args.out or os.path.join(here, "..", "firmware", "firmware.enc")
    out = os.path.normpath(out)

    plain = firmware_src.build()
    if len(plain) >= NONCE_ADDR:
        sys.exit(f"firmware too large: {plain.__len__()} bytes")

    blob = fw_key.pack_firmware(plain)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(blob)

    # Round-trip self-check.
    assert fw_key.unpack_firmware(blob) == plain, "firmware round-trip failed"
    print(f"firmware: {len(plain)} bytes plaintext, {len(blob)} bytes encrypted -> {out}")
    print(f"firmware CRC32: {fw_key.crc32(plain):08x}")

    if args.vectors:
        print("MAC test vectors (nonce -> tag):")
        for label, nonce in [
            ("zeros", bytes(16)),
            ("count", bytes(range(16))),
            ("ffff", b"\xff" * 16),
        ]:
            print(f"  {label}: {nonce.hex()} -> {mac(nonce).hex()}")
        print("verifier proof vector (zero nonce):", proof(bytes(16)).hex())


if __name__ == "__main__":
    main()
