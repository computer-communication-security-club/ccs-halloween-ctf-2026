#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Minecraft status handshake only; this is deliberately not a flag solver."""
import json
import socket
import struct
import sys


def varint(value):
    data = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        data.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(data)


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Server closed the status connection")
        data.extend(chunk)
    return bytes(data)


def read_varint(sock):
    result = 0
    for shift in range(0, 35, 7):
        byte = exact(sock, 1)[0]
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result
    raise RuntimeError("Invalid status length")


def status(host, port):
    address = host.encode()
    handshake = b'\x00' + varint(0) + varint(len(address)) + address + struct.pack('>H', port) + b'\x01'
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(varint(len(handshake)) + handshake + b'\x01\x00')
        packet_length = read_varint(sock)
        if not 1 <= packet_length <= 1024 * 1024:
            raise RuntimeError("Invalid status packet size")
        if read_varint(sock) != 0:
            raise RuntimeError("Unexpected status packet")
        size = read_varint(sock)
        if not 1 <= size <= packet_length:
            raise RuntimeError("Invalid status JSON size")
        return json.loads(exact(sock, size))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('Usage: uv run check_endpoint.py HOST PORT')
    result = status(sys.argv[1], int(sys.argv[2]))
    version = result.get('version', {}).get('name', '')
    if version != '26.3':
        sys.exit(f'Unexpected Minecraft version: {version!r}')
    print('Minecraft 26.3 status handshake passed; a manual gameplay solve is still required.')
