#!/usr/bin/env python3
import socket
import ssl
import sys

def recv_until(s, marker):
    buf = b""
    while marker not in buf:
        chunk = s.recv(65536)
        if not chunk:
            raise SystemExit("connection closed")
        buf += chunk
    return buf.decode("utf-8", "replace")

def main():
    tls = "--tls" in sys.argv
    if tls:
        sys.argv.remove("--tls")
    if len(sys.argv) < 4:
        print("usage: ritual_client.py [--tls] HOST PORT pk|status|ritual <candle>|offer <msg> <sig>")
        return 2
    host, port = sys.argv[1], int(sys.argv[2])
    cmd = sys.argv[3]
    s = socket.create_connection((host, port), timeout=30)
    if tls:
        s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    print(recv_until(s, b"> "), end="")
    if cmd == "pk":
        s.sendall(b"1\n")
        print(recv_until(s, b"> "), end="")
    elif cmd == "status":
        s.sendall(b"4\n")
        print(recv_until(s, b"> "), end="")
    elif cmd == "ritual" and len(sys.argv) >= 5:
        s.sendall(b"2\n")
        print(recv_until(s, b"candle (0-63): "), end="")
        s.sendall((sys.argv[4] + "\n").encode())
        print(recv_until(s, b"> "), end="")
    elif cmd == "offer" and len(sys.argv) >= 6:
        s.sendall(b"3\n")
        out = recv_until(s, b"signature (hex, sig or sig||message): ")
        print(out, end="")
        s.sendall((sys.argv[5] + "\n").encode())
        print(recv_until(s, b"> "), end="")
    else:
        print("unknown command")
        return 2
    s.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
