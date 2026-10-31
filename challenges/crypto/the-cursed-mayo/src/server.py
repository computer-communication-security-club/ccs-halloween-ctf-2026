#!/usr/bin/env python3
import fcntl
import os
import re
import socketserver
import subprocess
import sys

APP_DIR = os.environ.get("CURSED_APP_DIR", "/app")
DATA_DIR = os.environ.get("CURSED_DATA_DIR", "/data")
SIGNER = os.environ.get("CURSED_SIGNER", os.path.join(APP_DIR, "cursed_signer"))
PK_FILE = os.path.join(DATA_DIR, "pk.bin")
O_FILE = os.path.join(DATA_DIR, "O.bin")
CSK_FILE = os.path.join(DATA_DIR, "csk.bin")
COUNTER_FILE = os.path.join(DATA_DIR, "query_count")
COUNTER_LOCK = os.path.join(DATA_DIR, "query_count.lock")
FLAG_FILE = os.environ.get("CURSED_FLAG_FILE", "/flag.txt")

def load_flag():
    env_flag = os.environ.get("FLAG", "").strip()
    if env_flag:
        return env_flag
    try:
        with open(FLAG_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""

FLAG = load_flag()
MAX_QUERIES = int(os.environ.get("MAX_QUERIES", "600"))
PORT = int(os.environ.get("PORT", "1337"))
HOST = os.environ.get("HOST", "0.0.0.0")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
FLAG_RE = re.compile(r"^ccsCTF\{[^{}\r\n]+\}$")
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

BANNER = r"""
    ___                          _   __  __   _   __   __
   / __\__ _ _ __ ___  ___  ___ | | |  \/  | /_\ \ \ / /
  / /  / _` | '__/ _ \/ __|/ _ \| | | |\/| |/ _ \ \ V /
 / /__| (_| | | |  __/\__ \  __/| | | |  | / ___ \ | |
 \____/\__,_|_|  \___||___/\___||_| |_|  |_/_/   \_\|_|

        THE CURSED MAYO

The laboratory's signing oracle still breathes.
Each ritual costs one query. The offering is free.
"""

MENU = """
1. read the haunted public key
2. perform a ritual (costs one query)
3. make an offering and ask for the flag
4. count the remaining candles
> """


def _read_counter():
    try:
        with open(COUNTER_FILE, "r", encoding="ascii") as f:
            return max(0, int(f.read().strip() or "0"))
    except (OSError, ValueError):
        return 0


def remaining_queries():
    return max(0, MAX_QUERIES - _read_counter())


def consume_query():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(COUNTER_LOCK, "a", encoding="ascii") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            used = _read_counter()
            if used >= MAX_QUERIES:
                return None
            used += 1
            tmp = COUNTER_FILE + f".tmp.{os.getpid()}"
            with open(tmp, "w", encoding="ascii") as f:
                f.write(str(used))
            os.replace(tmp, COUNTER_FILE)
            return MAX_QUERIES - used
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def ensure_keys():
    os.makedirs(DATA_DIR, exist_ok=True)
    lock_path = os.path.join(DATA_DIR, "keygen.lock")
    with open(lock_path, "a", encoding="ascii") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            if all(os.path.exists(p) and os.path.getsize(p) > 0 for p in (PK_FILE, O_FILE, CSK_FILE)):
                return
            proc = subprocess.run(
                [SIGNER, "keygen", PK_FILE, O_FILE, CSK_FILE],
                capture_output=True, timeout=60, check=False, env=SAFE_ENV,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.decode("utf-8", "replace"))
            for p in (PK_FILE, O_FILE, CSK_FILE):
                os.chmod(p, 0o600)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def run_signer(args, timeout=30):
    return subprocess.run(
        [SIGNER] + args,
        capture_output=True, timeout=timeout, check=False, env=SAFE_ENV,
    )


class Handler(socketserver.StreamRequestHandler):
    timeout = 180

    def send(self, text):
        self.wfile.write(text.encode("utf-8", "replace"))
        self.wfile.flush()

    def read_line(self, limit=8192):
        raw = self.rfile.readline(limit)
        if not raw:
            return None
        if len(raw) >= limit and not raw.endswith(b"\n"):
            return None
        try:
            return raw.decode("utf-8", "replace").strip()
        except UnicodeDecodeError:
            return None

    def handle(self):
        try:
            self.request.settimeout(self.timeout)
            self.send(BANNER + "\n")
            while True:
                self.send(MENU)
                choice = self.read_line(128)
                if choice is None:
                    return
                if choice in ("1", "public", "pub"):
                    with open(PK_FILE, "rb") as f:
                        pk = f.read().hex()
                    self.send(f"public_key: {pk}\n")
                elif choice in ("2", "ritual"):
                    self.do_ritual()
                elif choice in ("3", "offering", "offer"):
                    self.do_offering()
                elif choice in ("4", "status", "candles"):
                    self.send(f"queries_left: {remaining_queries()}\n")
                else:
                    self.send("the candles do not understand that word\n")
        except OSError:
            return
        finally:
            try:
                self.wfile.flush()
            except Exception:
                pass

    def do_ritual(self):
        self.send("candle (0-63): ")
        candle = self.read_line(64)
        if candle is None or not candle.isdigit() or not (0 <= int(candle) < 64):
            self.send("that is not a candle the curse recognises\n")
            return
        left = consume_query()
        if left is None:
            self.send("the candles are spent; no more rituals are possible\n")
            return
        msg = os.urandom(32).hex()
        try:
            proc = run_signer(["ritual", O_FILE, CSK_FILE, msg, candle])
        except subprocess.TimeoutExpired:
            self.send("the ritual collapsed into silence\n")
            return
        if proc.returncode != 0:
            self.send("the ritual collapsed into silence\n")
            return
        out = proc.stdout.decode("utf-8", "replace")
        sig = None
        seen_msg = None
        for line in out.splitlines():
            if line.startswith("message: "):
                seen_msg = line[len("message: "):].strip()
            elif line.startswith("haunted_signature: "):
                sig = line[len("haunted_signature: "):].strip()
        if seen_msg != msg or not sig or not HEX_RE.match(sig) or len(sig) != 186 * 2:
            self.send("the ritual collapsed into silence\n")
            return
        self.send(f"message: {msg}\nhaunted_signature: {sig}\nqueries_left: {left}\n")

    def do_offering(self):
        msg = os.urandom(32).hex()
        self.send(f"offering_message: {msg}\n")
        self.send("signature (hex, sig or sig||message): ")
        sig = self.read_line(2048)
        if sig is None or not sig or not HEX_RE.match(sig):
            self.send("the offering is malformed\n")
            return
        if len(sig) not in (186 * 2, (186 + 32) * 2):
            self.send("the offering is malformed\n")
            return
        try:
            proc = run_signer(["verify", PK_FILE, msg, sig], timeout=20)
        except subprocess.TimeoutExpired:
            self.send("the curse does not answer\n")
            return
        if proc.returncode == 0:
            self.send(f"the curse breaks. {FLAG}\n")
        else:
            self.send("the curse rejects the offering\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    if not FLAG or not FLAG_RE.fullmatch(FLAG):
        sys.stderr.write("FLAG must be set and match ccsCTF{...}; refusing to start\n")
        raise SystemExit(2)
    ensure_keys()
    with Server((HOST, PORT), Handler) as server:
        sys.stderr.write(f"cursed mayo listening on {HOST}:{PORT} with {remaining_queries()} queries\n")
        sys.stderr.flush()
        server.serve_forever()


if __name__ == "__main__":
    main()
