#!/usr/bin/env python3
"""Verify deployed challenge endpoints without displaying recovered flags."""
import argparse
from datetime import datetime, timezone
import json
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.request

import manage
from rctf import API


def solve(path, host, port, *, tls=False, origin_ip=None):
    code = '''import runpy, socket, ssl, sys
target, host, port, tls, origin = sys.argv[1:]
if tls == 'yes':
    original = socket.create_connection
    context = ssl.create_default_context()
    def connect(address, *args, **kwargs):
        destination = (origin, address[1]) if origin else address
        return context.wrap_socket(original(destination, *args, **kwargs), server_hostname=address[0])
    socket.create_connection = connect
sys.argv = [target, host, port]
runpy.run_path(target, run_name='__main__')
'''
    result = subprocess.run([sys.executable, "-c", code, str(path / "solve/solve.py"),
                             host, str(port), "yes" if tls else "no", origin_ip or ""],
                            capture_output=True, text=True, timeout=300)
    expected = (path / "flag.txt").read_text().strip()
    ok = result.returncode == 0 and expected in result.stdout
    if not ok:
        output = re.sub(r"ccsCTF\{[^}]*\}", "[REDACTED]", result.stdout + result.stderr)
        print(output[-3000:], file=sys.stderr)
        raise RuntimeError(f"{path.name}: deployed solver failed")
    print(f"{path.name}: deployed solver passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=["shared", "instances", "instances-local", "minecraft"])
    parser.add_argument("--origin-ip", help="Test HTTPS directly at the origin, preserving TLS hostname verification")
    args = parser.parse_args()
    state = manage.state()
    if args.origin_ip:
        import ipaddress
        ipaddress.ip_address(args.origin_ip)
        if args.group != "instances":
            parser.error("--origin-ip requires the instances group")
        getaddrinfo = socket.getaddrinfo
        def resolve(host, *values, **kwargs):
            if host.endswith("." + manage.CONFIG["instances_host"]):
                host = args.origin_ip
            return getaddrinfo(host, *values, **kwargs)
        socket.getaddrinfo = resolve
    if args.group == "shared":
        host = state["workers"]["instancer"]["public_ip"]
        solve(manage.ROOT / "challenges/web/piggyback", host, 32002)
        solve(manage.ROOT / "challenges/rev/hydra-vm", host, 34001)
    elif args.group == "minecraft":
        subprocess.run([sys.executable,
            str(manage.ROOT / "challenges/misc/sict-halloween/solve/check_endpoint.py"),
            state["workers"]["minecraft"]["public_ip"], "35001"], check=True)
    else:
        api = API()
        summary = json.loads((manage.LOCAL / "import-summary.json").read_text())
        for item in summary:
            if not item["per_team"]:
                continue
            route = f"/api/v2/admin/challs/{item['id']}/instance"
            if api.call(route)["data"]["status"] != "stopped":
                raise RuntimeError("An organizer instance already exists; refusing to replace it")
            owned = False
            tunnel = None
            try:
                created = api.call(route, method="PUT")
                owned = True
                deadline = time.monotonic() + 90
                while True:
                    result = api.call(route)["data"]
                    if result["status"] == "running":
                        break
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"{item['slug']}: instance not ready")
                    time.sleep(2)
                endpoint = result["endpoints"][0]
                host, port = endpoint["host"], endpoint["port"]
                tls = args.group == "instances"
                if not tls:
                    containers = manage.ssh("instancer", "sudo docker ps -q --filter " +
                        shlex.quote("label=io.es3n1n.instancer.hostnames=" + host), capture_output=True).stdout.split()
                    assert len(containers) == 1
                    networks = json.loads(manage.ssh("instancer",
                        "sudo docker inspect --format '{{json .NetworkSettings.Networks}}' " + containers[0],
                        capture_output=True).stdout)
                    address = next(iter(networks.values()))["IPAddress"]
                    with socket.socket() as listener:
                        listener.bind(("127.0.0.1", 0))
                        port = listener.getsockname()[1]
                    service_port = 8000 if item["slug"] == "shelloween" else 8080
                    tunnel = subprocess.Popen([*manage.ssh_args("instancer")[:-1],
                        "-o", "ExitOnForwardFailure=yes", "-N", "-L",
                        f"127.0.0.1:{port}:{address}:{service_port}", manage.ssh_args("instancer")[-1]])
                    host = "127.0.0.1"
                    for _ in range(50):
                        if tunnel.poll() is not None:
                            raise RuntimeError("SSH tunnel exited")
                        try:
                            with socket.create_connection((host, port), timeout=0.2):
                                break
                        except OSError:
                            time.sleep(0.1)
                url = f"{'https' if tls else 'http'}://{host}:{port}"
                path = "/health" if item["slug"] == "shelloween" else "/healthz"
                with urllib.request.urlopen(url + path, timeout=15) as response:
                    assert response.status == 200
                solve(manage.ROOT / "challenges/web" / item["slug"],
                      host, port, tls=tls, origin_ip=args.origin_ip)
            finally:
                if tunnel is not None:
                    tunnel.terminate()
                    tunnel.wait(timeout=10)
                if owned:
                    api.call(route, method="DELETE")
                    assert api.call(route)["data"]["status"] == "stopped"
            print(f"{item['slug']}: rCTF start/status/stop passed")
    group = "instances-origin" if args.origin_ip else args.group
    result = {"time": datetime.now(timezone.utc).isoformat(), "group": group, "passed": True}
    (manage.HERE / f"verification-{group}.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
