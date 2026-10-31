#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["PyYAML==6.0.3"]
# ///
"""Provision and operate the two event workers without changing deployment/rctf/."""

import argparse
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCAL = HERE / ".local"
CONFIG = json.loads((HERE / "config.json").read_text())


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, text=True, **kwargs)


def aws(*args):
    result = run("aws", "--profile", CONFIG["profile"], "--region", CONFIG["region"],
                 *args, "--output", "json", capture_output=True)
    return json.loads(result.stdout or "{}")


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def prepare_local():
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    os.chmod(LOCAL, 0o700)


def state():
    return json.loads((LOCAL / "state.json").read_text())


def ssh_args(role):
    return ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={LOCAL / 'known_hosts'}",
            "-i", str(LOCAL / "id_rsa"), f"ubuntu@{state()['workers'][role]['public_ip']}"]


def ssh(role, command, **kwargs):
    return run(*ssh_args(role), command, **kwargs)


def provision(args):
    prepare_local()
    key = LOCAL / "id_rsa"
    pairs = aws("lightsail", "get-key-pairs")["keyPairs"]
    if CONFIG["key_pair"] not in {p["name"] for p in pairs}:
        created = aws("lightsail", "create-key-pair", "--key-pair-name", CONFIG["key_pair"])
        private = created["privateKeyBase64"]
        key.write_bytes(private.encode() if private.startswith("-----BEGIN") else base64.b64decode(private))
        key.chmod(0o600)
        public = run("ssh-keygen", "-y", "-f", key, capture_output=True).stdout
        key.with_suffix(".pub").write_text(public)
    elif not key.exists():
        raise RuntimeError("worker SSH key exists in AWS but its local private key is missing")
    existing = {i["name"]: i for i in aws("lightsail", "get-instances")["instances"]}
    rctf = existing[CONFIG["rctf_instance"]]
    recorded = {"rctf_private_ip": rctf["privateIpAddress"], "workers": {}}
    for role, spec in CONFIG["workers"].items():
        name = spec["name"]
        if name not in existing:
            aws("lightsail", "create-instances", "--instance-names", name,
                "--availability-zone", CONFIG["availability_zone"],
                "--blueprint-id", CONFIG["blueprint"], "--bundle-id", spec["bundle"],
                "--key-pair-name", CONFIG["key_pair"],
                "--user-data", f"file://{HERE / 'worker/cloud-init.sh'}",
                "--tags", "key=project,value=ccs-halloween-2026", "key=managed-by,value=ccs-workers",
                f"key=role,value={role}")
        else:
            tags = {t["key"]: t.get("value") for t in existing[name].get("tags", [])}
            if tags.get("managed-by") != "ccs-workers":
                raise RuntimeError(f"refusing to adopt unmanaged instance {name}")
        deadline = time.monotonic() + 300
        while True:
            instance = aws("lightsail", "get-instance", "--instance-name", name)["instance"]
            if instance["state"]["name"] == "running":
                break
            if time.monotonic() > deadline:
                raise TimeoutError(f"waiting for {name}")
            time.sleep(5)
        ip_name = f"{name}-ip"
        ips = {ip["name"]: ip for ip in aws("lightsail", "get-static-ips")["staticIps"]}
        if ip_name not in ips:
            aws("lightsail", "allocate-static-ip", "--static-ip-name", ip_name)
        elif ips[ip_name].get("attachedTo") not in (None, name):
            raise RuntimeError(f"refusing to reassign {ip_name}")
        if ips.get(ip_name, {}).get("attachedTo") != name:
            aws("lightsail", "attach-static-ip", "--static-ip-name", ip_name, "--instance-name", name)
        ip = aws("lightsail", "get-static-ip", "--static-ip-name", ip_name)["staticIp"]["ipAddress"]
        ports = [{"fromPort": 22, "toPort": 22, "protocol": "tcp", "cidrs": [CONFIG["ssh_cidr"]]}]
        ports += [{"fromPort": p, "toPort": p, "protocol": "tcp", "cidrs": ["0.0.0.0/0"]}
                  for p in spec["public_tcp"]]
        aws("lightsail", "put-instance-public-ports", "--instance-name", name,
            "--port-infos", json.dumps(ports))
        recorded["workers"][role] = {
            "name": name, "public_ip": ip, "private_ip": instance["privateIpAddress"],
            "static_ip_name": ip_name, "bundle": spec["bundle"],
        }
        save(LOCAL / "state.json", recorded)
        details = aws("lightsail", "get-instance-access-details", "--instance-name", name,
                      "--protocol", "ssh")["accessDetails"]
        lines = []
        for hostkey in details.get("hostKeys", []):
            public = hostkey["publicKey"]
            if not public.startswith(hostkey["algorithm"] + " "):
                public = hostkey["algorithm"] + " " + public
            lines.append(f"{ip} {public}\n")
        known = LOCAL / "known_hosts"
        old = known.read_text().splitlines(keepends=True) if known.exists() else []
        if not lines:
            # Lightsail sometimes omits hostKeys. Preserve previously pinned
            # keys; first contact uses TOFU at the AWS-confirmed static IP.
            lines = [line for line in old if line.startswith(ip + " ")]
            if not lines:
                scanned = run("ssh-keyscan", "-T", "10", "-t", "ed25519", ip,
                              capture_output=True)
                lines = scanned.stdout.splitlines(keepends=True)
                if not lines:
                    raise RuntimeError(f"No SSH host key available for {name}; retry after boot")
                print(f"Pinned first-contact SSH host key for {name} at {ip}", flush=True)
        known.write_text("".join(line for line in old if not line.startswith(ip + " ")) + "".join(lines))
        print(f"{role}: {ip}; private {instance['privateIpAddress']}", flush=True)


def status(args):
    print(json.dumps(state(), indent=2))
    for role in CONFIG["workers"]:
        ssh(role, "sudo test -f /opt/ccs-worker/bootstrap-complete && sudo docker ps --format '{{.Names}} {{.Status}}'")


def destroy(args):
    if not args.delete_workers:
        raise SystemExit("pass --delete-workers to delete event workers and their local data; back up Minecraft first")
    for role, worker in state()["workers"].items():
        if worker["name"] != CONFIG["workers"][role]["name"] or worker["name"] == CONFIG["rctf_instance"]:
            raise RuntimeError("worker identity mismatch")
        instance = aws("lightsail", "get-instance", "--instance-name", worker["name"])["instance"]
        tags = {t["key"]: t.get("value") for t in instance.get("tags", [])}
        if tags.get("managed-by") != "ccs-workers":
            raise RuntimeError("refusing to delete an unmanaged instance")
        aws("lightsail", "detach-static-ip", "--static-ip-name", worker["static_ip_name"])
        aws("lightsail", "delete-instance", "--instance-name", worker["name"])
        aws("lightsail", "release-static-ip", "--static-ip-name", worker["static_ip_name"])
        print(f"deleted {worker['name']} and released its IP")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("provision").set_defaults(func=provision)
    sub.add_parser("status").set_defaults(func=status)
    p = sub.add_parser("ssh")
    p.add_argument("role", choices=CONFIG["workers"])
    p.add_argument("remote_command", nargs=argparse.REMAINDER)
    p.set_defaults(func=lambda a: ssh(a.role, shlex.join(a.remote_command) if a.remote_command else "bash -l"))
    p = sub.add_parser("destroy")
    p.add_argument("--delete-workers", action="store_true")
    p.set_defaults(func=destroy)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
