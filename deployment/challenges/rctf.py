#!/usr/bin/env python3
"""Configure the private instancer connection and sync reviewed Konata configs."""
import argparse
import json
import os
import subprocess
import urllib.error
import urllib.request

import yaml
import manage

ORIGIN = manage.CONFIG["rctf_origin"]
RCTF = manage.ROOT / "deployment/rctf"


def remote(command, **kwargs):
    return subprocess.run(["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o",
        "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={RCTF / '.local/known_hosts'}",
        "-i", str(RCTF / ".local/id_rsa"), "ubuntu@13.215.75.166", command],
        check=True, text=True, **kwargs)


def configure():
    # Capture the shared token directly in memory, never in command arguments/logs.
    worker_env = manage.ssh("instancer", "sudo cat /opt/ccs-worker/instancer/.env", capture_output=True).stdout
    values = dict(line.split("=", 1) for line in worker_env.splitlines() if "=" in line)
    address = manage.state()["workers"]["instancer"]["private_ip"]
    payload = json.dumps({"DOCKER_INSTANCER_AUTH_TOKEN": values["AUTH_TOKEN"],
                          "DOCKER_INSTANCER_API_URL": f"http://{address}:12237"})
    remote("sudo bash /opt/rctf/backup.sh", stdout=subprocess.DEVNULL)
    code = '''import json, pathlib, os
values = json.loads(PAYLOAD)
p = pathlib.Path('/opt/rctf/.env')
lines = [line for line in p.read_text().splitlines() if line.split('=',1)[0] not in values]
p.write_text('\\n'.join(lines + [k+'='+v for k,v in values.items()])+'\\n')
os.chmod(p,0o600)
pathlib.Path('/opt/rctf/rctf.d/50-challenge-instancer.yaml').write_text('instancers:\\n  ccs:\\n    name: instancers/docker\\n    options: {}\\ndefaultInstancer: ccs\\n')
'''.replace("PAYLOAD", repr(payload))
    remote("sudo python3 -", input=code)
    remote("sudo bash -c 'cd /opt/rctf && docker compose config --quiet && docker compose up -d --wait --wait-timeout 120 rctf'")
    print("Private instancer connection configured; scoreboard is healthy")


class API:
    def __init__(self):
        self.token = None
        secret = json.loads((RCTF / ".local/admin-access.json").read_text())
        self.token = self.call("/api/v1/auth/login", {"teamToken": secret["team_token"]})["data"]["authToken"]

    def call(self, path, data=None, method=None, content_type="application/json"):
        headers = {"User-Agent": "CCS-Deployment/1.0", "Content-Type": content_type}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if data is not None and not isinstance(data, bytes):
            data = json.dumps(data).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(ORIGIN + path, data=data,
                    method=method, headers=headers), timeout=90) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            try:
                result = json.load(error)
                # Do not print API validation bodies: they may echo flags.
                kind = result.get("kind", "unknown")
            except Exception:
                kind = "non-JSON error"
            raise RuntimeError(f"{method or 'request'} {path}: HTTP {error.code}, {kind}") from None

def sync():
    """Use the same pinned Konata implementation and generated configs as CI."""
    from datetime import datetime
    check_env = os.environ.copy()
    check_env.update(UV_CACHE_DIR="/tmp/ccs-uv-cache", LOGURU_LEVEL="ERROR")
    subprocess.run(["uv", "run", "tools/konata.py"], cwd=manage.ROOT, env=check_env, check=True)
    secret = json.loads((RCTF / ".local/admin-access.json").read_text())
    state = manage.state()
    summary = []
    for path in sorted((manage.ROOT / "challenges").glob("*/*/kona.yaml")):
        directory = path.parent
        config = yaml.safe_load(path.read_text())["challenges"][0]
        env = os.environ.copy()
        env.update(RCTF_TOKEN=secret["team_token"],
                   CHALLENGE_HOST=state["workers"]["minecraft" if directory.name == "sict-halloween" else "instancer"]["public_ip"],
                   UV_CACHE_DIR="/tmp/ccs-uv-cache", LOGURU_LEVEL="WARNING", LOGURU_DIAGNOSE="NO")
        subprocess.run(["uvx", "--from", "konata==0.0.33", "kona", "sync", str(directory)],
                       cwd=manage.ROOT, env=env, check=True)
        release = config.get("release_time")
        release = datetime.fromisoformat(release) if isinstance(release, str) else release
        summary.append({"id": directory.relative_to(manage.ROOT).as_posix().replace("/", "_"),
                        "slug": directory.name, "hidden": config["hidden"],
                        "releaseTime": int(release.timestamp() * 1000) if release else None,
                        "per_team": "instancer_config" in config})
        print(f"Synced {directory.name} through Konata", flush=True)
    (manage.LOCAL / "import-summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["configure", "sync", "inspect"])
    args = parser.parse_args()
    if args.action == "inspect":
        for challenge in API().call("/api/v2/admin/challs")["data"]:
            print({key: challenge.get(key) for key in ["id", "name", "hidden"]})
    else:
        globals()[args.action]()
