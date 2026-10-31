#!/usr/bin/env python3
"""Build private challenge images and install the event worker services."""
import argparse
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile

import yaml
import manage

ROOT = manage.ROOT
HERE = manage.HERE


def upload(role, entries, destination):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for source, name in entries:
            archive.add(source, arcname=name, filter=lambda item: None if
                        any(p in {".git", ".local", "__pycache__", "node_modules"}
                            for p in Path(item.name).parts) else item)
    manage.ssh(role, f"sudo install -d -m 0700 {shlex.quote(destination)}")
    subprocess.run([*manage.ssh_args(role), f"sudo tar -xzf - -C {shlex.quote(destination)}"],
                   input=data.getvalue(), check=True)


def bootstrap(role):
    manage.ssh(role, "sudo sh -s", input=(HERE / "worker/cloud-init.sh").read_text())


def build(role, challenge=None):
    paths = [ROOT / "challenges/misc/sict-halloween"] if role == "minecraft" else [
        ROOT / "challenges" / name for name in ["web/piggyback", "web/shelloween",
                                               "web/poltergeist", "web/phpossessed", "rev/hydra-vm", "crypto/the-cursed-mayo"]]
    if challenge:
        paths = [p for p in paths if p.name == challenge]
        if not paths:
            raise ValueError("Unknown challenge for this worker")
    upload(role, [(p / name, f"{p.name}/{name}") for p in paths
                  for name in ["Dockerfile", ".dockerignore", "src", "flag.txt"]
                  if (p / name).exists()], "/opt/ccs-build")
    commands = ["set -eu"]
    for path in paths:
        compose = yaml.safe_load((path / "docker-compose.yml").read_text())
        seen = set()
        for service in compose["services"].values():
            spec = service["build"]
            target = spec.get("target") if isinstance(spec, dict) else "runtime"
            if target in seen:
                continue
            seen.add(target)
            tag = f"ccs/{path.name}:{target or 'runtime'}"
            target_arg = f"--target {target}" if target else ""
            commands.append(f"docker build --platform linux/amd64 {target_arg} -t {tag} /opt/ccs-build/{path.name}")
    manage.ssh(role, "sudo bash -s", input="\n".join(commands))


def build_instancer(upstream):
    revision = subprocess.check_output(["git", "-C", upstream, "rev-parse", "HEAD"], text=True).strip()
    if revision != manage.CONFIG["upstream_revision"]:
        raise RuntimeError("Unexpected upstream revision")
    upload("instancer", [(Path(upstream) / "apps/docker-instancer", "apps/docker-instancer"),
                          (HERE / "instancer", "ccs")], "/opt/ccs-build/instancer")
    manage.ssh("instancer", "sudo docker build --platform linux/amd64 -f /opt/ccs-build/instancer/ccs/Dockerfile "
               "-t ccs/instancer:reviewed /opt/ccs-build/instancer")


def image_id(role, tag):
    return manage.ssh(role, f"sudo docker image inspect --format '{{{{.Id}}}}' {shlex.quote(tag)}",
                      capture_output=True).stdout.strip()


def install(role):
    upload(role, [(HERE / "worker/firewall.sh", "firewall.sh"),
                  (HERE / "worker/ccs-firewall.service", "ccs-firewall.service")], "/opt/ccs-worker")
    state = manage.state()
    manage.ssh(role, "sudo bash -s", input=f"""set -eu
cd /opt/ccs-worker
printf '%s\\n' 'RCTF_PRIVATE_IP={state['rctf_private_ip']}' > firewall.env
chmod 600 firewall.env
install -m 0644 ccs-firewall.service /etc/systemd/system/ccs-firewall.service
systemctl daemon-reload
systemctl enable --now ccs-firewall.service
""")
    if role == "minecraft":
        path = ROOT / "challenges/misc/sict-halloween"
        compose = yaml.safe_load((path / "docker-compose.yml").read_text())
        service = compose["services"]["minecraft"]
        service.pop("build")
        service["image"] = image_id(role, "ccs/sict-halloween:runtime")
        service["environment"]["EULA"] = "TRUE"  # Explicitly accepted by the operator.
        service["dns"] = ["127.0.0.1"]
        service["ports"] = ["35001:25565"]
        compose["name"] = "ccs-minecraft"
        target = manage.LOCAL / "minecraft-compose.yml"
        target.write_text(yaml.safe_dump(compose, sort_keys=False))
        upload(role, [(target, "compose.yml")], "/opt/ccs-worker/minecraft")
        manage.ssh(role, "sudo bash -c 'cd /opt/ccs-worker/minecraft && docker compose up -d --wait --wait-timeout 300'")
        return
    for slug, category in [("piggyback", "web"), ("hydra-vm", "rev")]:
        path = ROOT / "challenges" / category / slug
        compose = yaml.safe_load((path / "docker-compose.yml").read_text())
        compose.pop("x-service", None)
        compose["name"] = f"ccs-{slug}"
        for service in compose["services"].values():
            spec = service.pop("build")
            target = spec.get("target", "runtime") if isinstance(spec, dict) else "runtime"
            service["image"] = image_id(role, f"ccs/{slug}:{target}")
            if service.get("network_mode") != "none":
                service["dns"] = ["127.0.0.1"]
            if "ports" in service:
                service["ports"] = ["32002:8443" if slug == "piggyback" else "34001:31337"]
        target = manage.LOCAL / f"{slug}-compose.yml"
        target.write_text(yaml.safe_dump(compose, sort_keys=False))
        upload(role, [(target, "compose.yml")], f"/opt/ccs-worker/{slug}")
        manage.ssh(role, f"sudo bash -c 'cd /opt/ccs-worker/{slug} && docker compose up -d --wait --wait-timeout 120'")

    install_instances(role)


def install_instances(role):
    if role != "instancer":
        raise ValueError("Instances require the instancer worker")
    state = manage.state()
    policy = {"ttl_seconds": manage.CONFIG["ttl_seconds"],
              "max_instances": manage.CONFIG["max_instances"],
              "max_per_challenge": manage.CONFIG["max_instances_per_challenge"], "challenges": {}}
    for category, slug in [("web", "shelloween"), ("web", "poltergeist"), ("web", "phpossessed"), ("crypto", "the-cursed-mayo")]:
        service = yaml.safe_load((ROOT / "challenges" / category / slug / "docker-compose.yml").read_text())["services"]["chall"]
        spec = service.pop("build")
        target = spec.get("target", "runtime") if isinstance(spec, dict) else "runtime"
        service["image"] = image_id(role, f"ccs/{slug}:{target}")
        for key in ["ports", "platform", "logging"]:
            service.pop(key, None)
        # Preserve every writable mount, including Apache's PID and mutex dirs.
        if isinstance(service.get("tmpfs"), list):
            service["tmpfs"] = dict(mount.split(":", 1) for mount in service["tmpfs"])
        service["networks"] = ["internal"]
        service["dns"] = ["127.0.0.1"]
        if slug == "the-cursed-mayo":
            # Port 1337 is reserved for the control API by the worker firewall.
            service["environment"] = {"PORT": "33001"}
            service["healthcheck"] = {
                "test": ["CMD", "python3", "-c", "import socket; socket.create_connection(('127.0.0.1', 33001), 2).close()"],
                "interval": "10s", "timeout": "3s", "start_period": "10s", "retries": 5,
            }
        if slug == "poltergeist":
            service["environment"]["POW_BITS"] = "24"
            # Jinja normalizes literal CRLFs while rendering Konata values.
            # Keep printf escapes textual so its health probe stays unchanged.
            service["healthcheck"]["test"] = [part.replace("\r", "\\r").replace("\n", "\\n")
                                               for part in service["healthcheck"]["test"]]
        policy["challenges"][slug] = {"max_instances": 20 if category == "crypto" else policy["max_per_challenge"],
            "config": {"services": {"chall": service},
            "networks": {"internal": {"driver": "bridge", "internal": True}}},
            "expose": [{"kind": "tcp-ssl" if category == "crypto" else "https", "hostPrefix": slug, "containerName": "chall",
                        "containerPort": 33001 if category == "crypto" else (8000 if slug == "shelloween" else 8080)}]}
    target = manage.LOCAL / "policy.json"
    target.write_text(json.dumps(policy, indent=2) + "\n")
    instances = {}
    for slug, entry in policy["challenges"].items():
        instances[slug] = {
            "challenge_integration_id": slug, "instancer": "ccs", "config": entry["config"],
            "expose": [{"kind": e["kind"], "host_prefix": e["hostPrefix"],
                        "container_name": e["containerName"], "container_port": e["containerPort"]}
                       for e in entry["expose"]],
            "timeout_milliseconds": policy["ttl_seconds"] * 1000, "extendable": True,
        }
    (HERE / "instances.json").write_text(json.dumps(instances, indent=2) + "\n")
    upload(role, [(HERE / "worker/compose.yml", "compose.yml"),
                  (HERE / "worker/conf", "conf"), (target, "policy.json")], "/opt/ccs-worker/instancer")
    pinned = image_id(role, "ccs/instancer:reviewed")
    manage.ssh(role, "sudo bash -s", input=f"""set -eu
cd /opt/ccs-worker/instancer
umask 077
if [ ! -f .env ]; then
  printf 'AUTH_TOKEN=%s\\nREDIS_PASSWORD=%s\\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
fi
sed -i '/^INSTANCER_IMAGE=/d;/^PRIVATE_IP=/d;/^INSTANCES_HOST=/d' .env
cat >> .env <<'EOF'
INSTANCER_IMAGE={pinned}
PRIVATE_IP={state['workers'][role]['private_ip']}
INSTANCES_HOST={manage.CONFIG['instances_host']}
EOF
docker compose config --quiet
docker compose up -d --wait --wait-timeout 120 --force-recreate instancer
""")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["bootstrap", "build", "build-instancer", "install", "install-instances"])
    p.add_argument("role", choices=["instancer", "minecraft"])
    p.add_argument("--upstream", default="/tmp/ccs-rctf-instancer-upstream")
    p.add_argument("--challenge", help="Build only this challenge slug")
    args = p.parse_args()
    if args.action == "build-instancer":
        build_instancer(args.upstream)
    elif args.action == "build":
        build(args.role, args.challenge)
    else:
        globals()[args.action.replace("-", "_")](args.role)


if __name__ == "__main__":
    main()
