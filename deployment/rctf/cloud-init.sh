#!/bin/sh
# Lightsail prepends its initialization and executes user data with /bin/sh.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io docker-compose-v2 curl ca-certificates unattended-upgrades
install -d -m 0755 /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{"log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}
EOF
systemctl enable --now docker
systemctl restart docker
install -d -m 0700 /opt/rctf /opt/rctf/backups
cat > /etc/ssh/sshd_config.d/60-rctf.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
sshd -t
systemctl reload ssh
touch /opt/rctf/bootstrap-complete
