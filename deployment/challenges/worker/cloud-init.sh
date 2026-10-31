#!/bin/sh
# Lightsail prepends initialization and executes user data with /bin/sh.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io docker-compose-v2 docker-buildx curl ca-certificates iptables python3 openssl
install -d -m 0755 /etc/docker /opt/ccs-worker
cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "local",
  "log-opts": {"max-size": "5m", "max-file": "2"},
  "default-address-pools": [{"base": "10.202.0.0/16", "size": 28}],
  "live-restore": true
}
EOF
systemctl enable --now docker
systemctl restart docker
cat > /etc/ssh/sshd_config.d/60-ccs.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
sshd -t
systemctl reload ssh
touch /opt/ccs-worker/bootstrap-complete
