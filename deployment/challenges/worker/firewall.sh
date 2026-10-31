#!/bin/bash
# This host is dedicated to challenge workloads. Never run on the rCTF host.
set -euo pipefail
cd /opt/ccs-worker
source ./firewall.env
iptables -N CCS-CHALLENGES 2>/dev/null || true
iptables -F CCS-CHALLENGES
iptables -C DOCKER-USER -j CCS-CHALLENGES 2>/dev/null || iptables -I DOCKER-USER 1 -j CCS-CHALLENGES
iptables -A CCS-CHALLENGES -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# No challenge-initiated traffic to the control plane, including Traefik's listeners.
iptables -A CCS-CHALLENGES -s 10.202.0.0/16 -d 10.203.0.0/24 -j DROP
iptables -A CCS-CHALLENGES -s 10.202.0.0/16 -p tcp -m multiport --dports 80,443,1337,12237 -j DROP
# Keep intended communication inside each individual challenge bridge.
iptables -A CCS-CHALLENGES -s 10.202.0.0/16 -m physdev --physdev-is-bridged -j RETURN
# Block new connections to the internet, AWS metadata, rCTF, and other bridges.
iptables -A CCS-CHALLENGES -s 10.202.0.0/16 -j DROP
# Docker-published ports traverse FORWARD, not INPUT. Protect the API here too.
iptables -A CCS-CHALLENGES -d 10.203.0.4 -p tcp --dport 1337 -s "$RCTF_PRIVATE_IP" -j RETURN
iptables -A CCS-CHALLENGES -d 10.203.0.4 -p tcp --dport 1337 -j DROP
iptables -A CCS-CHALLENGES -j RETURN
iptables -C INPUT -s 10.202.0.0/16 -j DROP 2>/dev/null || iptables -I INPUT 1 -s 10.202.0.0/16 -j DROP
# Permit replies to host-initiated management probes, but no new host access.
iptables -C INPUT -s 10.202.0.0/16 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -s 10.202.0.0/16 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# No IPv6 is configured on Docker challenge networks. Explicitly deny forwarding
# from Docker bridges if IPv6 is enabled later, rather than bypassing this policy.
ip6tables -C FORWARD -i 'br+' -j DROP 2>/dev/null || ip6tables -I FORWARD 1 -i 'br+' -j DROP
