#!/usr/bin/env bash
# Egress controls for sandbox containers. Idempotent; run as root after docker.
# Observe, don't block: internet egress is allowed and traced. Only metadata and private
# ranges are refused, and only for traffic *leaving* the dedicated det0 bridge, so replies
# to the container and the host's own traffic are untouched.
set -euo pipefail

NET=detonator
BRIDGE=det0
SUBNET=10.250.0.0/24
CHAIN=DETONATOR-EGRESS

if ! docker network inspect "$NET" >/dev/null 2>&1; then
  docker network create --driver bridge --subnet "$SUBNET" \
    --opt com.docker.network.bridge.name="$BRIDGE" \
    --opt com.docker.network.bridge.enable_icc=false "$NET" >/dev/null
fi

iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# Tetragon traces TCP connects only, so nothing else may leave: UDP (including DNS to public
# resolvers: the logging resolver on the host is reached via INPUT, not here), ICMP, and any
# other protocol are logged (chamber/egress.py reads them back) and rejected.
iptables -A "$CHAIN" ! -p tcp -m limit --limit 100/sec --limit-burst 400 \
  -j LOG --log-prefix "DETONATOR-NONTCP " --log-level 4
iptables -A "$CHAIN" ! -p tcp -j REJECT --reject-with icmp-admin-prohibited
iptables -A "$CHAIN" -p tcp --dport 53 -j REJECT --reject-with tcp-reset
for cidr in 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 0.0.0.0/8; do
  iptables -A "$CHAIN" -d "$cidr" -j REJECT --reject-with icmp-net-prohibited
done
iptables -A "$CHAIN" -j RETURN

iptables -N DOCKER-USER 2>/dev/null || true
iptables -C DOCKER-USER -i "$BRIDGE" -j "$CHAIN" 2>/dev/null \
  || iptables -I DOCKER-USER 1 -i "$BRIDGE" -j "$CHAIN"

# Traffic to the host itself (sshd, the chamber API) hits INPUT, not DOCKER-USER. The only
# host service sandboxes may reach is the dnsmasq resolver on the bridge address.
HOST_CHAIN=DETONATOR-HOST
RESOLVER=10.250.0.1
iptables -N "$HOST_CHAIN" 2>/dev/null || iptables -F "$HOST_CHAIN"
iptables -A "$HOST_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A "$HOST_CHAIN" -d "$RESOLVER" -p udp --dport 53 -j RETURN
iptables -A "$HOST_CHAIN" -d "$RESOLVER" -p tcp --dport 53 -j RETURN
iptables -A "$HOST_CHAIN" -j REJECT --reject-with icmp-host-prohibited
iptables -C INPUT -i "$BRIDGE" -j "$HOST_CHAIN" 2>/dev/null \
  || iptables -I INPUT 1 -i "$BRIDGE" -j "$HOST_CHAIN"

# No IPv6 on det0 (docker default), so nothing to filter there.
iptables -S "$CHAIN"
iptables -S "$HOST_CHAIN"
