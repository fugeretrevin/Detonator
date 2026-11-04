#!/usr/bin/env bash
# EXPERIMENTAL egress allowlist (W8). NOT wired into provisioning and NOT for the live Chamber
# during judging. It replaces the current "allow all public TCP, trace it" posture with a
# DNS-name allowlist: only the hosts a benign npm install legitimately needs are reachable;
# everything else is logged and refused, so an exfil attempt becomes evidence rather than a
# successful connection.
#
# Deploy ONLY on a sacrificial replica (a second EC2 instance with the full Chamber stack), run
# the acceptance tests in docs/WEAKPOINTS.md W8, and keep it only if benign install success stays
# within 2 packages of baseline and no new "Could not verify" appears from a telemetry blind
# spot. Rollback is re-running chamber/provision/iptables.sh.
#
# Allowlist tiers are taken from eval/egress_allowlist.py, whose offline analysis predicted the
# blast radius: at T1 (registry + node/github) only ~1% of 500 swept packages reach anything
# else, and 0 benign controls are affected. T2 adds four vetted vendor CDNs. Pick the tier with
# the EGRESS_TIER env var (default T2). Hosts ghfast.top and the aliyun OSS store are
# deliberately NOT included (unvetted mirror; one vendor's object store).
#
# Why REJECT, not DROP: a refused connection must fail fast. DROP makes a client wait out its own
# timeout, which would turn a benign package that tolerates a refused optional fetch into a slow
# "Could not verify". REJECT lets it fail and move on, which is what keeps install success near
# baseline. This is the single most important tuning choice here (docs/WEAKPOINTS.md W8).
set -euo pipefail

BRIDGE=det0
CHAIN=DETONATOR-EGRESS
ALLOW_SET=detonator-allow
DNSMASQ_D=/etc/dnsmasq.d/detonator-egress-allow.conf
TIER="${EGRESS_TIER:-T2}"

REGISTRY=(registry.npmjs.org registry.yarnpkg.com)
NODE_GITHUB=(nodejs.org github.com codeload.github.com api.github.com \
             release-assets.githubusercontent.com objects.githubusercontent.com \
             github-releases.githubusercontent.com)
VENDOR_CDN=(storage.googleapis.com astral.sh pypi.org cdn.sheetjs.com)

case "$TIER" in
  T0) HOSTS=("${REGISTRY[@]}") ;;
  T1) HOSTS=("${REGISTRY[@]}" "${NODE_GITHUB[@]}") ;;
  T2) HOSTS=("${REGISTRY[@]}" "${NODE_GITHUB[@]}" "${VENDOR_CDN[@]}") ;;
  *) echo "unknown EGRESS_TIER=$TIER (use T0|T1|T2)"; exit 2 ;;
esac

# 1. An ipset the allowed resolved IPs land in. dnsmasq adds the A/AAAA answers of the allowlist
#    names to it as they are resolved, so iptables can match by name indirectly.
command -v ipset >/dev/null || { echo "ipset not installed (apt-get install ipset)"; exit 1; }
ipset create "$ALLOW_SET" hash:ip timeout 1800 2>/dev/null || ipset flush "$ALLOW_SET"

# 2. Tell the Chamber's dnsmasq to populate the set for exactly the allowlist names. The
#    detonator-dns service already routes sandbox DNS through dnsmasq, so this is additive.
{
  echo "# EXPERIMENTAL W8 egress allowlist ($TIER). Managed by egress-policy-v2.sh."
  for h in "${HOSTS[@]}"; do
    echo "ipset=/$h/$ALLOW_SET"
  done
} > "$DNSMASQ_D"
systemctl restart detonator-dns.service 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true

# 3. Rewrite the egress chain: keep the existing refusals, then ALLOW the allowlisted set and
#    LOG+REJECT the rest instead of the current blanket RETURN.
iptables -F "$CHAIN"
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A "$CHAIN" ! -p tcp -m limit --limit 100/sec --limit-burst 400 \
  -j LOG --log-prefix "DETONATOR-NONTCP " --log-level 4
iptables -A "$CHAIN" ! -p tcp -j REJECT --reject-with icmp-admin-prohibited
iptables -A "$CHAIN" -p tcp --dport 53 -j REJECT --reject-with tcp-reset
for cidr in 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 0.0.0.0/8; do
  iptables -A "$CHAIN" -d "$cidr" -j REJECT --reject-with icmp-net-prohibited
done
# Allow the resolved allowlist, then refuse everything else — logged first, so the attempt is
# still recorded in the firewall log the Chamber reads back (chamber/egress.py).
iptables -A "$CHAIN" -p tcp -m set --match-set "$ALLOW_SET" dst -j RETURN
iptables -A "$CHAIN" -p tcp -m limit --limit 100/sec --limit-burst 400 \
  -j LOG --log-prefix "DETONATOR-DENIED-EGRESS " --log-level 4
iptables -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset

echo "egress-policy-v2 applied at tier $TIER with $(printf '%s ' "${HOSTS[@]}")"
iptables -S "$CHAIN"
