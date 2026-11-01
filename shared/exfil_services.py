"""Services that install-time malware uses to send data out or locate its victim.

One list, two uses:
- Brain: rule NET_EXFIL_SERVICE fires on a DNS lookup of, or connect to, any of these.
- Chamber: dnsmasq answers them with SINKHOLE_IP (TEST-NET-2, routes nowhere), so even a
  payload that works leaks nothing to the real service during a detonation.

No benign package in the eval (26 popular installs) contacted any of them.
"""

SINKHOLE_IP = "198.51.100.66"
SINKHOLE_IP6 = "2001:db8::66"  # without it, AAAA lookups were still forwarded upstream

EXFIL_SERVICES: dict[str, str] = {
    # request catchers / webhooks (Shai-Hulud 2025 exfiltrated to webhook.site)
    "webhook.site": "request catcher",
    "pipedream.net": "request catcher",
    "requestbin.com": "request catcher",
    "requestbin.net": "request catcher",
    "beeceptor.com": "request catcher",
    "hookbin.com": "request catcher",
    "canarytokens.com": "request catcher",
    # out-of-band interaction / tunnels
    "interact.sh": "OOB interaction server",
    "oast.fun": "OOB interaction server",
    "oast.pro": "OOB interaction server",
    "oast.live": "OOB interaction server",
    "oast.site": "OOB interaction server",
    "oast.online": "OOB interaction server",
    "oast.me": "OOB interaction server",
    "oastify.com": "OOB interaction server",
    "burpcollaborator.net": "OOB interaction server",
    "ngrok.io": "tunnel",
    "ngrok-free.app": "tunnel",
    "ngrok.app": "tunnel",
    "trycloudflare.com": "tunnel",
    "serveo.net": "tunnel",
    "localhost.run": "tunnel",
    # paste / file drops / chat bots
    "pastebin.com": "paste site",
    "paste.ee": "paste site",
    "hastebin.com": "paste site",
    "transfer.sh": "file drop",
    "file.io": "file drop",
    "api.telegram.org": "chat bot API",
    "discord.com": "chat webhook",
    "discordapp.com": "chat webhook",
    # victim location / public-IP lookups (geofenced payloads, e.g. ua-parser-js 2021)
    "ipinfo.io": "IP lookup",
    "ipapi.co": "IP lookup",
    "ip-api.com": "IP lookup",
    "api.ipify.org": "IP lookup",
    "ifconfig.me": "IP lookup",
    "icanhazip.com": "IP lookup",
    "checkip.amazonaws.com": "IP lookup",
    "freegeoip.app": "IP lookup",
}


def match(domain: str) -> tuple[str, str] | None:
    """(service, kind) if domain is one of the services or a subdomain of one."""
    d = domain.rstrip(".").lower()
    for service, kind in EXFIL_SERVICES.items():
        if d == service or d.endswith("." + service):
            return service, kind
    return None


def dnsmasq_lines() -> str:
    return "".join(
        f"address=/{s}/{SINKHOLE_IP}\naddress=/{s}/{SINKHOLE_IP6}\n" for s in EXFIL_SERVICES
    )


if __name__ == "__main__":  # setup.sh: python -m shared.exfil_services > sinkhole.conf
    print(dnsmasq_lines(), end="")
