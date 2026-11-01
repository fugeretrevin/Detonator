#!/usr/bin/env bash
# Idempotent Chamber VM bootstrap (BUILD_PLAN B0). Run from a checkout of the repo:
#   sudo bash chamber/provision/setup.sh
# Rebuilds a burned VM in a few minutes. Prints nothing secret.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP=/opt/pr-detonator
ENV_FILE=/etc/pr-detonator/env

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
[[ -e /sys/kernel/btf/vmlinux ]] || { echo "kernel lacks BTF; Tetragon will not load"; exit 1; }

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3-venv git jq curl ca-certificates \
  dnsmasq-base >/dev/null
command -v docker >/dev/null || apt-get install -y -qq docker.io >/dev/null
systemctl enable --now docker >/dev/null

echo "== tetragon"
bash "$REPO/chamber/provision/install_tetragon.sh"
install -m 0644 "$REPO/chamber/policies/tcp-connect.yaml" /etc/tetragon/tetragon.tp.d/
install -m 0644 "$REPO/chamber/policies/credential-files.yaml" /etc/tetragon/tetragon.tp.d/
# Bigger export file so a rotation mid-detonation is very unlikely.
echo 200 > /etc/tetragon/tetragon.conf.d/export-file-max-size-mb
systemctl restart tetragon

echo "== app code -> $APP"
install -d -m 0755 "$APP" /var/lib/pr-detonator/jobs
rm -rf "$APP/shared" "$APP/chamber"
cp -r "$REPO/shared" "$REPO/chamber" "$APP/"
[[ -x "$APP/venv/bin/python" ]] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/chamber/requirements.txt"

echo "== secret"
install -d -m 0700 /etc/pr-detonator
if [[ ! -s "$ENV_FILE" ]]; then
  umask 077
  printf 'CHAMBER_SECRET=%s\n' "$(openssl rand -hex 32)" > "$ENV_FILE"
  echo "generated new CHAMBER_SECRET in $ENV_FILE (copy it into the Modal 'chamber' secret)"
fi
chmod 600 "$ENV_FILE"

echo "== tls"
# Self-signed, for this VM's public IP; the Brain trusts exactly this certificate
# (CHAMBER_CA_PEM in the Modal 'chamber' secret). Regenerated only if missing.
TLS_DIR=/etc/pr-detonator/tls
if [[ ! -s "$TLS_DIR/cert.pem" ]]; then
  install -d -m 0700 "$TLS_DIR"
  IMDS_TOKEN=$(curl -fsS -X PUT http://169.254.169.254/latest/api/token \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  PUBLIC_IP=$(curl -fsS -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
    http://169.254.169.254/latest/meta-data/public-ipv4)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
    -subj "/CN=pr-detonator-chamber" -addext "subjectAltName=IP:$PUBLIC_IP,IP:127.0.0.1" \
    -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" 2>/dev/null
  chmod 600 "$TLS_DIR/key.pem"
  chmod 644 "$TLS_DIR/cert.pem"
  echo "generated TLS cert for $PUBLIC_IP (put $TLS_DIR/cert.pem in the Modal 'chamber' secret)"
fi

echo "== sandbox image"
docker build -q -t detonator-sandbox:latest "$REPO/chamber/sandbox" >/dev/null

echo "== services"
install -m 0644 "$REPO/chamber/provision/detonator-egress.service" /etc/systemd/system/
install -m 0644 "$REPO/chamber/provision/detonator-dns.service" /etc/systemd/system/
install -m 0644 "$REPO/chamber/provision/chamber.service" /etc/systemd/system/
install -m 0644 "$REPO/chamber/provision/dnsmasq.conf" /etc/pr-detonator/dnsmasq.conf
(cd "$APP" && venv/bin/python -m shared.exfil_services) > /etc/pr-detonator/sinkhole.conf
chmod 0644 /etc/pr-detonator/sinkhole.conf
install -m 0644 "$REPO/chamber/provision/detonator-dns.logrotate" /etc/logrotate.d/detonator-dns
install -d -m 0755 /var/log/pr-detonator
systemctl daemon-reload
systemctl enable detonator-egress detonator-dns chamber >/dev/null
systemctl restart detonator-egress
systemctl restart detonator-dns
systemctl restart chamber
sleep 3

echo "== health"
curl -fsS --cacert /etc/pr-detonator/tls/cert.pem https://127.0.0.1:8443/health && echo
