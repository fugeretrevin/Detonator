#!/usr/bin/env bash
# Install standalone (non-Kubernetes) Tetragon as a systemd service. Idempotent.
# Usage: sudo TETRAGON_VERSION=v1.7.1 ./install_tetragon.sh
set -euo pipefail

VERSION="${TETRAGON_VERSION:-v1.7.1}"
ARCH="amd64"
NAME="tetragon-${VERSION}-${ARCH}"
URL="https://github.com/cilium/tetragon/releases/download/${VERSION}/${NAME}.tar.gz"

MARKER=/etc/tetragon/.installed-version
# Note: `tetragon` has no version subcommand; running it starts a second daemon.
if [[ -f "$MARKER" && "$(cat "$MARKER")" == "$VERSION" ]]; then
  echo "tetragon ${VERSION} already installed"
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  cd "$work"
  curl -fsSLO "$URL"
  curl -fsSLO "${URL}.sha256sum"
  sha256sum -c "${NAME}.tar.gz.sha256sum"
  tar -xzf "${NAME}.tar.gz"
  (cd "$NAME" && ./install.sh)
  echo "$VERSION" > "$MARKER"
fi

# JSON export to a file the Chamber tails; policies load from the .tp.d directory.
install -d -m 0755 /etc/tetragon/tetragon.conf.d /etc/tetragon/tetragon.tp.d /var/log/tetragon
echo "/var/log/tetragon/tetragon.log" > /etc/tetragon/tetragon.conf.d/export-filename
echo "/etc/tetragon/tetragon.tp.d" > /etc/tetragon/tetragon.conf.d/tracing-policy-dir

systemctl daemon-reload
systemctl enable tetragon >/dev/null
systemctl restart tetragon
sleep 3
systemctl is-active tetragon
tetra status 2>/dev/null || true
