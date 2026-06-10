#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "first-boot-setup.sh must run as root" >&2
  exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_SRC=${ANGEL_REPO_SRC:-$(cd -- "$SCRIPT_DIR/../.." && pwd)}
INSTALL_DIR=${ANGEL_INSTALL_DIR:-/opt/angel-gates}
EDGE_USER=${ANGEL_EDGE_USER:-angel}
EDGE_GROUP=${ANGEL_EDGE_GROUP:-angel}

apt-get update
apt-get install -y python3-venv python3-pip ffmpeg rsync watchdog

if ! id "$EDGE_USER" >/dev/null 2>&1; then
  useradd --system --home /var/lib/angel-edge --shell /usr/sbin/nologin "$EDGE_USER"
fi

for group_name in gpio dialout video input; do
  if getent group "$group_name" >/dev/null 2>&1; then
    usermod -a -G "$group_name" "$EDGE_USER"
  fi
done

install -d -o root -g root -m 0755 "$INSTALL_DIR"
rsync -a --delete \
  --exclude .git \
  --exclude edge-data \
  "$REPO_SRC"/ "$INSTALL_DIR"/

install -d -o "$EDGE_USER" -g "$EDGE_GROUP" -m 0750 /var/lib/angel-edge
install -d -o "$EDGE_USER" -g "$EDGE_GROUP" -m 0750 /var/lib/angel-edge/camera-clips
install -d -o "$EDGE_USER" -g "$EDGE_GROUP" -m 0750 /var/log/angel-edge
install -d -o root -g "$EDGE_GROUP" -m 0750 /etc/angel-gates

if [[ ! -f /etc/angel-gates/edge.env ]]; then
  install -o root -g "$EDGE_GROUP" -m 0640 "$INSTALL_DIR/deploy/pi/env/angel-edge.env.example" /etc/angel-gates/edge.env
fi

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/edge/requirements.txt"
"$INSTALL_DIR/.venv/bin/pip" install gpiozero pyserial

chown -R root:root "$INSTALL_DIR"
chown -R "$EDGE_USER:$EDGE_GROUP" /var/lib/angel-edge /var/log/angel-edge

install -m 0644 "$INSTALL_DIR"/deploy/pi/systemd/*.service /etc/systemd/system/
install -d -m 0755 /etc/systemd/system.conf.d
install -m 0644 "$INSTALL_DIR"/deploy/pi/systemd/system.conf.d/*.conf /etc/systemd/system.conf.d/

systemctl daemon-reload
systemctl enable angel-edge-commissioning.service angel-edge.service

echo "Angel Gates first-boot setup complete."
echo "Edit /etc/angel-gates/edge.env, then run:"
echo "  systemctl restart angel-edge-commissioning.service angel-edge.service"
