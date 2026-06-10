# Raspberry Pi First Boot Package

This directory is the installable edge package for a Raspberry Pi or industrial Linux box.

It does not modify gate operator safety functions. It installs the Angel Gates authorization and evidence services only.

## What It Installs

- `angel-edge.service`: local HTTP API.
- `angel-edge-commissioning.service`: first-boot commissioning payload writer.
- `angel-edge-relay.service`: optional local relay pulse service.
- `angel-edge-camera.service`: optional RTSP evidence clip service.
- `angel-edge-anchor-publisher.service`: optional cloud witness publisher.
- `angel-edge-scanner.service`: optional QR scanner input service.
- `/etc/systemd/system.conf.d/10-angel-edge-watchdog.conf`: systemd hardware watchdog settings.
- `/etc/angel-gates/edge.env`: local runtime configuration.
- `/var/lib/angel-edge`: device key, SQLite store, commissioning payload, and camera clips.

## First Boot

Flash Raspberry Pi OS Lite or the industrial Linux base image, copy this repository onto the device, then run:

```bash
sudo deploy/pi/first-boot-setup.sh
```

The setup script creates the `angel` system user, prepares `/var/lib/angel-edge` with `0750` permissions, creates a Python virtual environment, installs dependencies, copies systemd units, enables commissioning plus the HTTP API, and writes the watchdog manager config.

Before pilot use, edit:

```bash
sudo nano /etc/angel-gates/edge.env
```

Replace every `replace-with-*` token. Keep `/etc/angel-gates/edge.env` readable only by root and the `angel` group.

## Commissioning Payload

On first boot, `angel-edge-commissioning.service` writes:

```text
/var/lib/angel-edge/commissioning-payload.json
```

That command creates the Ed25519 device keypair if it does not exist. If exactly one of `device.key` or `device.key.pub` exists, the runtime refuses the half-present keypair state instead of silently creating a new device identity.

View the payload:

```bash
sudo -u angel cat /var/lib/angel-edge/commissioning-payload.json
```

## Enable Optional Services

Relay service for a live relay HAT:

```bash
sudo systemctl enable --now angel-edge-relay.service
```

Camera capture after `ANGEL_CAMERA_RTSP_URL` is configured:

```bash
sudo systemctl enable --now angel-edge-camera.service
```

QR scanner input after scanner env vars are configured:

```bash
sudo systemctl enable --now angel-edge-scanner.service
```

Cloud anchor publisher after witness URL/token are configured:

```bash
sudo systemctl enable --now angel-edge-anchor-publisher.service
```

## Acceptance

Run the live acceptance battery:

```bash
python -m edge.angel_edge pilot-acceptance \
  --edge-url http://127.0.0.1:8765 \
  --edge-token "$ANGEL_INSTALLER_TOKEN" \
  --gate-id front \
  --relay-channel 26 \
  --observed-relay-clicks 3
```

The relay HAT should click only for the three allow cases.
