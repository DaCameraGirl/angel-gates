# Angel Edge Runtime

Angel Edge is the local authorization runtime for Angel Gates. It is the part that matters when the internet is down.

The edge keeps a local SQLite cache of gates, resident credentials, visitor credentials, QR public keys, revocations, token usage, and an append-only event log. Every access attempt is decided locally and logged before the controller emits any relay intent.

## Guarantees

- Local authorization path: no cloud call is required to allow or deny access.
- Safe relay posture: the runtime returns `relay_intent: true` only after an allow decision.
- Offline cache: residents and already-synced passes keep working during an outage.
- Revocation story: online target is under 30 seconds from cloud delta to edge apply.
- QR verification: Ed25519-signed visitor QR tokens are verified using cached public keys.
- Event log: access and configuration events are hash-chained for tamper evidence.
- Genesis and anchors: the log starts from a fixed genesis event and can anchor its current head upstream so tail truncation is detectable.
- No seeded data: initialization creates schema only.

## Install

Python 3.11 is expected. Install the crypto dependency if it is not already available:

```powershell
python -m pip install -r edge/requirements.txt
```

The Raspberry Pi GPIO relay driver additionally needs `gpiozero` on the edge box. The logging relay driver and test suite do not require it.

## Initialize

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 init --edge-id property-edge-001
```

## Commission The Edge

Create or read the device identity and print the commissioning QR payload:

```bash
python -m edge.angel_edge \
  --db edge-data/angel-edge.sqlite3 \
  --device-key-file edge-data/device.key \
  commissioning-payload
```

Sign a cloud claim challenge that includes `nonce`, `device_id`, `property_id`, `gate_id`, and `issued_at`:

```bash
python -m edge.angel_edge \
  --db edge-data/angel-edge.sqlite3 \
  --device-key-file edge-data/device.key \
  sign-claim-challenge --challenge-file edge-data/claim-challenge.json
```

Apply a cloud-signed binding artifact:

```bash
python -m edge.angel_edge \
  --db edge-data/angel-edge.sqlite3 \
  --device-key-file edge-data/device.key \
  apply-binding \
  --binding-file edge-data/binding.json \
  --cloud-public-key-file edge-data/cloud-binding-public.pem
```

For SD-card loss or box replacement, cloud support should create a rebind artifact for the replacement edge identity instead of reusing the old key. Register the old binding in the cloud registry DB:

```bash
python -m edge.angel_edge --db cloud-binding-registry.sqlite3 cloud-register-binding \
  --binding-file edge-data/old-binding.json \
  --event-history-ref witness:edge-old:sequence-4200
```

Create the replacement binding artifact from the new edge commissioning payload:

```bash
python -m edge.angel_edge --db cloud-binding-registry.sqlite3 cloud-create-rebind \
  --cloud-private-key-file edge-data/cloud-binding-private.pem \
  --new-device-id agd_new_device_id \
  --new-bootstrap-nonce new_bootstrap_nonce \
  --property-id property-1 \
  --property-label "Pilot Property" \
  --gate-id front \
  --reason sd_card_loss \
  --preserved-history-ref witness:edge-old:sequence-4200 \
  --output-file edge-data/rebind-artifact.json
```

Apply the rebind artifact with the same `apply-binding` command. The replacement edge remains a new device identity and records the old binding/device lineage locally.

Issue a short-lived dashboard token:

```bash
python -m edge.angel_edge \
  --db edge-data/angel-edge.sqlite3 \
  issue-api-token \
  --label "Pilot dashboard" \
  --scope dashboard \
  --ttl-hours 24
```

## Add A Gate

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 add-gate `
  --gate-id front `
  --name "Front Gate" `
  --site-area "Main Entry" `
  --provider "DoorKing" `
  --interface-type dry-contact `
  --operator-class "barrier gate operator" `
  --hardware-id "relay-bank-1" `
  --relay-channel 26 `
  --relay-pulse-ms 500 `
  --relay-cooldown-ms 1500 `
  --safety-ack
```

## Add A Resident PIN

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 add-credential `
  --credential-id unit-101-pin `
  --principal-id unit-101 `
  --principal-label "Unit 101" `
  --principal-type resident `
  --credential-type pin `
  --credential-value 582914 `
  --gate front
```

## Authorize Locally

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 authorize `
  --credential-type pin `
  --credential-value 582914 `
  --gate-id front
```

The response includes the decision, reason, event ID, event hash, and whether relay intent is authorized.

## Relay Service

The relay service is a separate local process that owns GPIO access. It accepts only bounded momentary pulse requests and records actual relay pulses back into the hash-chained event log.

Run a hardware-free logging relay service for development:

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 relay-service `
  --host 127.0.0.1 `
  --port 8766 `
  --token local-relay-token `
  --driver logging
```

Run with the Raspberry Pi GPIO driver on the edge box:

```bash
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 relay-service \
  --host 127.0.0.1 \
  --port 8766 \
  --token "$ANGEL_RELAY_TOKEN" \
  --driver gpio
```

For `--driver gpio`, `relay_channel` is a BCM GPIO number. The relay board must be active-high and wired through normally-open contacts.

Connect the HTTP authorization API to the local relay service:

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 serve `
  --host 127.0.0.1 `
  --port 8765 `
  --relay-url http://127.0.0.1:8766 `
  --relay-token local-relay-token
```

## Camera Capture Service

The camera service is a separate local process that owns RTSP and ffmpeg work. The authorization API only dispatches capture requests after the access decision has been written to the event log. Video capture success or failure never changes the allow/deny result or blocks a relay pulse.

Run the camera service with an RTSP camera:

```bash
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 camera-service \
  --host 127.0.0.1 \
  --port 8767 \
  --token "$ANGEL_CAMERA_TOKEN" \
  --rtsp-url "rtsp://user:pass@camera.local/stream1" \
  --camera-id front-gate-cam \
  --storage-path edge-data/camera-clips \
  --clip-seconds 8 \
  --retention-days 14
```

Connect the HTTP authorization API to the local camera service:

```bash
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 serve \
  --host 127.0.0.1 \
  --port 8765 \
  --camera-url http://127.0.0.1:8767 \
  --camera-token "$ANGEL_CAMERA_TOKEN"
```

When capture succeeds, the edge records a hash-chained `camera_clip_captured` event with the clip path and the linked access event ID/hash. When capture fails, it records `camera_capture_error` without logging the raw RTSP URL.

## Signed Visitor QR Flow

Create a signing keypair for cloud/dev signing:

```powershell
python -m edge.angel_edge generate-keypair `
  --private-key-file edge-data/cloud-qr-private.pem `
  --public-key-file edge-data/cloud-qr-public.pem
```

Cache the public key on the edge:

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 add-qr-public-key `
  --key-id cloud-key-1 `
  --public-key-file edge-data/cloud-qr-public.pem
```

Issue a signed QR token:

```powershell
python -m edge.angel_edge issue-qr-token `
  --private-key-file edge-data/cloud-qr-private.pem `
  --key-id cloud-key-1 `
  --token-id pass-2026-001 `
  --principal-id visitor-2026-001 `
  --principal-label "Approved Visitor" `
  --gate front `
  --expires-at 2026-06-10T23:00:00Z `
  --max-uses 2
```

The edge can authorize that QR without cloud reachability as long as the public key and revocation list are cached.

## QR Scanner Service

The scanner service reads QR text from a local reader and submits it to the same `POST /authorize` path as every other edge client. It does not verify or authorize credentials itself.

Run a keyboard-wedge or bench scanner that sends scans to stdin:

```powershell
python -m edge.angel_edge scanner-service `
  --edge-url http://127.0.0.1:8765 `
  --edge-token local-edge-token `
  --gate-id front `
  --scanner-id pedestal-qr-1 `
  --input stdin
```

Run a serial or USB CDC scanner:

```bash
python -m edge.angel_edge scanner-service \
  --edge-url http://127.0.0.1:8765 \
  --edge-token "$ANGEL_EDGE_TOKEN" \
  --gate-id front \
  --scanner-id pedestal-qr-1 \
  --input serial \
  --serial-port /dev/ttyACM0 \
  --baudrate 9600
```

Run a Linux keyboard-event scanner:

```bash
python -m edge.angel_edge scanner-service \
  --edge-url http://127.0.0.1:8765 \
  --edge-token "$ANGEL_EDGE_TOKEN" \
  --gate-id front \
  --scanner-id pedestal-qr-1 \
  --input evdev \
  --evdev-path /dev/input/event4
```

Serial mode requires `pyserial` on the edge box. Evdev mode requires Linux input-device permissions and the correct scanner device path.

## Local HTTP API

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 serve --host 127.0.0.1 --port 8765
```

Endpoints:

- `GET /health`
- `GET /events`
- `GET /events/stream`
- `GET /verify-log`
- `POST /authorize`
- `POST /sync/delta`
- `POST /anchors/head`

Every endpoint requires:

```text
Authorization: Bearer <scoped-short-lived-token>
```

## Verify The Event Log

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 verify-log
```

The verifier recalculates every hash from the beginning of the log and reports the first broken sequence if anything was modified.

The same check is available over the local API for installer acceptance:

```bash
curl -H "Authorization: Bearer $ANGEL_INSTALLER_TOKEN" http://127.0.0.1:8765/verify-log
```

## Export An Incident Report

Managers can export a damaged-arm incident packet from a gate and time window. The JSON report carries the integrity data, the CSV is the manager-readable event table, and the Markdown file is the printable packet for invoice, resident notice, insurer, or board review.

```bash
python -m edge.angel_edge --db "$ANGEL_EDGE_DB" export-incident-report \
  --gate-id "$INCIDENT_GATE_ID" \
  --started-at "$INCIDENT_STARTED_AT" \
  --ended-at "$INCIDENT_ENDED_AT" \
  --property-label "$PROPERTY_LABEL" \
  --selected-event-id "$SELECTED_EVENT_ID" \
  --manager-notes-file incident-notes.txt \
  --json-output incident-report.json \
  --csv-output incident-events.csv \
  --markdown-output incident-report.md
```

The report includes access, relay, and camera events for the window, plus linked relay/camera evidence that references an access decision event ID and hash. It does not invent a responsible party; the manager selects the likely event from the real log.

## Anchor The Current Head

Cloud sync should periodically store the current edge head hash and sequence. The local command records an anchor without publishing it:

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 anchor-head --anchor-type cloud_pending
```

When the cloud stores that sequence and hash, later tail truncation becomes detectable because a shortened local chain can no longer satisfy the latest known anchor.

## Publish Anchors To Witness Storage

The witness service is the append-only cloud-side store for edge head anchors. Use a separate database from the edge runtime:

```bash
python -m edge.angel_edge --db edge-data/witness.sqlite3 witness-service \
  --host 127.0.0.1 \
  --port 8770 \
  --token "$ANGEL_WITNESS_TOKEN"
```

Run the edge publisher loop against that witness:

```bash
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 anchor-publisher \
  --witness-url http://127.0.0.1:8770 \
  --witness-token "$ANGEL_WITNESS_TOKEN" \
  --poll-seconds 10
```

The publisher sends the current head when any publish trigger is due:

- no previous cloud witness anchor exists
- 100 new events since the previous witness anchor
- 5 minutes have elapsed and new events exist
- a local credential, QR token, or binding revocation anchor has not been witnessed

For one-shot operation:

```bash
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 publish-anchor \
  --witness-url http://127.0.0.1:8770 \
  --witness-token "$ANGEL_WITNESS_TOKEN"
```

The witness store is append-only per edge. It accepts exact duplicate publishes, but rejects stale anchors, duplicate sequences with different hashes, and anchors that do not extend the previously witnessed sequence/hash.

## Pilot Acceptance Runner

Run the live acceptance battery against the actual edge HTTP service:

```bash
python -m edge.angel_edge pilot-acceptance \
  --edge-url http://127.0.0.1:8765 \
  --edge-token "$ANGEL_INSTALLER_TOKEN" \
  --gate-id front \
  --relay-channel 26 \
  --observed-relay-clicks 3
```

The token must have `installer` or `*` scope because the runner applies a test sync delta, authorizes test credentials, reads events, anchors the head, and verifies the log. The runner expects three allow cases, so a hardware installer should hear exactly three relay clicks and none for deny cases.

`--include-binding-revocation` is intentionally not part of the default run. It revokes local API tokens on the target edge and should be used only on a disposable acceptance image or when reset access is confirmed.
