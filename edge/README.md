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

## Local HTTP API

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 serve --host 127.0.0.1 --port 8765
```

Endpoints:

- `GET /health`
- `GET /events`
- `GET /events/stream`
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

## Anchor The Current Head

Cloud sync should periodically store the current edge head hash and sequence. The local command records the anchor payload that the cloud service should acknowledge:

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 anchor-head --anchor-type cloud_pending
```

When the cloud stores that sequence and hash, later tail truncation becomes detectable because a shortened local chain can no longer satisfy the latest known anchor.
