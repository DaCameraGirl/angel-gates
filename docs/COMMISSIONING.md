# Commissioning

Commissioning is the control plane for Angel Gates. It binds one physical edge box to one property and gate slot, provisions short-lived scoped tokens, and gives cloud sync a trustworthy identity root.

## Installer View

1. Open the existing gate operator cabinet.
2. Mount the Angel Gates edge box inside the cabinet.
3. Connect DIN-rail power.
4. Connect the relay's normally-open contacts to the operator's open-command input, the same class of input a keypad uses.
5. Connect QR reader, keypad, or other credential readers to the edge box.
6. Connect Ethernet, Wi-Fi, or LTE.
7. Wait for the edge status LED to indicate unclaimed-ready.
8. Open the manager dashboard on a phone or laptop.
9. Tap `Add Gate`.
10. Scan the commissioning QR printed by the edge.
11. Confirm the property and gate slot.
12. The edge signs the cloud claim challenge.
13. Cloud returns a signed binding artifact.
14. The edge applies the artifact and enters `claimed_pending_cloud` if the property network is offline, or `claimed` after cloud sync is confirmed.

No gate safety loop, photo eye, reversing edge, operator board safety function, or UL 325 safety device is modified by this flow.

## Hardware Boundary

Angel Gates makes the brain, not the safety system.

- Built by Angel Gates: Linux edge box, relay intent, local authorization runtime, event log.
- Bought off the shelf: QR reader, keypad, optional LPR camera, optional non-safety presence input.
- Existing operator domain: barrier arm, motor controller, loops, photo eyes, reversing edges, entrapment protection, operator safety logic.

The edge relay must be de-energized by default. Power loss means no Angel Gates relay intent is sent.

## Per-Gate And Per-Property Model

- One edge box per gate cabinet is the default.
- One edge box can drive multiple relays/readers only when the cabinets and wiring layout support it cleanly.
- One property workspace owns the resident list, credential set, audit log, and manager dashboard.
- Each gate is an endpoint under that property workspace.

## Device Identity

On first boot, the edge creates an Ed25519 device keypair:

```text
/var/lib/angel-edge/device.key
/var/lib/angel-edge/device.key.pub
```

The private key never leaves the edge.

The device ID is the fingerprint of the public key. If exactly one of the private/public files exists, the edge refuses to identify itself instead of silently generating a new identity.

## Commissioning QR

The QR payload is not authority. It is only a claim request:

```json
{
  "device_id": "agd_...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
  "bootstrap_nonce": "...",
  "commissioning_status": "unclaimed",
  "payload_version": 1
}
```

Someone photographing this QR cannot open a gate or claim the device without completing the signed challenge round-trip.

## Claim Challenge

Cloud sends a challenge bound to the exact property and gate slot:

```json
{
  "nonce": "...",
  "device_id": "agd_...",
  "property_id": "property_...",
  "gate_id": "front",
  "issued_at": "2026-06-10T18:00:00Z"
}
```

The edge signs the whole tuple with its device private key. Cloud verifies the signature against the public key from the QR payload.

## Binding Artifact

Cloud returns an Ed25519-signed binding artifact:

```json
{
  "payload": {
    "binding_id": "binding_...",
    "device_id": "agd_...",
    "bootstrap_nonce": "...",
    "property_id": "property_...",
    "property_label": "Pilot Property",
    "gate_id": "front",
    "issued_at": "2026-06-10T18:00:05Z",
    "status": "claimed_pending_cloud",
    "api_tokens": []
  },
  "signature": "...",
  "algorithm": "Ed25519"
}
```

The edge verifies this artifact using the cloud binding public key pinned into the edge image or provided through a trusted local installer channel.

## Offline Commissioning

If the gate cabinet has no working internet, the installer can still complete commissioning from a phone or laptop that has cloud reachability through a hotspot.

The installer device scans the QR, cloud mints the binding artifact, and the artifact is applied locally to the edge over LAN or SSH. The edge can then operate as `claimed_pending_cloud` until property connectivity comes online and normal sync begins.

## Tokens

The device key is the root identity. Tokens are leaves.

Tokens are short-lived and scoped:

- `dashboard`
- `installer`
- `edge-api`
- `edge-sync`
- `anchor-publish`

Compromised token: rotate or let it expire.

Compromised device key: physical service event; pull or factory-reset the box.

## Revocation

Cloud can revoke a binding through sync. Once the edge receives binding revocation:

1. It writes `binding_revoked`.
2. It revokes local API tokens.
3. It anchors the revocation event.
4. It stops authorizing access immediately.

Factory reset is local only. It is not exposed through the HTTP API.

## SD Card Replacement

If an edge loses its device key, it is a new device identity. The support path is installer-initiated rebind, not device impersonation:

1. Mark the old binding superseded.
2. Preserve old event history.
3. Bind the new device ID to the existing property/gate slot.
4. Resume sync from the new edge identity.

Do not let a fresh SD card silently impersonate the old edge.

The cloud registry helper stores active and superseded bindings in a registry database. Register the old binding payload and its latest preserved history reference:

```bash
python -m edge.angel_edge --db cloud-binding-registry.sqlite3 cloud-register-binding \
  --binding-file old-binding.json \
  --event-history-ref witness:edge-old:sequence-4200
```

After the replacement edge prints a new commissioning payload, create a rebind artifact for that new device ID and bootstrap nonce:

```bash
python -m edge.angel_edge --db cloud-binding-registry.sqlite3 cloud-create-rebind \
  --cloud-private-key-file cloud-binding-private.pem \
  --new-device-id agd_new_device_id \
  --new-bootstrap-nonce new_bootstrap_nonce \
  --property-id property-1 \
  --property-label "Pilot Property" \
  --gate-id front \
  --reason sd_card_loss \
  --preserved-history-ref witness:edge-old:sequence-4200 \
  --output-file rebind-artifact.json
```

Apply `rebind-artifact.json` to the replacement edge with the normal `apply-binding` command. The edge records `rebind_id`, `replaces_binding_id`, `replaces_device_id`, and `rebind_preserved_history_ref` in local metadata and writes a `binding_rebind_applied` event.
