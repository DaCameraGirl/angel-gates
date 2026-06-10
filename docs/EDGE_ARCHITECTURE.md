# Edge Architecture

Angel Gates is edge-first. The dashboard and apps are clients. The edge box and event log are the product spine.

## Directive

Build the edge box and event log first.

The edge box makes local authorization decisions. The event log proves what happened. Resident apps, visitor apps, dashboards, reports, and cloud sync are skins over those two pieces.

## Edge Box Decision

Use a Linux SBC or industrial Linux box, not a bare microcontroller.

Baseline requirements:

- Local SQLite credential cache.
- Local Ed25519 QR verification.
- Local access decision in under 200 ms.
- Hardware watchdog.
- OTA update path.
- TLS client identity for cloud sync.
- Relay output that is de-energized by default.
- No wiring design that holds a gate open.
- Power loss leaves the gate operator behaving as it did before Angel Gates was installed.

## Authorization Tuple

Every access decision is shaped as:

```text
principal, credential, gate, time, decision, reason
```

Optional attached context:

- plate confidence
- fallback requirement
- photo or plate crop reference
- edge ID
- sync cursor
- relay intent

## Offline And Degraded Mode

The gate cannot depend on cloud reachability.

The edge keeps:

- residents
- active visitor passes
- PIN credentials
- plate credentials
- signed QR public keys
- revocation lists
- token use counts
- event sync queue

Cloud pushes deltas. Edge applies and acknowledges them. When offline, the edge keeps authorizing from cache and queues audit events.

Target revocation propagation while online: under 30 seconds from manager action to edge apply.

Offline truth: passes issued after the last successful sync may not work yet. Already-synced residents and passes keep working.

## Credential Rules

- Visitor passes require expiry, gate scope, and optional max uses.
- Resident PINs are per-unit and should rotate on move-out.
- Plates require a confidence threshold. Default threshold is 0.85.
- Low-confidence plate reads should require fallback PIN or QR instead of becoming a silent denial.
- QR codes are signed and verified locally, not looked up in the cloud authorization path.

## Event Log

Every access attempt writes an event before any relay intent leaves the authorization layer.

The edge log is:

- append-only at the application layer
- hash-chained
- timestamped
- credential-attributed when known
- synced to cloud when online
- retained locally on a rolling policy

The SQLite implementation stores each event with `previous_hash` and `event_hash`. Verification recalculates from sequence one and reports the first broken link.

## Integration Strategy

Do not start with OEM cloud APIs.

Dry contact and Wiegand-compatible handoff cover the long tail of installed gate operators. DoorKing, Linear, LiftMaster, Nice, FAAC, and older HOA or storage-lot installs can be reached through the retrofit path.

Brand-specific cloud integrations are later upgrades, not the core compatibility story.

## Beachhead

Start with self-storage, small HOAs, and private roads.

These buyers have older hardware, clear audit pain, fewer corporate procurement layers, and a strong need for offline access and dispute records.
