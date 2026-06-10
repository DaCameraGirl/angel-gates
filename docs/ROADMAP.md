# Roadmap

This roadmap keeps the product spine clear: edge box first, event log first, everything else as clients over those two pieces.

## Shipped

- Edge authorization runtime: local SQLite authorization keeps residents and already-synced visitor passes working without cloud reachability.
- Hash-chained event log: every access/configuration event is tamper-evident from a fixed genesis record.
- Head anchors: edge can anchor the current sequence and hash so tail truncation can be detected after cloud witness.
- QR tokens: signed Ed25519 visitor QR tokens verify locally using cached public keys.
- Offline/degraded mode: the edge decides from cache and queues events while connectivity is down.
- Dashboard-over-edge: the browser dashboard no longer makes allow/deny decisions; it asks the edge API.
- Local API hardening: scoped short-lived tokens, WAL, busy timeout, single-writer discipline, and SSE event feed.
- Commissioning control plane: device key, claim challenge, binding artifact, local factory reset, and binding revocation exist.
- PIN/QR rate limits: failed PIN and QR attempts now create persistent gate/type and credential-scope lockouts with audit events.

## Next

- Cloud sync and anchor publishing: edge should publish anchors every 100 events, every 5 minutes, and immediately on revocation because cloud witness is what makes truncation externally detectable.
- Pilot acceptance test: run the real edge service over LAN against PIN, QR, plate, bad bearer, revoked credential, expired QR, low-confidence plate, event replay, anchor, and verify-log paths.
- QR scanner driver: ingest USB HID or serial scanner output and submit QR payloads to the edge authorization path.
- Relay driver: map an allow decision to a configured relay channel with de-energized default and no inverted open behavior.
- First-boot Pi image: package systemd services, key directory permissions, local API, watchdog, and commissioning payload display.
- SD-card-loss rebind: support replacing an edge identity for an existing property/gate slot while preserving old event history.
- Cloud binding and token rotation: use the device key as root identity and rotate dashboard, sync, and anchor tokens as leaves.

## Later

- LPR: add rear-plate-aware lane geometry and confidence fallback after QR/PIN proves the first pilot.
- Chargeback reports: turn event/photo windows into incident packets for damaged gate arms and unauthorized access disputes.
- Multi-tenant SaaS cloud: add property tenants, user roles, billing, support tools, and cloud-side anchor storage.
- Intercom/video call: only after the access/audit product is working, because multifamily video workflows are a different competitive set.
- Installer mobile app: defer until the dashboard role-gated commissioning page proves the workflow.
- OEM cloud integrations: myQ Community, DKS, and other OEM APIs are upgrades, not the v1 compatibility path.
