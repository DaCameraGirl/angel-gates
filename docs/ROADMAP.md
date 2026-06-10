# Roadmap

This roadmap keeps the product spine clear: edge box first, event log first, everything else as clients over those two pieces.

## Shipped

- Edge authorization runtime: local SQLite authorization keeps residents and already-synced visitor passes working without cloud reachability.
- Hash-chained event log: every access/configuration event is tamper-evident from a fixed genesis record.
- Head anchors: edge can anchor the current sequence and hash so tail truncation can be detected after cloud witness.
- Cloud witness: edge can publish anchors every 100 events, after 5 minutes with new events, and after revocation; witness storage is append-only per edge and rejects forked anchor streams.
- QR tokens: signed Ed25519 visitor QR tokens verify locally using cached public keys.
- Offline/degraded mode: the edge decides from cache and queues events while connectivity is down.
- Dashboard-over-edge: the browser dashboard no longer makes allow/deny decisions; it asks the edge API.
- Local API hardening: scoped short-lived tokens, WAL, busy timeout, single-writer discipline, and SSE event feed.
- Commissioning control plane: device key, claim challenge, binding artifact, local factory reset, and binding revocation exist.
- PIN/QR rate limits: failed PIN and QR attempts now create persistent gate/type and credential-scope lockouts with audit events.
- Relay driver boundary: allow decisions can dispatch momentary relay pulses through a local relay service with cooldown and relay audit events.
- QR scanner input: stdin, serial, and Linux evdev scanner modes submit QR payloads to the edge authorization API without creating another decision engine.
- Camera clip capture: the edge can dispatch short RTSP evidence clips after allow/deny gate events and record clip or failure metadata in the hash-chained log.
- Pilot acceptance runner: live edge HTTP service test covers PIN, QR, plate, denial cases, events, SSE, head anchors, verify-log, and relay-click expectation.
- First-boot Pi package: setup script, systemd units, environment template, commissioning payload writer, key-directory permissions, and watchdog manager config.
- SD-card-loss rebind: cloud registry helpers supersede the old binding, preserve history reference, and mint a new binding artifact for the replacement device identity.
- LPR pilot plan: rear-plate-aware geometry, shadow-mode metrics, confidence fallback, and privacy/retention boundaries are documented for phase two.
- Chargeback incident export: gate/time-window reports can export integrity JSON, manager CSV, and printable Markdown from real edge events with linked camera/relay evidence.
- OEM cloud evaluation plan: later integration triggers, disqualifiers, due diligence, and adapter boundaries are documented without changing the retrofit-first compatibility story.

## Next

- Cloud binding and token rotation: use the device key as root identity and rotate dashboard, sync, and anchor tokens as leaves.

## Later

- LPR production workflow: implement rear-plate-aware capture and assisted authorization only after QR/PIN proves the first pilot.
- Chargeback PDF generation: turn exported incident packets into polished PDFs after the pilot proves the workflow.
- Multi-tenant SaaS cloud: add property tenants, user roles, billing, support tools, and cloud-side anchor storage.
- Intercom/video call: only after the access/audit product is working, because multifamily video workflows are a different competitive set.
- Installer mobile app: defer until the dashboard role-gated commissioning page proves the workflow.
- OEM cloud adapters: build only after a property-authorized request and official partner path prove they reduce manager work without replacing local authorization.
