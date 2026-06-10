# Angel Gates

Angel Gates is an edge-first access authorization platform for gated properties.

The product spine is the edge box and the event log:

- The edge box makes local authorization decisions without depending on cloud reachability.
- The event log proves what happened with a hash-chained, tamper-evident record.

Resident apps, visitor apps, dashboards, reports, and cloud sync are clients over those two pieces.

The app starts with an empty local workspace. There are no seeded residents, passes, controllers, integrations, alerts, or audit records.

## Edge First

The local edge runtime lives in `edge/`.

It includes:

- SQLite credential cache.
- Local PIN, plate, and signed QR authorization.
- Ed25519 QR token verification using cached public keys.
- Revocation support for credentials and QR tokens.
- Offline event queueing.
- Hash-chained event log verification.
- Fixed genesis event and head anchors for truncation detection.
- Commissioning identity with local device keys, signed claims, binding artifacts, and scoped API tokens.
- Local HTTP API for reader/controller integration.
- Local relay service with logging and GPIO drivers for momentary relay pulses.
- Sync delta intake for cloud-to-edge updates.

Start here:

```powershell
python -m edge.angel_edge --db edge-data/angel-edge.sqlite3 init --edge-id property-edge-001
python -m unittest edge.tests.test_edge_runtime
```

## Product Buckets

### V1 Scope

- Resident app and manager-operated resident records.
- Visitor passes with time windows.
- License plate, QR, and PIN credential decisions.
- Manager dashboard with audit logs.
- Maintenance alerts tied to real controller records.
- Cloud sync settings, workspace export, and workspace import.
- Integration records for DoorKing, Linear, LiftMaster, custom relay controllers, and cloud APIs.
- Retrofit controller model that emits momentary relay pulses only after authorization.
- Local-first authorization with offline/degraded mode.
- Revocation propagation target under 30 seconds while online.
- Tamper-evident event trail for disputes, break-ins, move-outs, and board review.

### Safety And Compliance Boundary

- Design the access-control layer with UL 294 considerations in mind.
- Treat barrier and gate operator motion as a separate UL 325 safety domain.
- Do not bypass certified operators, entrapment protection, installer commissioning, loops, photo eyes, reversing edges, or site safety procedures.
- Keep this app as an authorization and audit layer until certified controller hardware and professional installation are part of the deployment.

This repository is not a certification claim, legal opinion, installer manual, or hardware safety approval.

## What's Not In Scope Yet

- LPR production workflow.
- Intercom or video-call visitor workflow.
- OEM cloud integrations such as myQ Community or DKS cloud APIs.
- Multi-tenant SaaS billing and administration.
- Dedicated installer mobile app.
- Automated chargeback PDF generation.

## Run Locally

Open `index.html` in a browser for the current dashboard shell. The app uses browser local storage and has no package dependencies.

Run the edge checks:

```powershell
python -m compileall edge
python -m unittest edge.tests.test_edge_runtime
```

Optional syntax check:

```powershell
node --check src/app.js
```

## Project Shape

- `index.html` - application shell.
- `styles.css` - responsive industrial operations UI.
- `src/app.js` - dashboard shell, direct edge API panel, local workspace forms, audit events, export, and import.
- `edge/` - local edge controller runtime and tests.
- `docs/EDGE_ARCHITECTURE.md` - edge-first product architecture.
- `docs/COMMISSIONING.md` - installer-facing commissioning and device identity flow.
- `docs/ROADMAP.md` - shipped, next, and later work with rationale.
- `docs/PILOT.md` - first-property pilot plan and success metrics.
- `docs/HARDWARE.md` - physical bill of materials and wiring boundary.
- `docs/PRICING.md` - working pricing model and competitive positioning.
- `docs/THREAT_MODEL.md` - security risks, mitigations, and gaps.
- `docs/CHARGEBACK.md` - incident and damaged-arm evidence workflow.
- `docs/SAFETY_BOUNDARY.md` - UL 294 / UL 325 boundary language.

## Data Policy

The app stores only records entered through the browser UI or imported from a workspace JSON file. Clearing browser storage or using the in-app clear action removes local records from that browser.

The edge runtime creates schema only. It does not seed controller, resident, visitor, pass, credential, integration, or audit data.
