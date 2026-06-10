# Angel Gates

Angel Gates is a production-minded starting point for a modern gate access-control layer. It focuses on authorization, resident and visitor workflows, manager operations, auditability, maintenance visibility, cloud handoff, and integration records for existing gate systems.

The app starts with an empty local workspace. There are no seeded residents, passes, controllers, integrations, alerts, or audit records.

## Product Buckets

### Good Startup Idea

- Resident app and manager-operated resident records.
- Visitor passes with time windows.
- License plate, QR, and PIN credential decisions.
- Manager dashboard with audit logs.
- Maintenance alerts tied to real controller records.
- Cloud sync settings, workspace export, and workspace import.
- Integration records for DoorKing, Linear, LiftMaster, custom relay controllers, and cloud APIs.
- Retrofit controller model that records relay intent only after authorization.

### Safety And Compliance Boundary

- Design the access-control layer with UL 294 considerations in mind.
- Treat barrier and gate operator motion as a separate UL 325 safety domain.
- Do not bypass certified operators, entrapment protection, installer commissioning, loops, photo eyes, reversing edges, or site safety procedures.
- Keep this app as an authorization and audit layer until certified controller hardware and professional installation are part of the deployment.

This repository is not a certification claim, legal opinion, installer manual, or hardware safety approval.

## Run Locally

Open `index.html` in a browser. The app uses browser local storage and has no package dependencies.

Optional syntax check:

```powershell
node --check src/app.js
```

## Project Shape

- `index.html` - application shell.
- `styles.css` - responsive industrial operations UI.
- `src/app.js` - local workspace state, forms, credential decision engine, audit events, export, and import.

## Data Policy

The app stores only records entered through the browser UI or imported from a workspace JSON file. Clearing browser storage or using the in-app clear action removes local records from that browser.
