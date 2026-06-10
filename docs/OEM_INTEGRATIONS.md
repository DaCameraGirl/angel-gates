# OEM Cloud Integration Evaluation

OEM cloud integrations are later adapters. They are not the first compatibility story.

Until the retrofit pilot proves the edge/event-log product, Angel Gates should stay focused on dry-contact relay pulse and Wiegand-style handoff. Those paths work with the installed base without depending on brand-specific cloud access, partner approval, internet availability, or undocumented APIs.

## Evaluation Trigger

Evaluate an OEM cloud integration only after these are true:

- The QR/PIN plus camera evidence pilot has produced real event, chargeback, support, and installer data.
- A real property or portfolio asks for a specific OEM integration.
- The property can authorize access to its OEM account or partner program.
- The integration supports the evidence workflow instead of pulling the product into broad access-control replacement.
- The installer path remains clear and does not require modifying UL 325 operator safety functions.

Do not evaluate APIs in the abstract just because they exist.

## Candidate Categories

Track candidates by category, not by hype:

- myQ Community-style cloud account integrations.
- DoorKing/DKS account or entry-system integrations.
- Linear/Nice and LiftMaster ecosystem integrations.
- Broad access-control platform exports or webhooks.
- Installer or dealer portals that can provide event or credential context.

This document does not claim any specific API is available, approved, stable, or appropriate. Each candidate needs current partner documentation and a property-authorized test account before engineering work starts.

## Acceptable Integration Modes

Good later integrations should be leaves under the Angel Gates edge/event-log spine:

- Import resident, unit, or credential context for manager review.
- Export Angel Gates event summaries into a property or OEM system.
- Ingest OEM events as supplemental evidence.
- Reconcile gate/account metadata so managers do not type duplicate labels.
- Push revocation or credential updates only when the edge still receives a local cache delta and logs the change.

The integration can enrich the evidence record. It should not replace local authorization.

## Disqualifiers

Do not pursue an OEM integration if it:

- Requires a cloud round trip before a resident can enter.
- Requires Angel Gates to bypass, disable, or modify certified operator safety behavior.
- Has no official partner path, no property-authorized account path, or terms that prohibit the intended use.
- Cannot produce an audit trail that can be tied back to an Angel Gates event ID/hash.
- Requires storing raw credential secrets in a third-party cloud without a clear revocation and retention model.
- Makes the OEM cloud the source of truth for relay pulses.
- Creates support burden the first property cannot validate.
- Dilutes the sales pitch away from damaged-arm accountability and local reliability.

## Due Diligence Checklist

For each candidate, record:

- Property request and business reason.
- OEM account owner and written authorization path.
- Official docs or partner-contact source.
- Authentication model and token rotation.
- Rate limits, uptime assumptions, and offline behavior.
- Data fields available: credentials, residents, gate names, events, photos, clips, or status.
- Write capabilities and whether they are actually needed.
- Auditability: request ID, event ID, timestamp, actor, and response body retention.
- Privacy and retention rules for names, unit labels, plates, photos, clips, and access events.
- Installer impact: cabinet work, account setup, support workflow, and rollback.
- Failure behavior: what the edge does when the OEM cloud is slow, down, or inconsistent.
- Cost: partner fees, hardware lock-in, account tier, and support load.

## Adapter Architecture

An OEM adapter should sit outside the relay-critical path:

```text
OEM cloud <-> Angel cloud adapter <-> sync delta <-> edge cache <-> local authorization
```

or:

```text
edge event log -> Angel cloud -> OEM/event export
```

Rules:

- The edge still decides from local cache.
- Every imported change becomes a hash-chained configuration or revocation event.
- Every exported event carries the Angel Gates event ID/hash and latest known anchor when available.
- OAuth tokens, partner credentials, and OEM account secrets stay in cloud-side secret storage, not in the edge SQLite database.
- A failed OEM sync creates diagnostics; it does not block QR/PIN access or relay pulse dispatch after an allow decision.

## First Evaluation Spike

When a real property asks for one OEM path:

1. Write a one-page integration brief for that exact property and OEM account.
2. Confirm official access path and terms.
3. Build a read-only adapter first.
4. Map imported records to Angel Gates fields without creating duplicate source-of-truth rules.
5. Export one incident packet or event summary back to the OEM/property workflow if supported.
6. Run a failure drill with the OEM endpoint unavailable.
7. Decide whether write-back is worth the added support risk.

Success means the integration reduces manager work while preserving local edge authorization and event integrity. If it only adds a logo to the pitch, defer it.

## Positioning

Use this answer when asked about OEM clouds:

```text
Angel Gates starts with the retrofit path because that is what lets us work with the gate already on site. OEM cloud integrations can be useful later, but they are adapters over the edge/event-log product. They do not replace local authorization, the relay safety boundary, or the chargeback evidence workflow.
```

