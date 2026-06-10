# Chargeback Workflow

Chargeback evidence is a core loss-prevention workflow for storage facilities, HOAs, and gated communities.

## Problem

Gate arms get knocked off or damaged. Managers often know the approximate time window but lack evidence strong enough to bill the responsible unit or visitor.

## Workflow

1. Manager opens `Incident Review`.
2. Manager selects property, gate, and time window.
3. System shows every entry and exit event in that window.
4. Events include credential, unit or visitor, gate, timestamp, decision, reason, and plate/photo references when available.
5. Manager tags likely responsible event.
6. System exports an incident report PDF.
7. Report can attach to an invoice, resident notice, insurer packet, or board packet.

## Report Contents

- Property and gate.
- Incident time window.
- Selected event details.
- Credential attribution.
- Unit or visitor sponsor.
- Plate confidence if LPR is present.
- Photo or clip reference if camera is present.
- Event hash and latest anchor hash.
- Manager notes.

## Pilot Version

The first pilot can support a manual incident packet:

- Manager chooses a time window.
- Dashboard exports matching events as JSON/CSV.
- Photos or video clips are attached manually if cameras are present.

Automated PDF generation can come after the pilot proves the evidence workflow.

## Why It Sells

The audit log is not only about security. It creates a chargeback path where the property previously had a maintenance expense with no accountable event trail.
