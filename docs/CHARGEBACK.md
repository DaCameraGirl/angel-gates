# Chargeback Workflow

Chargeback evidence is a core loss-prevention workflow for storage facilities, HOAs, and gated communities.

## Problem

Gate arms get knocked off or damaged. Managers often know the approximate time window but lack evidence strong enough to bill the responsible unit or visitor.

## Workflow

1. Manager opens `Incident Review`.
2. Manager selects property, gate, and time window.
3. System shows every entry and exit event in that window.
4. Events include credential, unit or visitor, gate, timestamp, decision, reason, and plate/photo/clip references when available.
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
- Clip reference if camera capture is present.
- Event hash and latest anchor hash.
- Manager notes.

## Pilot Version

The first pilot can support a manual incident packet:

- Manager chooses a time window.
- Dashboard exports matching events as JSON/CSV.
- Automated camera capture records local clip references and capture failures in the edge event log.
- Report assembly can still start as manual JSON/CSV export until PDF generation exists.

Automated PDF generation can come after the pilot proves the evidence workflow.

## Export Shape

The JSON export must carry verification data from day one:

- `events[].sequence`
- `events[].event_id`
- `events[].event_hash`
- `events[].previous_hash`
- `events[].occurred_at`
- `events[].gate_id`
- `events[].credential_type`
- `events[].credential_id`
- `events[].principal_id`
- `events[].principal_label`
- `events[].decision`
- `events[].reason`
- `events[].media`
- `latest_anchor.sequence`
- `latest_anchor.event_hash`
- `latest_anchor.anchored_at`
- `latest_anchor.upstream_ref`

CSV can be the manager-readable companion format, but JSON is the integrity format. A recipient should be able to verify the selected events against the hash chain and latest known anchor.

## Why It Sells

The audit log is not only about security. It creates a chargeback path where the property previously had a maintenance expense with no accountable event trail.
