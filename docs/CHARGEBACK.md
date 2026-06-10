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
6. System exports an incident report packet.
7. Report packet can attach to an invoice, resident notice, insurer packet, or board packet.

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

## Pilot Export

The edge can export an incident packet directly from the local SQLite event log:

```bash
python -m edge.angel_edge --db "$ANGEL_EDGE_DB" export-incident-report \
  --gate-id "$INCIDENT_GATE_ID" \
  --started-at "$INCIDENT_STARTED_AT" \
  --ended-at "$INCIDENT_ENDED_AT" \
  --property-label "$PROPERTY_LABEL" \
  --selected-event-id "$SELECTED_EVENT_ID" \
  --manager-notes-file incident-notes.txt \
  --json-output incident-report.json \
  --csv-output incident-events.csv \
  --markdown-output incident-report.md
```

JSON is the integrity export. CSV is the manager-readable event table. Markdown is the printable packet for invoice, resident notice, insurer, or board review. Automated PDF generation can come after the pilot proves the evidence workflow.

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
- `events[].media_refs`
- `events[].extra`
- `events[].linked_decision_event_id`
- `events[].linked_decision_event_hash`
- `latest_anchor.sequence`
- `latest_anchor.event_hash`
- `latest_anchor.anchored_at`
- `latest_anchor.upstream_ref`

The export includes camera and relay evidence linked to access events by decision event ID/hash. A recipient should be able to verify the selected events against the hash chain and latest known anchor.

## Why It Sells

The audit log is not only about security. It creates a chargeback path where the property previously had a maintenance expense with no accountable event trail.
