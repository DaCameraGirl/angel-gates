"""Incident report export for damaged-arm chargeback review."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from typing import Any

from . import __version__
from .store import EdgeError, current_head, format_utc, parse_time, utc_now, verify_event_log


REPORT_TYPE = "damaged_arm_incident"
EXPORT_SCHEMA_VERSION = "1"
REPORT_EVENT_TYPES = ("access_attempt", "relay", "camera")
LINKED_EVIDENCE_EVENT_TYPES = ("relay", "camera")


def build_incident_report(
    connection: sqlite3.Connection,
    *,
    gate_id: str,
    started_at: str,
    ended_at: str,
    property_id: str | None = None,
    property_label: str | None = None,
    selected_event_id: str | None = None,
    manager_notes: str | None = None,
) -> dict[str, Any]:
    if not gate_id:
        raise EdgeError("gate_id_required")
    start = parse_time(started_at)
    end = parse_time(ended_at)
    if start is None or end is None:
        raise EdgeError("incident_window_required")
    if start > end:
        raise EdgeError("incident_window_invalid")

    normalized_started_at = format_utc(start)
    normalized_ended_at = format_utc(end)
    events = incident_events_for_window(
        connection,
        gate_id=gate_id,
        started_at=normalized_started_at,
        ended_at=normalized_ended_at,
    )
    selected_event = None
    if selected_event_id:
        selected_event = next((event for event in events if event["event_id"] == selected_event_id), None)
        if selected_event is None:
            raise EdgeError("selected_event_outside_incident_report")

    verification = verify_event_log(connection)
    return {
        "report_type": REPORT_TYPE,
        "schema_version": EXPORT_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "generated_by": f"angel-edge {__version__}",
        "property": {
            "property_id": property_id,
            "property_label": property_label,
        },
        "gate_id": gate_id,
        "window": {
            "started_at": normalized_started_at,
            "ended_at": normalized_ended_at,
        },
        "selected_event_id": selected_event_id,
        "selected_event": selected_event,
        "manager_notes": manager_notes,
        "summary": summarize_events(events),
        "events": events,
        "head": current_head(connection),
        "latest_anchor": verification.get("latest_anchor"),
        "log_verification": verification,
    }


def incident_events_for_window(
    connection: sqlite3.Connection,
    *,
    gate_id: str,
    started_at: str,
    ended_at: str,
) -> list[dict[str, Any]]:
    rows_by_id: dict[str, sqlite3.Row] = {}
    for row in connection.execute(
        f"""
        SELECT *
        FROM events
        WHERE gate_id = ?
          AND occurred_at >= ?
          AND occurred_at <= ?
          AND event_type IN ({",".join("?" for _ in REPORT_EVENT_TYPES)})
        ORDER BY sequence ASC
        """,
        (gate_id, started_at, ended_at, *REPORT_EVENT_TYPES),
    ).fetchall():
        rows_by_id[row["event_id"]] = row

    access_event_ids = [
        row["event_id"]
        for row in rows_by_id.values()
        if row["event_type"] == "access_attempt"
    ]
    for event_id in access_event_ids:
        for row in connection.execute(
            f"""
            SELECT *
            FROM events
            WHERE gate_id = ?
              AND event_type IN ({",".join("?" for _ in LINKED_EVIDENCE_EVENT_TYPES)})
              AND extra_json LIKE ?
            ORDER BY sequence ASC
            """,
            (gate_id, *LINKED_EVIDENCE_EVENT_TYPES, f'%"{event_id}"%'),
        ).fetchall():
            rows_by_id[row["event_id"]] = row

    rows = sorted(rows_by_id.values(), key=lambda row: int(row["sequence"]))
    return [event_export(row) for row in rows]


def event_export(row: sqlite3.Row) -> dict[str, Any]:
    request = load_json_field(row["request_json"])
    media = load_json_field(row["media_json"])
    extra = load_json_field(row["extra_json"])
    return {
        "sequence": int(row["sequence"]),
        "event_id": row["event_id"],
        "event_hash": row["event_hash"],
        "previous_hash": row["previous_hash"],
        "occurred_at": row["occurred_at"],
        "event_type": row["event_type"],
        "gate_id": row["gate_id"],
        "credential_type": row["credential_type"],
        "credential_id": row["credential_id"],
        "principal_id": row["principal_id"],
        "principal_label": row["principal_label"],
        "decision": row["decision"],
        "reason": row["reason"],
        "confidence": row["confidence"],
        "fallback_required": bool(row["fallback_required"]),
        "request": request,
        "media": media,
        "media_refs": media_refs(media),
        "extra": extra,
        "linked_decision_event_id": extra.get("decision_event_id"),
        "linked_decision_event_hash": extra.get("decision_event_hash"),
    }


def summarize_events(events: list[dict[str, Any]]) -> dict[str, int]:
    access_attempts = [event for event in events if event["event_type"] == "access_attempt"]
    return {
        "event_count": len(events),
        "access_attempts": len(access_attempts),
        "allow_count": sum(1 for event in access_attempts if event["decision"] == "allow"),
        "deny_count": sum(1 for event in access_attempts if event["decision"] == "deny"),
        "fallback_required_count": sum(1 for event in access_attempts if event["fallback_required"]),
        "camera_clip_count": sum(1 for event in events if event["reason"] == "camera_clip_captured"),
        "camera_error_count": sum(1 for event in events if event["reason"] == "camera_capture_error"),
        "relay_event_count": sum(1 for event in events if event["event_type"] == "relay"),
    }


def incident_report_csv(report: dict[str, Any]) -> str:
    output = io.StringIO()
    fieldnames = [
        "sequence",
        "occurred_at",
        "event_type",
        "gate_id",
        "principal_label",
        "principal_id",
        "credential_type",
        "credential_id",
        "decision",
        "reason",
        "confidence",
        "fallback_required",
        "media_refs",
        "linked_decision_event_id",
        "event_id",
        "event_hash",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for event in report["events"]:
        writer.writerow(
            {
                "sequence": event["sequence"],
                "occurred_at": event["occurred_at"],
                "event_type": event["event_type"],
                "gate_id": event["gate_id"],
                "principal_label": event["principal_label"],
                "principal_id": event["principal_id"],
                "credential_type": event["credential_type"],
                "credential_id": event["credential_id"],
                "decision": event["decision"],
                "reason": event["reason"],
                "confidence": "" if event["confidence"] is None else event["confidence"],
                "fallback_required": event["fallback_required"],
                "media_refs": ";".join(event["media_refs"]),
                "linked_decision_event_id": event["linked_decision_event_id"] or "",
                "event_id": event["event_id"],
                "event_hash": event["event_hash"],
            }
        )
    return output.getvalue()


def incident_report_markdown(report: dict[str, Any]) -> str:
    property_label = report["property"].get("property_label") or report["property"].get("property_id") or "Not specified"
    selected = report.get("selected_event")
    lines = [
        "# Gate Incident Report",
        "",
        f"- Report type: `{REPORT_TYPE}`",
        f"- Generated at: {report['generated_at']}",
        f"- Property: {property_label}",
        f"- Gate: {report['gate_id']}",
        f"- Window: {report['window']['started_at']} to {report['window']['ended_at']}",
        f"- Event count: {report['summary']['event_count']}",
        f"- Access attempts: {report['summary']['access_attempts']}",
        f"- Camera clips: {report['summary']['camera_clip_count']}",
        f"- Camera errors: {report['summary']['camera_error_count']}",
        "",
    ]
    if report.get("manager_notes"):
        lines.extend(["## Manager Notes", "", str(report["manager_notes"]), ""])
    if selected:
        lines.extend(
            [
                "## Selected Event",
                "",
                f"- Event ID: `{selected['event_id']}`",
                f"- Timestamp: {selected['occurred_at']}",
                f"- Principal: {selected.get('principal_label') or selected.get('principal_id') or 'Unknown'}",
                f"- Credential: {selected.get('credential_type') or 'Unknown'} / {selected.get('credential_id') or 'Unknown'}",
                f"- Decision: {selected.get('decision') or 'n/a'}",
                f"- Reason: {selected.get('reason') or 'n/a'}",
                f"- Event hash: `{selected['event_hash']}`",
                "",
            ]
        )

    lines.extend(
        [
            "## Events",
            "",
            "| Seq | Time | Type | Principal | Credential | Decision | Reason | Media |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for event in report["events"]:
        credential = " / ".join(filter(None, [event.get("credential_type"), event.get("credential_id")])) or "n/a"
        principal = event.get("principal_label") or event.get("principal_id") or "n/a"
        lines.append(
            "| "
            + " | ".join(
                [
                    markdown_cell(event["sequence"]),
                    markdown_cell(event["occurred_at"]),
                    markdown_cell(event["event_type"]),
                    markdown_cell(principal),
                    markdown_cell(credential),
                    markdown_cell(event.get("decision") or "n/a"),
                    markdown_cell(event.get("reason") or "n/a"),
                    markdown_cell("; ".join(event["media_refs"]) or "n/a"),
                ]
            )
            + " |"
        )

    latest_anchor = report.get("latest_anchor")
    lines.extend(["", "## Integrity", ""])
    lines.append(f"- Log verification: {'ok' if report['log_verification'].get('ok') else 'failed'}")
    lines.append(f"- Head sequence: {report['head'].get('sequence')}")
    lines.append(f"- Head hash: `{report['head'].get('event_hash')}`")
    if latest_anchor:
        lines.append(f"- Latest anchor sequence: {latest_anchor.get('sequence')}")
        lines.append(f"- Latest anchor hash: `{latest_anchor.get('event_hash')}`")
        if latest_anchor.get("upstream_ref"):
            lines.append(f"- Latest anchor upstream ref: `{latest_anchor.get('upstream_ref')}`")
    else:
        lines.append("- Latest anchor: none")
    lines.append("")
    return "\n".join(lines)


def load_json_field(value: str) -> dict[str, Any]:
    try:
        loaded = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def media_refs(media: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("clips", "photos", "images", "plate_crops"):
        value = media.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    ref = item.get("path") or item.get("url") or item.get("ref")
                    if ref:
                        refs.append(str(ref))
                elif item:
                    refs.append(str(item))
    for key in ("clip_path", "photo_path", "image_path", "plate_crop_path"):
        if media.get(key):
            refs.append(str(media[key]))
    return refs


def markdown_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")

