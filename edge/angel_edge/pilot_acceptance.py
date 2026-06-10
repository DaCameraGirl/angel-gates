"""Pilot acceptance runner for a live Angel Edge HTTP service."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib import error, request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto_tokens import generate_keypair, sign_token


class PilotAcceptanceError(RuntimeError):
    """Pilot acceptance failure."""


@dataclass
class HttpResult:
    status: int
    payload: dict[str, Any]


class EdgeHttpClient:
    def __init__(self, *, edge_url: str, token: str, timeout_seconds: float = 5.0) -> None:
        self.edge_url = edge_url.rstrip("/")
        self.token = token
        self.timeout_seconds = timeout_seconds

    def get(self, path: str, *, token: str | None = None, expected_status: int = 200) -> HttpResult:
        return self.request_json("GET", path, token=token, expected_status=expected_status)

    def post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        token: str | None = None,
        expected_status: int = 200,
    ) -> HttpResult:
        return self.request_json("POST", path, payload=payload, token=token, expected_status=expected_status)

    def request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
        expected_status: int = 200,
    ) -> HttpResult:
        body = None if payload is None else json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.token if token is None else token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        http_request = request.Request(f"{self.edge_url}{path}", data=body, headers=headers, method=method)
        try:
            with request.urlopen(http_request, timeout=self.timeout_seconds) as response:
                status = response.status
                response_body = response.read().decode("utf-8")
        except error.HTTPError as exc:
            status = exc.code
            response_body = exc.read().decode("utf-8")
        if status != expected_status:
            raise PilotAcceptanceError(f"{method} {path} returned {status}, expected {expected_status}: {response_body}")
        if not response_body:
            return HttpResult(status=status, payload={})
        return HttpResult(status=status, payload=json.loads(response_body))

    def read_stream_event(self, *, after_sequence: int) -> dict[str, Any]:
        http_request = request.Request(
            f"{self.edge_url}/events/stream?after_sequence={after_sequence}",
            headers={"Authorization": f"Bearer {self.token}"},
            method="GET",
        )
        with request.urlopen(http_request, timeout=self.timeout_seconds) as response:
            event_name = ""
            data = ""
            deadline = time.monotonic() + self.timeout_seconds
            while time.monotonic() < deadline:
                line = response.readline().decode("utf-8")
                if line == "":
                    break
                if line.startswith("event:"):
                    event_name = line.removeprefix("event:").strip()
                elif line.startswith("data:"):
                    data = line.removeprefix("data:").strip()
                elif line.strip() == "" and data:
                    payload = json.loads(data)
                    payload["_sse_event"] = event_name
                    return payload
        raise PilotAcceptanceError("events_stream_timeout")


def run_pilot_acceptance(
    *,
    edge_url: str,
    token: str,
    gate_id: str,
    relay_channel: int = 0,
    relay_pulse_ms: int = 500,
    relay_cooldown_ms: int = 1500,
    include_binding_revocation: bool = False,
    observed_relay_clicks: int | None = None,
) -> dict[str, Any]:
    client = EdgeHttpClient(edge_url=edge_url, token=token)
    run_id = f"pilot-{uuid.uuid4().hex[:12]}"
    key_id = f"{run_id}-qr-key"
    private_key, public_pem = acceptance_keypair()
    now = int(time.time())

    results: list[dict[str, Any]] = []
    access_events: list[str] = []
    expected_relay_clicks = 0

    health = client.get("/health").payload
    record_step(results, "health", True, {"head_sequence": health.get("head_sequence")})

    bad_bearer = client.post(
        "/authorize",
        {"credential_type": "pin", "credential_value": "bad", "gate_id": gate_id},
        token="bad-token",
        expected_status=401,
    )
    record_step(results, "bad_bearer_rejected", bad_bearer.status == 401)

    valid_qr = sign_acceptance_token(
        private_key,
        key_id=key_id,
        token_id=f"{run_id}-qr-valid",
        principal_id=f"{run_id}-visitor",
        principal_label="Pilot Acceptance Visitor",
        gate_id=gate_id,
        exp=now + 3600,
    )
    revoked_qr = sign_acceptance_token(
        private_key,
        key_id=key_id,
        token_id=f"{run_id}-qr-revoked",
        principal_id=f"{run_id}-revoked",
        principal_label="Pilot Acceptance Revoked Visitor",
        gate_id=gate_id,
        exp=now + 3600,
    )
    expired_qr = sign_acceptance_token(
        private_key,
        key_id=key_id,
        token_id=f"{run_id}-qr-expired",
        principal_id=f"{run_id}-expired",
        principal_label="Pilot Acceptance Expired Visitor",
        gate_id=gate_id,
        exp=now - 120,
    )

    delta = acceptance_delta(
        run_id=run_id,
        gate_id=gate_id,
        public_pem=public_pem,
        key_id=key_id,
        relay_channel=relay_channel,
        relay_pulse_ms=relay_pulse_ms,
        relay_cooldown_ms=relay_cooldown_ms,
    )
    client.post("/sync/delta", delta)
    record_step(results, "sync_delta_applied", True)

    checks = [
        (
            "pin_allow",
            {"credential_type": "pin", "credential_value": f"{run_id}2468", "gate_id": gate_id},
            "allow",
            "authorized",
        ),
        (
            "qr_allow",
            {"credential_type": "qr", "credential_value": valid_qr, "gate_id": gate_id},
            "allow",
            "authorized_signed_qr",
        ),
        (
            "plate_allow",
            {"credential_type": "plate", "credential_value": f"AG{run_id[-4:]}", "gate_id": gate_id, "confidence": 0.96},
            "allow",
            "authorized",
        ),
        (
            "revoked_qr_denied",
            {"credential_type": "qr", "credential_value": revoked_qr, "gate_id": gate_id},
            "deny",
            "qr_token_revoked",
        ),
        (
            "expired_qr_denied",
            {"credential_type": "qr", "credential_value": expired_qr, "gate_id": gate_id},
            "deny",
            "token_expired",
        ),
        (
            "low_confidence_plate_denied",
            {"credential_type": "plate", "credential_value": f"AG{run_id[-4:]}", "gate_id": gate_id, "confidence": 0.40},
            "deny",
            "plate_confidence_below_threshold",
        ),
    ]

    for name, payload, expected_decision, expected_reason in checks:
        response = client.post("/authorize", payload).payload
        passed = response.get("decision") == expected_decision and response.get("reason") == expected_reason
        if response.get("event_id"):
            access_events.append(response["event_id"])
        if expected_decision == "allow":
            expected_relay_clicks += 1
        record_step(
            results,
            name,
            passed,
            {
                "decision": response.get("decision"),
                "reason": response.get("reason"),
                "event_id": response.get("event_id"),
                "relay_intent": response.get("relay_intent"),
                "relay_dispatch": response.get("relay_dispatch"),
            },
        )

    events_response = client.get("/events?limit=250").payload
    event_ids = {event["event_id"] for event in events_response.get("events", [])}
    record_step(
        results,
        "events_endpoint_contains_access_attempts",
        all(event_id in event_ids for event_id in access_events),
        {"checked_event_ids": access_events},
    )

    head_sequence = int(events_response["head"]["sequence"])
    stream_event = client.read_stream_event(after_sequence=max(0, head_sequence - 1))
    record_step(
        results,
        "events_stream_returns_event",
        stream_event.get("_sse_event") == "event" and int(stream_event.get("sequence", 0)) >= head_sequence,
        {"sequence": stream_event.get("sequence"), "event_type": stream_event.get("event_type")},
    )

    anchor = client.post(
        "/anchors/head",
        {"anchor_type": "pilot_acceptance", "upstream_ref": run_id},
    ).payload["anchor"]
    record_step(results, "anchor_head", int(anchor["sequence"]) >= head_sequence, anchor)

    verification = client.get("/verify-log").payload
    record_step(results, "verify_log", bool(verification.get("ok")), verification)

    if observed_relay_clicks is not None:
        record_step(
            results,
            "relay_click_count_observed",
            int(observed_relay_clicks) == expected_relay_clicks,
            {"expected": expected_relay_clicks, "observed": int(observed_relay_clicks)},
        )
    else:
        record_step(
            results,
            "relay_click_count_expected",
            True,
            {"expected": expected_relay_clicks, "note": "Confirm on hardware that only allow cases clicked."},
        )

    if include_binding_revocation:
        client.post(
            "/sync/delta",
            {
                "binding_revocations": [
                    {
                        "reason": "pilot_acceptance_binding_revoked",
                        "source_created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    }
                ]
            },
        )
        revoked_health = client.get("/health", expected_status=401)
        record_step(results, "binding_revocation_revokes_api_tokens", revoked_health.status == 401)
    else:
        record_step(
            results,
            "binding_revocation_skipped",
            True,
            {"note": "Enable include_binding_revocation only on a disposable edge because it revokes local API tokens."},
        )

    failed = [result for result in results if not result["ok"]]
    if failed:
        raise PilotAcceptanceError(json.dumps({"failed": failed}, sort_keys=True))
    return {"ok": True, "run_id": run_id, "edge_url": edge_url, "gate_id": gate_id, "results": results}


def acceptance_delta(
    *,
    run_id: str,
    gate_id: str,
    public_pem: str,
    key_id: str,
    relay_channel: int,
    relay_pulse_ms: int,
    relay_cooldown_ms: int,
) -> dict[str, Any]:
    return {
        "gates": [
            {
                "gate_id": gate_id,
                "name": "Pilot Acceptance Gate",
                "site_area": "Acceptance",
                "provider": "Angel Gates",
                "interface_type": "dry-contact",
                "operator_class": "barrier gate operator",
                "hardware_id": "pilot-acceptance-relay",
                "relay_channel": int(relay_channel),
                "relay_pulse_ms": int(relay_pulse_ms),
                "relay_cooldown_ms": int(relay_cooldown_ms),
                "safety_acknowledged": True,
            }
        ],
        "credentials": [
            {
                "credential_id": f"{run_id}-pin",
                "principal_id": f"{run_id}-unit-pin",
                "principal_label": "Pilot Acceptance PIN",
                "principal_type": "resident",
                "credential_type": "pin",
                "credential_value": f"{run_id}2468",
                "gate_scope": [gate_id],
            },
            {
                "credential_id": f"{run_id}-plate",
                "principal_id": f"{run_id}-unit-plate",
                "principal_label": "Pilot Acceptance Plate",
                "principal_type": "resident",
                "credential_type": "plate",
                "credential_value": f"AG{run_id[-4:]}",
                "gate_scope": [gate_id],
                "confidence_threshold": 0.85,
            },
        ],
        "qr_public_keys": [{"key_id": key_id, "public_key_pem": public_pem}],
        "qr_token_revocations": [{"token_id": f"{run_id}-qr-revoked", "reason": "pilot_acceptance_revoked"}],
    }


def acceptance_keypair() -> tuple[Ed25519PrivateKey, str]:
    private_pem, public_pem = generate_keypair()
    key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PilotAcceptanceError("acceptance_private_key_invalid")
    return key, public_pem


def sign_acceptance_token(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    token_id: str,
    principal_id: str,
    principal_label: str,
    gate_id: str,
    exp: int,
) -> str:
    return sign_token(
        private_key,
        key_id,
        {
            "token_id": token_id,
            "principal_id": principal_id,
            "principal_label": principal_label,
            "gate_scope": [gate_id],
            "exp": int(exp),
        },
    )


def record_step(results: list[dict[str, Any]], name: str, ok: bool, detail: dict[str, Any] | None = None) -> None:
    results.append({"name": name, "ok": bool(ok), "detail": detail or {}})
