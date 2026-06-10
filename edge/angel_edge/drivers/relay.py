"""Relay driver interface and non-hardware implementation."""

from __future__ import annotations

import json
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib import error, request

from .. import store


class RelayError(RuntimeError):
    """Relay driver or dispatch error."""


@dataclass(frozen=True)
class RelayPulse:
    gate_id: str
    channel: int
    duration_ms: int
    cooldown_ms: int
    decision_event_id: str
    decision_event_hash: str


@dataclass(frozen=True)
class RelayPulseResult:
    channel: int
    duration_ms: int
    started_at: str
    ended_at: str
    driver: str


class RelayDriver(Protocol):
    name: str

    def pulse(self, pulse: RelayPulse) -> RelayPulseResult:
        """Emit one momentary relay pulse."""


class LoggingRelayDriver:
    """Hardware-free relay driver used in tests and local development."""

    name = "logging"

    def __init__(self) -> None:
        self.pulses: list[RelayPulse] = []

    def pulse(self, pulse: RelayPulse) -> RelayPulseResult:
        started_at = store.utc_now()
        self.pulses.append(pulse)
        time.sleep(pulse.duration_ms / 1000)
        return RelayPulseResult(
            channel=pulse.channel,
            duration_ms=pulse.duration_ms,
            started_at=started_at,
            ended_at=store.utc_now(),
            driver=self.name,
        )


class RelayController:
    """Owns relay cooldown enforcement and records relay events."""

    def __init__(self, *, db_path: str, driver: RelayDriver) -> None:
        self.db_path = db_path
        self.driver = driver
        self._lock = threading.Lock()
        self._cooldowns: dict[tuple[str, int], float] = {}

    def request_pulse(self, payload: dict[str, Any]) -> dict[str, Any]:
        pulse = parse_pulse_payload(payload)
        cooldown_key = (pulse.gate_id, pulse.channel)
        now = time.monotonic()

        with self._lock:
            suppressed_until = self._cooldowns.get(cooldown_key, 0)
            if suppressed_until > now:
                event = self._record_suppressed(pulse, suppressed_until - now)
                return {"ok": True, "status": "suppressed_cooldown", "event": event}
            self._cooldowns[cooldown_key] = now + (pulse.cooldown_ms / 1000)

        try:
            result = self.driver.pulse(pulse)
        except Exception as exc:  # pragma: no cover - hardware failure path
            event = self._record_error(pulse, str(exc))
            raise RelayError(str(exc)) from exc

        with closing(store.connect(self.db_path)) as connection:
            store.migrate(connection)
            event = store.record_relay_pulse(
                connection,
                gate_id=pulse.gate_id,
                relay_channel=result.channel,
                duration_ms=result.duration_ms,
                cooldown_ms=pulse.cooldown_ms,
                decision_event_id=pulse.decision_event_id,
                decision_event_hash=pulse.decision_event_hash,
                started_at=result.started_at,
                ended_at=result.ended_at,
                driver=result.driver,
            )
        return {"ok": True, "status": "pulsed", "event": event}

    def _record_suppressed(self, pulse: RelayPulse, remaining_seconds: float) -> dict[str, Any]:
        suppressed_until = store.format_utc(datetime.now(UTC) + timedelta(seconds=remaining_seconds))
        with closing(store.connect(self.db_path)) as connection:
            store.migrate(connection)
            return store.record_relay_suppressed(
                connection,
                gate_id=pulse.gate_id,
                relay_channel=pulse.channel,
                cooldown_ms=pulse.cooldown_ms,
                decision_event_id=pulse.decision_event_id,
                decision_event_hash=pulse.decision_event_hash,
                suppressed_until=suppressed_until,
                driver=self.driver.name,
            )

    def _record_error(self, pulse: RelayPulse, message: str) -> dict[str, Any]:
        with closing(store.connect(self.db_path)) as connection:
            store.migrate(connection)
            return store.record_relay_error(
                connection,
                gate_id=pulse.gate_id,
                relay_channel=pulse.channel,
                duration_ms=pulse.duration_ms,
                decision_event_id=pulse.decision_event_id,
                decision_event_hash=pulse.decision_event_hash,
                error=message,
                driver=self.driver.name,
            )


def parse_pulse_payload(payload: dict[str, Any]) -> RelayPulse:
    required = ["gate_id", "channel", "duration_ms", "cooldown_ms", "decision_event_id", "decision_event_hash"]
    missing = [field for field in required if payload.get(field) in (None, "")]
    if missing:
        raise RelayError("relay_pulse_missing_" + "_".join(missing))
    duration_ms = int(payload["duration_ms"])
    cooldown_ms = int(payload["cooldown_ms"])
    if duration_ms < store.MIN_RELAY_PULSE_MS or duration_ms > store.MAX_RELAY_PULSE_MS:
        raise RelayError("relay_pulse_duration_out_of_range")
    if cooldown_ms < store.MIN_RELAY_COOLDOWN_MS or cooldown_ms > store.MAX_RELAY_COOLDOWN_MS:
        raise RelayError("relay_cooldown_out_of_range")
    channel = int(payload["channel"])
    if channel < 0:
        raise RelayError("relay_channel_must_be_non_negative")
    return RelayPulse(
        gate_id=str(payload["gate_id"]),
        channel=channel,
        duration_ms=duration_ms,
        cooldown_ms=cooldown_ms,
        decision_event_id=str(payload["decision_event_id"]),
        decision_event_hash=str(payload["decision_event_hash"]),
    )


def relay_payload_from_authorization(result: dict[str, Any]) -> dict[str, Any] | None:
    relay = result.get("relay")
    if result.get("decision") != "allow" or not result.get("relay_intent") or not isinstance(relay, dict):
        return None
    return {
        "gate_id": relay["gate_id"],
        "channel": relay["channel"],
        "duration_ms": relay["pulse_ms"],
        "cooldown_ms": relay["cooldown_ms"],
        "decision_event_id": result["event_id"],
        "decision_event_hash": result["event_hash"],
    }


def dispatch_relay_pulse_async(
    *,
    relay_url: str | None,
    relay_token: str | None,
    authorization_result: dict[str, Any],
) -> bool:
    payload = relay_payload_from_authorization(authorization_result)
    if not relay_url or not relay_token or payload is None:
        return False

    thread = threading.Thread(
        target=_post_relay_pulse,
        kwargs={"relay_url": relay_url.rstrip("/"), "relay_token": relay_token, "payload": payload},
        daemon=True,
    )
    thread.start()
    return True


def _post_relay_pulse(*, relay_url: str, relay_token: str, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    http_request = request.Request(
        f"{relay_url}/pulse",
        data=body,
        headers={
            "Authorization": f"Bearer {relay_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=1.0):
            return
    except (OSError, error.URLError):
        return
