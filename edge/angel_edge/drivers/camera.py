"""Camera clip capture driver and dispatch helpers."""

from __future__ import annotations

import json
import re
import subprocess
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib import error, request

from .. import store

MIN_CLIP_SECONDS = 1
MAX_CLIP_SECONDS = 120
MAX_RETENTION_DAYS = 3650


class CameraError(RuntimeError):
    """Camera capture or dispatch error."""


@dataclass(frozen=True)
class CameraCaptureRequest:
    camera_id: str
    gate_id: str
    rtsp_url: str
    clip_seconds: int
    storage_path: Path
    output_path: Path
    retention_days: int
    decision_event_id: str
    decision_event_hash: str
    decision_occurred_at: str
    access_decision: str
    access_reason: str


@dataclass(frozen=True)
class CameraCaptureResult:
    clip_path: Path
    bytes_written: int
    started_at: str
    ended_at: str
    driver: str


class CameraDriver(Protocol):
    name: str

    def capture(self, capture_request: CameraCaptureRequest) -> CameraCaptureResult:
        """Capture one video clip to the request output path."""


class FfmpegCameraDriver:
    """RTSP camera driver backed by ffmpeg."""

    name = "ffmpeg"

    def __init__(self, *, ffmpeg_path: str = "ffmpeg", rtsp_transport: str = "tcp") -> None:
        self.ffmpeg_path = ffmpeg_path
        self.rtsp_transport = rtsp_transport

    def capture(self, capture_request: CameraCaptureRequest) -> CameraCaptureResult:
        capture_request.storage_path.mkdir(parents=True, exist_ok=True)
        started_at = store.utc_now()
        command = [
            self.ffmpeg_path,
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-rtsp_transport",
            self.rtsp_transport,
            "-i",
            capture_request.rtsp_url,
            "-t",
            str(capture_request.clip_seconds),
            "-an",
            "-c:v",
            "copy",
            str(capture_request.output_path),
        ]
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=capture_request.clip_seconds + 15,
            check=False,
        )
        ended_at = store.utc_now()
        if completed.returncode != 0:
            raise CameraError(
                "ffmpeg_capture_failed:"
                + sanitize_process_error(completed.stderr or completed.stdout, capture_request.rtsp_url)
            )
        if not capture_request.output_path.exists() or capture_request.output_path.stat().st_size <= 0:
            raise CameraError("camera_clip_empty")
        return CameraCaptureResult(
            clip_path=capture_request.output_path,
            bytes_written=capture_request.output_path.stat().st_size,
            started_at=started_at,
            ended_at=ended_at,
            driver=self.name,
        )


class CameraController:
    """Owns camera capture requests and records evidence events."""

    def __init__(
        self,
        *,
        db_path: str,
        rtsp_url: str,
        storage_path: str | Path,
        camera_id: str,
        clip_seconds: int,
        retention_days: int,
        driver: CameraDriver | None = None,
    ) -> None:
        if not rtsp_url:
            raise CameraError("camera_rtsp_url_required")
        self.db_path = db_path
        self.rtsp_url = rtsp_url
        self.storage_path = Path(storage_path)
        self.camera_id = camera_id
        self.clip_seconds = bounded_int(
            clip_seconds,
            minimum=MIN_CLIP_SECONDS,
            maximum=MAX_CLIP_SECONDS,
            field="camera_clip_seconds",
        )
        self.retention_days = bounded_int(
            retention_days,
            minimum=0,
            maximum=MAX_RETENTION_DAYS,
            field="camera_retention_days",
        )
        self.driver = driver or FfmpegCameraDriver()

    def request_capture(self, payload: dict[str, Any]) -> dict[str, Any]:
        capture_request = self._parse_payload(payload)
        thread = threading.Thread(target=self._capture_and_record, args=(capture_request,), daemon=True)
        thread.start()
        return {
            "ok": True,
            "status": "accepted",
            "camera_id": capture_request.camera_id,
            "decision_event_id": capture_request.decision_event_id,
        }

    def capture_once(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._capture_and_record(self._parse_payload(payload))

    def _parse_payload(self, payload: dict[str, Any]) -> CameraCaptureRequest:
        required = [
            "gate_id",
            "decision_event_id",
            "decision_event_hash",
            "decision_occurred_at",
            "access_decision",
            "access_reason",
        ]
        missing = [field for field in required if payload.get(field) in (None, "")]
        if missing:
            raise CameraError("camera_capture_missing_" + "_".join(missing))
        access_decision = str(payload["access_decision"])
        if access_decision not in {"allow", "deny"}:
            raise CameraError("camera_capture_decision_must_be_allow_or_deny")
        return build_capture_request(
            rtsp_url=self.rtsp_url,
            storage_path=self.storage_path,
            camera_id=self.camera_id,
            clip_seconds=self.clip_seconds,
            retention_days=self.retention_days,
            payload=payload,
        )

    def _capture_and_record(self, capture_request: CameraCaptureRequest) -> dict[str, Any]:
        try:
            result = self.driver.capture(capture_request)
            self._apply_retention()
            with closing(store.connect(self.db_path)) as connection:
                store.migrate(connection)
                event = store.record_camera_clip(
                    connection,
                    gate_id=capture_request.gate_id,
                    camera_id=capture_request.camera_id,
                    decision_event_id=capture_request.decision_event_id,
                    decision_event_hash=capture_request.decision_event_hash,
                    decision_occurred_at=capture_request.decision_occurred_at,
                    access_decision=capture_request.access_decision,
                    access_reason=capture_request.access_reason,
                    clip_path=str(result.clip_path),
                    started_at=result.started_at,
                    ended_at=result.ended_at,
                    duration_seconds=capture_request.clip_seconds,
                    bytes_written=result.bytes_written,
                    driver=result.driver,
                    retention_days=capture_request.retention_days,
                )
            return {"ok": True, "status": "captured", "event": event}
        except Exception as exc:
            with closing(store.connect(self.db_path)) as connection:
                store.migrate(connection)
                event = store.record_camera_error(
                    connection,
                    gate_id=capture_request.gate_id,
                    camera_id=capture_request.camera_id,
                    decision_event_id=capture_request.decision_event_id,
                    decision_event_hash=capture_request.decision_event_hash,
                    decision_occurred_at=capture_request.decision_occurred_at,
                    access_decision=capture_request.access_decision,
                    access_reason=capture_request.access_reason,
                    duration_seconds=capture_request.clip_seconds,
                    error=sanitize_error_message(str(exc), capture_request.rtsp_url),
                    driver=self.driver.name,
                )
            return {"ok": False, "status": "capture_error", "event": event}

    def _apply_retention(self) -> None:
        if self.retention_days <= 0 or not self.storage_path.exists():
            return
        cutoff = datetime.now(UTC) - timedelta(days=self.retention_days)
        for path in self.storage_path.glob("*.mp4"):
            try:
                modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
            except OSError:
                continue
            if modified < cutoff:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    continue


def build_capture_request(
    *,
    rtsp_url: str,
    storage_path: Path,
    camera_id: str,
    clip_seconds: int,
    retention_days: int,
    payload: dict[str, Any],
) -> CameraCaptureRequest:
    gate_id = str(payload["gate_id"])
    decision_event_id = str(payload["decision_event_id"])
    output_path = storage_path / clip_filename(
        gate_id=gate_id,
        camera_id=camera_id,
        decision_event_id=decision_event_id,
    )
    return CameraCaptureRequest(
        camera_id=camera_id,
        gate_id=gate_id,
        rtsp_url=rtsp_url,
        clip_seconds=clip_seconds,
        storage_path=storage_path,
        output_path=output_path,
        retention_days=retention_days,
        decision_event_id=decision_event_id,
        decision_event_hash=str(payload["decision_event_hash"]),
        decision_occurred_at=str(payload["decision_occurred_at"]),
        access_decision=str(payload["access_decision"]),
        access_reason=str(payload["access_reason"]),
    )


def capture_payload_from_authorization(result: dict[str, Any]) -> dict[str, Any] | None:
    if result.get("decision") not in {"allow", "deny"}:
        return None
    if not result.get("event_id") or not result.get("event_hash") or not result.get("gate_id"):
        return None
    return {
        "gate_id": result["gate_id"],
        "decision_event_id": result["event_id"],
        "decision_event_hash": result["event_hash"],
        "decision_occurred_at": result["occurred_at"],
        "access_decision": result["decision"],
        "access_reason": result["reason"],
    }


def dispatch_camera_capture_async(
    *,
    camera_url: str | None,
    camera_token: str | None,
    authorization_result: dict[str, Any],
) -> bool:
    payload = capture_payload_from_authorization(authorization_result)
    if not camera_url or not camera_token or payload is None:
        return False

    thread = threading.Thread(
        target=_post_camera_capture,
        kwargs={"camera_url": camera_url.rstrip("/"), "camera_token": camera_token, "payload": payload},
        daemon=True,
    )
    thread.start()
    return True


def _post_camera_capture(*, camera_url: str, camera_token: str, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    http_request = request.Request(
        f"{camera_url}/capture",
        data=body,
        headers={
            "Authorization": f"Bearer {camera_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=1.0):
            return
    except (OSError, error.URLError):
        return


def bounded_int(value: int, *, minimum: int, maximum: int, field: str) -> int:
    parsed = int(value)
    if parsed < minimum or parsed > maximum:
        raise CameraError(f"{field}_must_be_between_{minimum}_and_{maximum}")
    return parsed


def clip_filename(*, gate_id: str, camera_id: str, decision_event_id: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return "_".join(
        [
            timestamp,
            sanitize_filename_part(gate_id),
            sanitize_filename_part(camera_id),
            sanitize_filename_part(decision_event_id),
        ]
    ) + ".mp4"


def sanitize_filename_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-._")
    return (cleaned or "unknown")[:80]


def sanitize_process_error(message: str, rtsp_url: str) -> str:
    return sanitize_error_message(message, rtsp_url) or "unknown_ffmpeg_error"


def sanitize_error_message(message: str, rtsp_url: str) -> str:
    sanitized = message.replace(rtsp_url, "rtsp://<redacted>")
    return " ".join(sanitized.split())[:240]
