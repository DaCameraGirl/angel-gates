"""Local camera capture service.

This process owns RTSP/ffmpeg work. The HTTP authorization service can ask it
to capture evidence after an access event has already been committed.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .drivers.camera import CameraController, CameraError, FfmpegCameraDriver


def run_camera_service(
    db_path: str,
    host: str,
    port: int,
    *,
    token: str,
    rtsp_url: str,
    camera_id: str,
    storage_path: str,
    clip_seconds: int,
    retention_days: int,
    ffmpeg_path: str = "ffmpeg",
) -> None:
    if not token:
        raise CameraError("camera_service_token_required")
    controller = CameraController(
        db_path=db_path,
        rtsp_url=rtsp_url,
        storage_path=storage_path,
        camera_id=camera_id,
        clip_seconds=clip_seconds,
        retention_days=retention_days,
        driver=FfmpegCameraDriver(ffmpeg_path=ffmpeg_path),
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "AngelCamera/0.1"

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/capture":
                self.send_json(404, {"error": "not_found"})
                return
            if not self.authorized():
                self.send_json(401, {"error": "unauthorized"})
                return
            try:
                result = controller.request_capture(self.read_json())
            except (CameraError, ValueError, KeyError, json.JSONDecodeError) as exc:
                self.send_json(400, {"ok": False, "error": str(exc)})
                return
            self.send_json(202, result)

        def authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            return header == f"Bearer {token}"

        def read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Angel Camera listening on http://{host}:{port} for camera {camera_id}")
    httpd.serve_forever()
