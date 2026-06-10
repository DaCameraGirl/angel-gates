"""Edge-to-cloud anchor publishing."""

from __future__ import annotations

import json
import time
from contextlib import closing
from typing import Any, Protocol
from urllib import error, request

from . import store


class AnchorPublishError(RuntimeError):
    """Anchor publishing error."""


class AnchorClient(Protocol):
    def publish_anchor(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Publish an anchor payload and return witness response JSON."""


class HttpAnchorClient:
    def __init__(self, *, witness_url: str, witness_token: str) -> None:
        if not witness_url:
            raise AnchorPublishError("witness_url_required")
        if not witness_token:
            raise AnchorPublishError("witness_token_required")
        self.witness_url = witness_url.rstrip("/")
        self.witness_token = witness_token

    def publish_anchor(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        http_request = request.Request(
            f"{self.witness_url}/anchors",
            data=body,
            headers={
                "Authorization": f"Bearer {self.witness_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=5.0) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            try:
                body_text = exc.read().decode("utf-8")
                payload = json.loads(body_text)
                message = payload.get("error") or body_text
            except (UnicodeDecodeError, json.JSONDecodeError):
                message = exc.reason
            raise AnchorPublishError(f"witness_rejected_anchor:{message}") from exc
        except (OSError, error.URLError) as exc:
            raise AnchorPublishError(f"witness_unreachable:{exc}") from exc


class AnchorPublisher:
    def __init__(
        self,
        *,
        db_path: str,
        client: AnchorClient,
        event_interval: int = store.DEFAULT_ANCHOR_EVENT_INTERVAL,
        max_age_seconds: int = store.DEFAULT_ANCHOR_MAX_AGE_SECONDS,
    ) -> None:
        self.db_path = db_path
        self.client = client
        self.event_interval = int(event_interval)
        self.max_age_seconds = int(max_age_seconds)

    def publish_once(self, *, force: bool = False, reason: str = "manual") -> dict[str, Any]:
        with closing(store.connect(self.db_path)) as connection:
            store.migrate(connection)
            due = store.anchor_publish_due(
                connection,
                event_interval=self.event_interval,
                max_age_seconds=self.max_age_seconds,
            )
            if not force and not due["due"]:
                return {"ok": True, "published": False, "due": due}
            reasons = [reason] if force else list(due["reasons"])
            payload = store.anchor_publish_payload(connection, reasons=reasons)

        witness_response = self.client.publish_anchor(payload)
        if not witness_response.get("ok"):
            raise AnchorPublishError(str(witness_response.get("error") or "witness_rejected_anchor"))
        witness_anchor = witness_response["anchor"]
        with closing(store.connect(self.db_path)) as connection:
            store.migrate(connection)
            local_anchor = store.record_cloud_anchor_ack(
                connection,
                payload=payload,
                witness_anchor_id=witness_anchor["witness_anchor_id"],
                received_at=witness_anchor["received_at"],
                duplicate=bool(witness_response.get("duplicate")),
            )
        return {
            "ok": True,
            "published": True,
            "duplicate": bool(witness_response.get("duplicate")),
            "payload": payload,
            "witness_anchor": witness_anchor,
            "local_anchor": local_anchor,
        }


def run_anchor_publisher(
    *,
    db_path: str,
    witness_url: str,
    witness_token: str,
    poll_seconds: int = 10,
    event_interval: int = store.DEFAULT_ANCHOR_EVENT_INTERVAL,
    max_age_seconds: int = store.DEFAULT_ANCHOR_MAX_AGE_SECONDS,
) -> None:
    publisher = AnchorPublisher(
        db_path=db_path,
        client=HttpAnchorClient(witness_url=witness_url, witness_token=witness_token),
        event_interval=event_interval,
        max_age_seconds=max_age_seconds,
    )
    print(f"Angel Anchor Publisher polling every {poll_seconds}s")
    while True:
        try:
            result = publisher.publish_once()
            if result.get("published"):
                payload = result["payload"]
                print(
                    "published anchor "
                    f"edge={payload['edge_id']} sequence={payload['sequence']} "
                    f"witness={result['witness_anchor']['witness_anchor_id']}"
                )
        except AnchorPublishError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        time.sleep(max(1, int(poll_seconds)))
