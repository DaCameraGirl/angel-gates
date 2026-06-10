"""QR scanner input service for Angel Gates edge devices."""

from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from typing import Any, Callable, Iterator, TextIO
from urllib import error, request


class ScannerError(RuntimeError):
    """Scanner input or edge authorization error."""


@dataclass(frozen=True)
class ScanResult:
    ok: bool
    decision: str | None
    reason: str
    event_id: str | None = None
    relay_dispatch: bool | None = None


class EdgeHttpQrAuthorizer:
    """Submits scanned QR tokens to the local edge HTTP API."""

    def __init__(self, *, edge_url: str, edge_token: str, gate_id: str, scanner_id: str) -> None:
        self.edge_url = edge_url.rstrip("/")
        self.edge_token = edge_token
        self.gate_id = gate_id
        self.scanner_id = scanner_id

    def authorize(self, token: str, *, source: str) -> ScanResult:
        payload = {
            "credential_type": "qr",
            "credential_value": token,
            "gate_id": self.gate_id,
            "media": {
                "scanner_id": self.scanner_id,
                "scanner_source": source,
            },
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        http_request = request.Request(
            f"{self.edge_url}/authorize",
            data=body,
            headers={
                "Authorization": f"Bearer {self.edge_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=2.0) as response:
                result = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            raise ScannerError(f"edge_authorize_http_{exc.code}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ScannerError("edge_authorize_failed") from exc
        return scan_result_from_authorize_response(result)


def scan_result_from_authorize_response(response: dict[str, Any]) -> ScanResult:
    return ScanResult(
        ok=response.get("decision") == "allow",
        decision=str(response.get("decision") or ""),
        reason=str(response.get("reason") or "unknown"),
        event_id=response.get("event_id"),
        relay_dispatch=bool(response.get("relay_dispatch")) if "relay_dispatch" in response else None,
    )


def normalize_scan(raw: str | bytes) -> str:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    return raw.strip()


def process_scan(
    raw: str | bytes,
    *,
    source: str,
    authorize: Callable[[str], ScanResult],
) -> ScanResult:
    token = normalize_scan(raw)
    if not token:
        return ScanResult(ok=False, decision=None, reason="empty_scan_ignored")
    return authorize(token)


def run_scanner_service(
    *,
    edge_url: str,
    edge_token: str,
    gate_id: str,
    scanner_id: str,
    input_mode: str,
    serial_port: str | None = None,
    baudrate: int = 9600,
    evdev_path: str | None = None,
    output: TextIO = sys.stdout,
) -> None:
    authorizer = EdgeHttpQrAuthorizer(edge_url=edge_url, edge_token=edge_token, gate_id=gate_id, scanner_id=scanner_id)
    for raw_scan in scanner_source(input_mode=input_mode, serial_port=serial_port, baudrate=baudrate, evdev_path=evdev_path):
        result = process_scan(
            raw_scan,
            source=input_mode,
            authorize=lambda token: authorizer.authorize(token, source=input_mode),
        )
        print(json.dumps(scan_result_log(result), sort_keys=True), file=output, flush=True)


def scan_result_log(result: ScanResult) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "decision": result.decision,
        "reason": result.reason,
        "event_id": result.event_id,
        "relay_dispatch": result.relay_dispatch,
    }


def scanner_source(
    *,
    input_mode: str,
    serial_port: str | None,
    baudrate: int,
    evdev_path: str | None,
) -> Iterator[str]:
    if input_mode == "stdin":
        yield from read_stdin_scans(sys.stdin)
        return
    if input_mode == "serial":
        if not serial_port:
            raise ScannerError("serial_port_required")
        yield from read_serial_scans(serial_port, baudrate=baudrate)
        return
    if input_mode == "evdev":
        if not evdev_path:
            raise ScannerError("evdev_path_required")
        yield from read_evdev_scans(evdev_path)
        return
    raise ScannerError(f"unsupported_scanner_input:{input_mode}")


def read_stdin_scans(stream: TextIO) -> Iterator[str]:
    for line in stream:
        yield line


def read_serial_scans(port: str, *, baudrate: int = 9600) -> Iterator[str]:
    try:
        import serial  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on optional Pi package
        raise ScannerError("pyserial_required_for_serial_scanner") from exc

    with serial.Serial(port=port, baudrate=baudrate, timeout=None) as scanner:  # pragma: no cover - hardware path
        while True:
            yield scanner.readline().decode("utf-8", errors="ignore")


EV_KEY = 1
KEY_DOWN = 1
KEY_REPEAT = 2
KEY_ENTER = 28
KEY_LEFTSHIFT = 42
KEY_RIGHTSHIFT = 54
EVDEV_EVENT = struct.Struct("llHHI")

UNSHIFTED_KEYS = {
    2: "1",
    3: "2",
    4: "3",
    5: "4",
    6: "5",
    7: "6",
    8: "7",
    9: "8",
    10: "9",
    11: "0",
    12: "-",
    13: "=",
    16: "q",
    17: "w",
    18: "e",
    19: "r",
    20: "t",
    21: "y",
    22: "u",
    23: "i",
    24: "o",
    25: "p",
    26: "[",
    27: "]",
    30: "a",
    31: "s",
    32: "d",
    33: "f",
    34: "g",
    35: "h",
    36: "j",
    37: "k",
    38: "l",
    39: ";",
    40: "'",
    41: "`",
    43: "\\",
    44: "z",
    45: "x",
    46: "c",
    47: "v",
    48: "b",
    49: "n",
    50: "m",
    51: ",",
    52: ".",
    53: "/",
    57: " ",
}

SHIFTED_KEYS = {
    **{code: value.upper() for code, value in UNSHIFTED_KEYS.items() if value.isalpha()},
    2: "!",
    3: "@",
    4: "#",
    5: "$",
    6: "%",
    7: "^",
    8: "&",
    9: "*",
    10: "(",
    11: ")",
    12: "_",
    13: "+",
    26: "{",
    27: "}",
    39: ":",
    40: '"',
    41: "~",
    43: "|",
    51: "<",
    52: ">",
    53: "?",
}


class EvdevKeyboardDecoder:
    """Decodes Linux keyboard-style scanner events into complete scans."""

    def __init__(self) -> None:
        self.shift = False
        self.buffer: list[str] = []

    def feed(self, event_type: int, code: int, value: int) -> str | None:
        if event_type != EV_KEY:
            return None
        if code in {KEY_LEFTSHIFT, KEY_RIGHTSHIFT}:
            self.shift = value in {KEY_DOWN, KEY_REPEAT}
            return None
        if value not in {KEY_DOWN, KEY_REPEAT}:
            return None
        if code == KEY_ENTER:
            token = "".join(self.buffer)
            self.buffer = []
            return token
        keymap = SHIFTED_KEYS if self.shift else UNSHIFTED_KEYS
        character = keymap.get(code)
        if character:
            self.buffer.append(character)
        return None


def read_evdev_scans(device_path: str) -> Iterator[str]:
    decoder = EvdevKeyboardDecoder()
    with open(device_path, "rb", buffering=0) as device:  # pragma: no cover - hardware path
        while True:
            raw = device.read(EVDEV_EVENT.size)
            if len(raw) != EVDEV_EVENT.size:
                continue
            _, _, event_type, code, value = EVDEV_EVENT.unpack(raw)
            token = decoder.feed(event_type, code, value)
            if token is not None:
                yield token
