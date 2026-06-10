# Hardware

Angel Gates builds the brain, buys the eyes, and leaves the gate operator's safety reflexes alone.

## Build

- Linux edge box: Raspberry Pi CM4/CM5, Pi 5, or industrial Linux equivalent.
- Relay HAT or isolated relay board.
- DIN-rail power supply.
- Industrial enclosure.
- SD card or eMMC storage.
- Optional hardware watchdog.

Working target cost for the edge box is roughly $120 to $180 in parts before enclosure and installer labor.

## Buy

- QR reader: embedded 2D barcode scanner rated for phone-screen/LCD reading.
- PIN/keypad: Wiegand, USB, serial, or GPIO keypad depending on pedestal constraints.
- IP camera with RTSP: required for damaged-arm evidence and chargeback workflow.
- Optional LPR-capable camera: deferred until phase two.
- Optional non-safety presence input: microwave radar or photo sensor wired only to the edge for wake/capture hints.
- Connectivity: Ethernet, Wi-Fi, or LTE.

## Physical Wiring

The relay's normally-open contacts land on the gate operator's open-command input terminals, the same class of input a keypad or reader controller uses.

The relay must be de-energized by default. Angel Gates failure or power loss means no relay intent is sent.

The edge stores relay configuration per gate:

- `relay_channel`: GPIO/driver channel. For the Raspberry Pi GPIO driver this is the BCM GPIO number, not the physical header pin number.
- `relay_pulse_ms`: momentary close duration. Default is 500 ms.
- `relay_cooldown_ms`: minimum time before another pulse on the same gate/channel. Default is 1500 ms.

The GPIO driver assumes an active-high relay board wired through normally-open contacts. Confirm the exact relay HAT schematic before install; some cheap relay boards are active-low and are not acceptable without an explicit driver/configuration change.

## DoorKing 1601 Pilot Shape

- Edge box mounts inside the existing operator cabinet.
- Relay output lands on the open-command input.
- QR reader mounts at driver-window height in the pedestal, roughly 42 to 48 inches from the ground.
- Existing dial pad remains in place as fallback.
- Existing loops, detector modules, photo eyes, reversing edges, and operator safety logic remain untouched.

## Pi First-Boot Package

The installable Pi package lives in `deploy/pi/`.

It creates `/var/lib/angel-edge` with restricted permissions, installs systemd services for the edge API and optional relay/camera/scanner/anchor publisher processes, writes the first-boot commissioning payload, and configures systemd hardware watchdog settings.

## LPR Geometry Note

Georgia and South Carolina are rear-plate-only states. Entry LPR cannot assume a front plate.

Practical paths:

- Mount camera past the pedestal and angled back toward the stopped vehicle's rear plate.
- Add LPR at exit first, where rear plates naturally face the camera.
- Defer LPR until QR/PIN pilot data proves the workflow and site geometry is known.

## Not Built By Angel Gates

- Gate arm.
- Operator motor controller.
- Safety loops.
- Entrapment protection.
- Photo eyes.
- Reversing edges.
- Gate construction.

Those stay in the operator/installer safety domain.
