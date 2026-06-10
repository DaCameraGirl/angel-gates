# Rear-Plate-Aware LPR Pilot Plan

This is a phase-two plan. It should start only after the QR/PIN pilot produces real entry, camera, support, and incident-window data.

The first deployable system remains QR/PIN authorization with camera-backed event evidence. LPR is an added credential and evidence client over the same edge/event-log spine, not a replacement for the edge box, relay boundary, or tamper-evident log.

## Why Rear-Plate Geometry Matters

Georgia and South Carolina field deployments should be designed as rear-plate-first lanes. A front-facing camera at the pedestal is the wrong default if most vehicles only present a rear plate after they pass the reader.

The preferred pilot geometry is:

- Keep the QR/PIN reader at the normal driver stop point.
- Place the LPR camera past the pedestal, downstream of the decision point.
- Aim the camera back toward the rear of the vehicle as it clears the pedestal and approaches the barrier arm.
- Keep the camera outside the gate operator safety envelope and away from moving arm hardware.
- Treat the existing evidence camera and the LPR camera as separate roles unless one mounting point proves it can reliably capture both the incident scene and the rear plate.

The practical goal is not perfect computer vision. The goal is to learn whether rear-plate capture can identify a vehicle often enough to reduce manager review time without creating bad denials.

## Site Survey Inputs

Collect these before proposing LPR hardware:

- Lane direction, vehicle stop point, pedestal position, arm position, loop detector locations, and expected vehicle path.
- Camera mounting options past the pedestal: post, wall, canopy, cabinet, or dedicated pole.
- Distance and angle from camera to rear plate when the vehicle is stopped or moving slowly.
- Day, night, rain, headlight, taillight, glare, and reflective-plate conditions.
- Lane width, turn radius, tailgating behavior, and whether vehicles queue bumper-to-bumper.
- Power and network path for a second camera.
- Whether the property already has cameras with usable rear-plate views.
- Any property notice, privacy, retention, or resident-consent requirements.

Do not sell LPR from a parking-lot assumption. Walk the exact lane.

## Pilot Phases

### 1. Post-QR/PIN Review

Use the QR/PIN pilot data first:

- entry volume by hour
- median authorization time
- fallback dial-pad usage
- manager review burden
- camera clip quality around allow and deny events
- damaged-arm or suspicious-event windows

If QR/PIN plus event-linked video already solves the manager pain, defer LPR.

### 2. Shadow Mode

Install or aim the LPR camera without allowing it to open the gate.

For each edge event, record:

- event ID and timestamp
- gate ID
- plate read text, if any
- confidence score
- image or crop reference when retention policy allows it
- fallback reason when no reliable plate is read

Shadow mode should answer: "Would this have helped the manager find the right vehicle?" It should not affect authorization.

### 3. Assisted Authorization

Only after shadow-mode results are credible, allow plate credentials as an assisted path:

- High-confidence known plate can authorize.
- Low-confidence read returns fallback required.
- Unknown plate returns fallback required.
- Missing read returns fallback required.
- QR/PIN remains available and should be presented as the normal fallback, not as an error state.

The edge already models this with `credential_type=plate`, `confidence`, `confidence_threshold`, and `fallback_required`. The first threshold should be conservative and adjusted from site data, not guessed from a vendor demo.

### 4. Production Consideration

Move beyond assisted authorization only if the property sees:

- high rear-plate capture rate in the real lane
- low false-match risk
- acceptable fallback rate
- no material increase in support calls
- manager-visible evidence value during real incident review
- clear resident and property communication about plate use and retention

## Decision Policy

LPR must never create silent denial.

Use these outcomes:

- `allow`: known plate, correct gate, valid time window, confidence at or above threshold.
- `deny`: known plate explicitly revoked or outside scope.
- `fallback_required`: low confidence, unknown plate, missing plate, unreadable plate, ambiguous match, or camera/LPR service error.

The driver should see a QR/PIN fallback path. The manager should see an event reason that explains why LPR was not enough.

## Evidence Policy

LPR evidence should attach to the same event spine as QR/PIN:

- plate read and confidence
- plate crop or camera clip reference
- linked access event ID/hash
- relay event when a pulse was emitted
- latest known anchor for integrity review

For privacy and chargeback review:

- Store only the minimum plate evidence needed for the property use case.
- Avoid exposing full plate values in broad dashboard lists when a masked display is enough.
- Apply retention to plate crops and clips.
- Do not publish plate numbers, resident names, unit numbers, or raw incident media without written permission.

## Acceptance Metrics

A rear-plate-aware LPR pilot should report:

- rear-plate capture rate during real entries
- high-confidence match rate
- fallback-required rate
- false-positive investigations
- false-negative investigations
- manager time saved during incident review
- support tickets caused by LPR behavior
- night and rain performance compared with daytime baseline

Do not present LPR as proven until these numbers come from the actual lane.

## What Stays Out Of Scope

- Replacing QR/PIN in the first QR/PIN pilot.
- Opening the gate from an unverified or low-confidence plate read.
- Using LPR failure as a reason to strand residents without fallback.
- Changing the operator, safety devices, loops, photo eyes, or UL 325 safety functions.
- Treating OEM camera analytics as the product spine.

