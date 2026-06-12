# Angel Gates DoorKing Add-On Proposal

Prepared for: [Property / Property Manager]  
Prepared by: Angel Gates  
Date: [Date]

## The Short Version

Angel Gates is a bonus app and evidence layer for the DoorKing gate system already on site.

It does not replace the existing DoorKing box, gate operator, call box, keypad, loops, photo eyes, safety devices, or installer setup. The current metal DoorKing box stays in place.

Angel Gates adds:

- Resident and visitor QR/PIN access.
- Time-limited guest, delivery, vendor, and contractor passes.
- Manager control over who has access and when.
- Timestamped gate events.
- Camera-linked incident evidence using the property's existing camera/NVR system when available.
- Email alerts to the property manager when an incident needs review.
- A cleaner evidence trail for damaged gate arms, chargebacks, resident notices, vendor disputes, and board review.

## The Problem Today

The property already has a working DoorKing gate setup, but the visitor experience and incident review process are still painful.

Common issues:

- Guests and delivery drivers get stuck at the old metal call box/keypad.
- Wrong codes trigger loud beeps and repeated failed attempts.
- Residents share permanent gate codes because temporary access is inconvenient.
- Managers have to piece together gate events and camera footage manually.
- When a gate arm is damaged, it can be hard to prove which resident, visitor, vendor, or vehicle was involved.
- The property may eat the cost of damage because the evidence trail is weak.

Angel Gates fixes the workflow around the gate without ripping out the existing DoorKing equipment.

## What Changes For Residents And Visitors

Residents and managers can send temporary QR/PIN passes before a visitor arrives.

Example uses:

- Family and friends.
- Food delivery.
- Package delivery.
- Cleaners.
- Dog walkers.
- Contractors.
- Maintenance vendors.
- Rideshare or medical transport.

Each pass can have:

- A sponsor: resident, manager, vendor, or unit.
- A gate or lane.
- A start time.
- An expiration time.
- A QR code or PIN.
- A status: active, suspended, expired, or denied.

The visitor does not have to search the old directory, call the resident from the box, or keep retrying a shared code while the keypad beeps. They use the approved Angel Gates pass, the gate opens, and the event is logged.

The benefit is simple: easier access for the right people, better accountability for the property.

## What Changes For The Property Manager

The manager gets a dashboard for access and incident review.

Manager benefits:

- Create, suspend, or expire visitor and vendor passes.
- See who sponsored each pass.
- See when a pass was used.
- See denied attempts and expired-code attempts.
- Match gate events to camera footage.
- Receive incident emails with timestamp, gate, credential, sponsor/unit, and clip or snapshot reference.
- Build a cleaner chargeback packet when a gate arm is damaged.

Instead of asking, "Who came through around that time?", the manager can review a specific event window.

## Incident Email Workflow

Angel Gates can use the property's existing camera system if the camera or NVR provides an accessible stream, snapshot, or clip export. If the current system cannot provide usable clips, a small pilot camera can be added for the gate arm and vehicle tag area.

When an incident needs review, the property manager receives an email with:

- Property, gate, and lane.
- Exact timestamp.
- Credential used: QR, PIN, resident pass, visitor pass, vendor pass, or other access method.
- Associated resident, unit, visitor sponsor, vendor, or work order when known.
- Vehicle tag/plate reference when visible.
- Snapshot or clip link for the matching time window.
- Event ID and review link.
- Status such as needs review, likely responsible event, dismissed, or chargeback-ready.

The email should present evidence for manager review, not make a final accusation automatically.

## How It Works Beside DoorKing

DoorKing stays in place. Angel Gates runs beside it.

Install shape:

- Angel Gates edge controller is installed at one gate.
- QR/PIN reader is mounted near the existing pedestal.
- Angel Gates sends a momentary open command to the same class of gate input used by keypads and access readers.
- Existing DoorKing box/dial pad remains active.
- Existing safety devices and gate operator behavior remain untouched.
- Existing cameras are connected only if the property approves access to the camera/NVR feed.

Angel Gates makes local allow/deny decisions from a cached credential list. If internet service is unavailable, already-synced residents and passes can continue working locally, and events queue for later sync.

## Entry And Exit

For entry:

- Resident, visitor, or vendor uses an Angel Gates QR/PIN pass.
- Angel Gates validates the pass locally.
- If allowed, Angel Gates logs the event and sends the gate open command.

For exit:

- The existing free-exit loop can remain in place if normal exit behavior is enough.
- If the property wants exit accountability too, Angel Gates can add an exit-side reader and/or camera event capture.

## 90-Day Pilot

Pilot scope:

- One gate.
- Existing DoorKing setup remains in place.
- QR/PIN access for selected residents, visitors, vendors, and managers.
- Existing camera/NVR feed used if accessible.
- Incident email alerts to the property manager.
- Event review and basic incident export.
- No replacement of DoorKing.
- No modification of gate safety equipment.

Success metrics:

- Visitor pass usage.
- Entry speed compared with the current call-box/keypad workflow.
- Number of denied or expired attempts captured.
- Number of gate-arm incident windows with useful evidence.
- Number and value of possible chargeback opportunities.
- Manager satisfaction after two weeks and at 90 days.
- Installer feedback on wiring and support burden.

## Pricing After Pilot

For the first 90-day pilot, Angel Gates can waive hardware and setup fees while proving value.

Standard pricing after a successful pilot:

- Hardware kit: $499 one-time per installed gate package.
- Installation/setup: $350 one-time.
- Service: $79/month per gate plus $0.75/month per unit.

Example for a one-gate, 270-unit property:

- Standard SaaS: $279/month.
- Year-one total after conversion: $4,197.
- Year-two onward: $3,348/year.

## What We Need From The Property

To prepare the pilot, Angel Gates needs:

- Permission to run a 90-day pilot at one gate.
- Exact DoorKing model numbers if available.
- Gate count and lane layout.
- Confirmation that the existing DoorKing box stays in place.
- Permission for a qualified gate/access installer to mount the Angel Gates reader and edge controller.
- Camera/NVR brand, model, and access method if the property wants to use existing cameras.
- Property manager email address for incident alerts.
- Current gate-arm/service-call history if available.
- Current monthly phone, cellular, or cloud cost tied to gate access if available.
- Decision-maker contact for pilot approval and post-pilot conversion.

## Short Email Version

Subject: DoorKing gate add-on pilot

Hi [Name],

Following up on our conversation, I put together a pilot proposal for Angel Gates as an add-on to the existing DoorKing gate setup.

The current DoorKing box, gate operator, and safety system would stay in place. Angel Gates would add a bonus QR/PIN app layer so residents and managers can send time-limited passes to guests, deliveries, cleaners, vendors, contractors, and family members.

The property also gets a better evidence trail. Each Angel Gates event is timestamped, tied to a sponsor/unit/vendor when known, and can be matched to the property's camera footage. If there is a gate-arm incident, the manager can receive an email with the event details, timestamp, and clip or snapshot reference.

The first pilot would run for 90 days at one gate. We would measure visitor-pass usage, entry speed, denied attempts, manager usability, and whether event/video evidence helps with incident review or chargebacks.

The standard post-pilot price would be $499 hardware, $350 setup, and $79/month per gate plus $0.75/month per unit. For a 270-unit, one-gate property, that is $279/month after the pilot.

Can we schedule a quick walkthrough to confirm the DoorKing model, gate layout, camera/NVR access, property manager email for alerts, and recent gate-arm service history?

Best,  
[Your Name]

## Safety Boundary

Angel Gates is an authorization and evidence layer. It is equivalent to adding a keypad or reader controller.

It does not control, modify, certify, bypass, or monitor gate operator safety functions. Existing DoorKing operator behavior, loops, photo eyes, reversing edges, entrapment protection, signage, emergency access, and other site safety systems remain in place.

Installation must be performed by a qualified gate/access installer.

Power loss or Angel Gates failure should leave the existing DoorKing gate system behaving as it did before installation.

## Later DoorKing Integration

Angel Gates should start as a retrofit layer beside DoorKing.

Later, if the property authorizes it and official DoorKing/DKS access is available, Angel Gates can evaluate:

- Read-only import of resident, unit, gate, or credential labels.
- Export of event summaries or incident packets.
- Reconciliation of gate names and unit labels.
- Supplemental DoorKing event context.

Any deeper integration should be based on official documentation, property authorization, and a clear support path.

## Source Notes

- DoorKing product categories and current Easy Connect options: https://www.doorking.com/
- DoorKing Cloud account/programming page: https://www.doorking.com/cloud/
- DoorKing eVolve resident app page: https://www.doorking.com/dks-easy-connect/evolve-resident-app/
- DoorKing 2137 video entry system page: https://www.doorking.com/evolve-series/2137-video-entry-system/
