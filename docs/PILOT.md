# Pilot Plan

This is the working plan for a first live property pilot. Details here are field notes to verify before outreach or contract language.

## Target Property

- Working target: Ansley Commons.
- Working manager/operator note: Birge & Held managed.
- Working size note: 270 units.
- Working construction note: built 2014.
- Gate hardware note: DoorKing 1601 barrier gate with existing dial pad.
- Recent work note: 2023 renovation did not solve the gate workflow.

## Pain Points To Validate

- Dial-pad backup process is slow and produces poor accountability.
- Gate arm damage, open-gate periods, and related service calls may cost roughly $4,000 to $8,000/year; validate this from maintenance records before using it in sales copy.
- Managers need a reliable way to answer "who came through at this time?"
- Managers need evidence strong enough to charge back damaged arms to the responsible unit or visitor.
- The existing operator and safety system should remain in place.

## Pilot Scope

- Duration: 90 days free.
- Hardware: one edge box at one gate.
- Credentials: QR and PIN only.
- Camera evidence: in pilot scope because damaged-arm chargeback is the wedge.
- LPR: out of pilot scope unless the site demands it after QR/PIN and camera evidence are proven. See `docs/LPR_PILOT.md` for the later rear-plate-aware plan.
- Install path: licensed gate installer or maintenance lead under installer guidance.
- Existing dial pad remains as fallback.
- Residents who opt in use QR/PIN flow; everyone else can keep using the old path.

## Success Metrics

- Entries per hour through the pilot lane.
- Median time per entry compared with dial-pad baseline.
- Number of denied attempts captured with reason.
- Number of gate-arm incident windows where event evidence identifies likely responsible unit/visitor.
- Number and value of chargeback opportunities created from event/video evidence.
- Manager satisfaction after two weeks and at 90 days.
- Installer feedback on cabinet wiring, commissioning, and support burden.

## Pilot Asks

- Signed pilot agreement.
- Permission to install one edge box and credential reader without modifying safety devices.
- Permission to use anonymized operational metrics.
- Permission to report validated savings and chargeback recovery numbers if the pilot succeeds.
- Permission to use the property as a case study if the pilot succeeds.
- Intro to a regional decision-maker if success metrics are met.

## Acceptance Gate Before Install

- Edge boots into unclaimed state and prints/scans commissioning payload.
- Claim challenge and binding artifact flow works.
- Dashboard token is scoped and expires.
- PIN and QR allow cases click the relay.
- Deny cases do not click the relay.
- Allow/deny events can be matched to camera clips for the same time window.
- Binding revocation stops authorization.
- Verify-log passes after the pilot test battery.
- Factory reset returns edge to unclaimed state.

Run the live edge service acceptance battery from a laptop on the property LAN or from the Pi:

```bash
python -m edge.angel_edge pilot-acceptance \
  --edge-url http://EDGE_HOST:8765 \
  --edge-token "$ANGEL_INSTALLER_TOKEN" \
  --gate-id front \
  --relay-channel 26 \
  --observed-relay-clicks 3
```

The runner provisions isolated test credentials through `/sync/delta`, then checks PIN, QR, plate, revoked QR, expired QR, low-confidence plate, bad bearer, `/events`, `/events/stream`, `/anchors/head`, and `/verify-log`.

The optional `--include-binding-revocation` check is destructive because it revokes local API tokens on the target edge. Use it only on a disposable acceptance image or after confirming reset access.
