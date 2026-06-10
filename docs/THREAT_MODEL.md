# Threat Model

This threat model focuses on realistic pilot and small-property deployment risks.

## Assets

- Device private key.
- Scoped API tokens.
- Resident credentials.
- Visitor QR tokens.
- Revocation lists.
- Event log and anchors.
- Relay intent path.
- Property/gate binding.

## Threats And Answers

### PIN Brute Force At The Pedestal

Risk: an attacker tries thousands of PINs at a gate.

Current answer: every deny is logged locally.

Gap: add gate-level and credential-type rate limiting. Proposed rule: after 3 wrong PINs at one gate, lock PIN attempts for 30 seconds, log the lockout, then increase backoff on repeated failures.

### Stolen Bearer Token

Risk: a manager laptop or dashboard token is stolen.

Current answer: tokens are short-lived, scoped, stored hashed on the edge, and revocable.

Gap: cloud token rotation and user/session inventory are not built yet.

### Photographed Commissioning QR

Risk: someone photographs the edge QR before install.

Current answer: QR payload has no authority. It only contains device ID, public key, and bootstrap nonce. Claim requires the edge to sign a challenge bound to property and gate.

### Binding Revoked But Edge Keeps Opening

Risk: fired manager, sold property, or compromised edge should stop authorizing.

Current answer: binding revocation revokes API tokens, writes a final event, anchors it, and makes authorization return `edge_binding_revoked` without relay intent.

### Event Log Edits

Risk: someone edits an old access event.

Current answer: event hashes cover previous hash, sequence, and full payload from fixed genesis.

### Event Log Tail Truncation

Risk: someone deletes the end of the log and presents a shorter valid chain.

Current answer: head anchors store sequence and hash. Once cloud stores anchors append-only, truncation below the latest anchor is detectable.

Gap: cloud-side anchor storage and fork rejection are not built yet.

### SD Card Failure Or Device Key Loss

Risk: a fresh image generates a new device identity for a gate that already has history.

Current answer: edge refuses half-present keypair state. A fresh image becomes a new device identity.

Gap: cloud-side installer rebind to existing property/gate slot is not built. Design: mark old binding superseded, preserve old event history, bind new device ID to the same gate slot, and resume sync under new identity.

### Physical Cabinet Access

Risk: someone opens the operator cabinet and tampers with the edge.

Current answer: physical cabinet security is the property/operator domain. Angel Gates should log what it can, but physical access means the site has a broader security problem.

### Unauthenticated Local API

Risk: someone on a flat property Wi-Fi calls the edge API.

Current answer: local API requires scoped bearer tokens even on localhost.

### Relay Inversion Or Stuck Open

Risk: a software or wiring bug holds the gate open.

Current answer: relay driver must be de-energized by default and emit intent only after allow.

Gap: real relay driver and Pi acceptance test with audible relay click are not built yet.
