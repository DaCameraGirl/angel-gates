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

Current answer: failed PIN attempts are stored in SQLite and counted over a sliding one-hour window. Lockouts are scoped by gate plus credential type, and also by credential hash, so a gate-level attack is contained to that gate while repeated attacks against one credential still leave a manager-visible trail. Backoff is 30 seconds after 3 failures, 5 minutes after 6, and 1 hour after 9. Every lockout writes a `rate_limit` event into the hash-chained log.

### QR Abuse At The Pedestal

Risk: an attacker spams malformed or revoked QR payloads to burn CPU or probe visitor-pass behavior.

Current answer: QR failures use the same persistent rate-limit path as PIN failures. After lockout, the edge denies before signature verification, revocation lookup, or token usage checks. Scanner and HTTP authorization request logs store a QR fingerprint instead of the raw token value.

### Stolen Bearer Token

Risk: a manager laptop or dashboard token is stolen.

Current answer: tokens are short-lived, scoped, stored hashed on the edge, and revocable.

Gap: cloud token rotation and user/session inventory are not built yet.

### Photographed Commissioning QR

Risk: someone photographs the edge QR before install.

Current answer: QR payload has no authority. It only contains device ID, public key, and bootstrap nonce. Claim requires the edge to sign a challenge bound to property and gate.

### Revoked Binding Artifact Replay

Risk: a revoked cloud-signed binding artifact is replayed during a later recommissioning attempt for the same physical edge.

Current answer: the edge stops authorizing when binding revocation lands, and factory reset removes the local binding state and device key.

Gap: cloud should store revoked binding artifact hashes and refuse to honor them during future claim or rebind flows.

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

### Clock Manipulation

Risk: an attacker or bad OS image moves the edge clock backward, making expired QR tokens look valid, weakening `locked_until` rate-limit enforcement, or making event timestamps unreliable.

Current answer: QR verification allows only a small skew tolerance for normal drift.

Gap: the Pi image should include RTC or verified NTP sync, and the HTTP authorization service should refuse to start access decisions until time is sane.

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

Current answer: relay control is split into a local relay service that owns GPIO and accepts only momentary pulse requests from the authorization service. The GPIO driver initializes active-high outputs off, pulses for a bounded duration, and turns off in a `finally` block. The runtime has no hold-open command. Duplicate allow bursts are suppressed by per-gate/channel cooldown. Actual pulses and cooldown suppressions write `relay` events into the hash-chained log.

Gap: Pi acceptance testing must verify the selected relay HAT is active-high, normally-open, de-energized by default, and audibly clicks only on allow cases.
