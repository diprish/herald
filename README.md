# HERALD

**Human Entity Realtime Authenticated Link Delivery** — a next-generation messaging protocol designed to replace SMTP email.

HERALD eliminates spam and phishing **by structural design, not filtering**: the protocol has no primitive for unauthenticated or untrusted delivery.

## Core ideas

- **One person, one identity.** A single Global Identifier (GID) per physical human, progressively anchored to real-world identity (employer/school onboarding, national eID, bank KYC) — with instant, zero-effort registration at the entry level.
- **Contexts, not inboxes.** `diprish:deloitte`, `diprish:mit`, `diprish:home` — organizational namespaces granted and revoked by verified Context Authorities.
- **Trust before delivery.** Messages are admitted only through the trust chain (mutual contacts, shared org context, accepted requests, or implicit grants from the user's own actions). Cold sending does not exist.
- **Threads are signed event logs.** Replicated, append-only, Ed25519-signed — giving group messaging, multi-device sync, edits, reactions, and read state as ordinary events.
- **Real-time, end-to-end encrypted.** Persistent WebSocket transport, X25519 + AES-256-GCM, perfect forward secrecy, cross-signed device trust.
- **No HTML.** Structured content blocks make visual phishing impossible.
- **Zero-interaction default.** Any mechanism requiring a user decision must have a path where the decision is inferred from an action the user already took. Security must never cost the end user effort that email did not.

## How it compares to SMTP

HERALD replaces spam and phishing filtering with structural prevention, adds
real-time encrypted transport, and charges the user zero extra effort for that
security. See **[docs/comparison-with-smtp.md](docs/comparison-with-smtp.md)**
for a full, section-referenced comparison against SMTP, IMAP/POP,
SPF/DKIM/DMARC, PGP/S-MIME, and Matrix.

## Repository layout

```
spec/               Protocol specifications (v1.1 is current)
docs/               Architecture notes, diagrams, and comparisons
docs/architecture/  Tech stack decision and phased implementation roadmap
docs/proposals/     Pre-HIP drafts (Offers; Cold Contact; Reservations)
```

## Specification versions

| Version | Status | Highlights |
|---|---|---|
| [v1.1](spec/HERALD_Protocol_Specification_v1.1.md) | **Current draft** | Event-log threads, HCS/HFA API split, sliding sync, OIDC auth, cross-signing, progressive identity levels, implicit trust grants, day-one bidirectional SMTP bridge, Bridge API, governance model |
| [v1.0](spec/HERALD_Protocol_Specification_v1.0.md) | Superseded | Original envelope-based design |

## Planned components

1. **Identity Registry (IR)** — federated GID → public key registry
2. **HERALD Home Server (HHS)** — trust evaluation, thread log replication, real-time relay
3. **Client** — reference web/mobile client

## Status

Pre-implementation. The specification is a living draft; wire formats are subject to revision through the HIP (HERALD Improvement Proposal) process described in spec §16. The reference implementation's stack and phased plan are documented in [docs/architecture/](docs/architecture/).

## License

Specification text: CC-BY-4.0 (proposed). Reference implementations: Apache-2.0 (proposed).
