# HERALD Protocol Specification
## Human Entity Realtime Authenticated Link Delivery
### Version 1.1 — Draft

---

## Changelog from v1.0

| Area | Change |
|---|---|
| Design principles | Added **2.7 Zero-interaction default** as a binding design constraint |
| Identity | Registration is now **progressive**: instant unverified GIDs, verification unlocked by external anchors (eID, KYC, employer HR) |
| Identity | Added **social/institutional key recovery** (context-shard escrow + cross-signing) |
| Trust chain | Added **implicit trust grants**: transactional, introduction-forwarding, context-inheritance |
| Trust chain | Connection Request rate limit is now **adaptive** (acceptance-rate based), not a flat 10/day |
| Threads | Replaced loose envelopes with a **signed append-only event log per thread** (Matrix-derived event-graph, simplified) |
| APIs | Split into **Client-Server API (HCS)** and **Federation API (HFA)** |
| Sync | Added **sliding sync** as the mandatory client sync model |
| Auth | `HERALD_AUTH` now layered on **OIDC / OAuth 2.0** |
| Devices | Added **cross-signing device trust** (verify once, chain thereafter) |
| Migration | SMTP gateway is now **day-one and bidirectional**, invisible to the user |
| Contexts | Revocation now has a **90-day grace redirect** state |
| Links | Pre-resolution now **warns and displays**, never hard-rejects (except known-malicious) |
| Retention | Offline queue retention is **recipient-configurable** (30-day floor); non-delivery produces a manifest, never silent deletion |
| KDS | Added **push invalidation** on key rotation |
| Ecosystem | Added **generic Bridge API** (SMTP gateway is bridge #1) |
| Governance | Added **HIP process** (HERALD Improvement Proposals) and foundation model |

---

## 1. Abstract

HERALD is a next-generation messaging protocol designed to replace SMTP-based email. It is built on three foundational principles: **one physical identity per person**, **trust-chain-gated delivery**, and **real-time encrypted transport**. HERALD eliminates spam and phishing by design — not by filtering — because the protocol itself makes unauthenticated and untrusted delivery structurally impossible.

Version 1.1 restructures the protocol around a replicated event-log thread model, splits the client and federation APIs, and — critically — binds every mechanism to a zero-interaction principle: security must never cost the end user effort that email did not.

---

## 2. Design Principles

1. **One person, one identity.** A human being holds a single global identifier. Verification is anchored to real-world identity — but acquired progressively, riding on verifications the user has already performed elsewhere (employer onboarding, national eID, bank KYC).

2. **Contexts, not inboxes.** A person's identifier extends with organizational namespaces (`:home`, `:deloitte`, `:mit`) representing life contexts, granted and revoked by verified organizations.

3. **Trust before delivery.** A message is delivered only if the sender is within the recipient's trust chain. Cold messages are impossible by default.

4. **Cryptographic authenticity.** Every event is signed by the sender's device key, chained to their identity. Spoofing is mathematically impossible.

5. **Real-time as first-class.** Persistent connections, push delivery, millisecond latency. Threads are live replicated logs, not store-and-forward envelopes.

6. **No HTML rendering.** Message content is structured data. Phishing through formatted hyperlinks, CSS tricks, and visual deception is not possible.

7. **Zero-interaction default.** *Any protocol mechanism that requires a user decision MUST have a path where that decision is inferred from an action the user already took for another reason.* Explicit approval screens are the fallback of last resort, budgeted at fewer than one per user per week. Every HIP (see §16) must include a zero-interaction analysis.

---

## 3. Identity System

### 3.1 Global Identifier (GID)

```
GID = [a-z0-9][a-z0-9_-]{2,31}
```

Examples: `diprish`, `alice`, `bob99`. Globally unique, permanent, never re-assigned.

### 3.2 Context Address

```
ContextAddress = GID ":" ContextName
ContextName    = [a-z0-9][a-z0-9_-]{1,31}
```

```
diprish:home       → personal context (self-managed)
diprish:deloitte   → work context (Deloitte-verified)
diprish:mit        → school context (MIT-verified)
```

A bare GID (`diprish`) is equivalent to `diprish:default`.

### 3.3 Full HERALD Address

```
HERALDAddress = ( GID | ContextAddress ) [ "@" Domain ]
```

The `@Domain` suffix is used only for federation routing; within the HERALD network the GID alone is globally unique.

### 3.4 Verification Levels (NEW in 1.1)

A GID exists at one of three levels. **Registration at Level 0 is instant and requires nothing from the user beyond choosing a name** — a keypair is generated silently on-device.

| Level | Name | How it is reached | Capabilities |
|---|---|---|---|
| 0 | **Unverified** | Instant self-registration | Message mutual contacts only. Cannot send Connection Requests. Cannot receive org contexts. Shown with an "unverified" marker. |
| 1 | **Anchored** | Any single external anchor: verified org context grant (employer/school HR has already ID-checked the person), national eID assertion, or bank-KYC OIDC assertion | Full trust-tier participation. Connection Requests enabled. |
| 2 | **Registry-verified** | Biometric or government-ID enrollment with an IRA node, deduplicated against the global registry | One-identity-per-person guarantee enforced. Required to *issue* context grants (i.e., to operate a Context Authority) and for high-trust roles. |

**Key property:** the most common path from Level 0 to Level 1 is *receiving a job or school context grant* — the organization already verified the person's identity during onboarding. The user does zero additional work; verification they performed for another reason propagates into the protocol (Principle 2.7).

Duplicate-identity enforcement (the "one person" rule) binds strictly at Level 2. Level 0–1 identities that attempt abuse patterns are throttled by the adaptive limits in §6.5 and can be challenged to verify.

### 3.5 Registration Process

**Level 0 (instant):**
1. Client generates an Ed25519 identity keypair and a device keypair on-device.
2. Client claims an available GID at any HERALD server; the server publishes `GID → identity_pubkey` to the registry with `level: 0`.
3. Done. Total user effort: typing a name.

**Level 1 (automatic when an anchor appears):**
- When a Context Authority issues a grant for the GID, or an eID/KYC OIDC assertion is presented, the IRA upgrades the record to `level: 1` and records the anchor type (not the underlying identity documents, which are never stored by the IRA at this level).

**Level 2 (explicit, once, optional for most users):**
1. User presents government ID or biometric enrollment to an IRA node.
2. IRA verifies the proof has not previously anchored another GID.
3. IRA issues a signed Identity Certificate binding `GID → identity_pubkey → anchor_hash`.

### 3.6 Device Keys and Cross-Signing (NEW in 1.1)

Each device holds its own device keypair. The identity key signs a **self-signing key**, which signs each device key. Adding a new device:

1. New device generates its device keypair and displays a QR code / short emoji sequence.
2. Any existing verified device scans/compares and countersigns.
3. The new device is now trusted by every counterparty automatically via the signature chain — no re-verification with any contact, ever.

Total user effort for a new phone: one QR scan. This adopts the cross-signing model proven in Matrix, unchanged in substance.

### 3.7 Key Recovery (NEW in 1.1)

Losing every device MUST NOT mean losing the identity. Two recovery mechanisms, both zero-configuration:

**Context-shard escrow (default, automatic).** When a GID holds ≥2 organizational contexts, the client automatically Shamir-splits a recovery key and escrows one encrypted shard with each Context Authority (the CA cannot read it alone). Recovery = re-authenticating with 2 of the user's organizations via their normal SSO ("verify with your employer"). Threshold: 2-of-N, N = number of org contexts, minimum 2.

**Encrypted cloud recovery (fallback).** A recovery key encrypted under a key derived from the user's platform account (iCloud Keychain, Google Password Manager, or any WebAuthn-capable store). Enabled by default at first login; opt-out available.

Recovery rotates the identity keypair (§3.8) and revokes all prior device keys. Counterparties see a signed "identity recovered on <date>" event in shared threads.

**Explicitly rejected:** seed phrases, mandatory printed recovery codes, or any mechanism requiring the user to safeguard an artifact.

### 3.8 Key Rotation

New identity public key signed by the current identity key (or produced by recovery in §3.7), published to the registry, **push-invalidated** to all KDS caches (§11.5).

### 3.9 Context Registration and Revocation

**Personal contexts** are created freely by the holder.

**Organizational contexts** require the organization to operate a registered Context Authority (CA), whose operator identity is Level 2. The CA signs a context grant `GID:context → valid_until → grant_signature`.

**Revocation with grace redirect (CHANGED in 1.1):** when a grant is revoked (e.g., employment ends):

1. The context immediately stops accepting *new-relationship* inbound messages and can no longer be used to *send* under the org identity.
2. For **90 days**, inbound events on pre-existing threads addressed to the revoked context generate a signed `CONTEXT_MOVED` hint pointing to the bare GID. The sender's client transparently re-addresses; the sender sees nothing unless they inspect.
3. The user's client automatically posts a farewell/redirect event to active threads (suppressible).
4. Thread history remains readable forever — grant validity is evaluated **at event-acceptance time**, never retroactively.
5. After 90 days, the context returns `CONTEXT_REVOKED` with no forwarding.

---

## 4. Thread Model — Signed Event Logs (NEW in 1.1)

v1.0's loose envelope model is replaced. **A thread is a replicated, signed, append-only event log**, held identically by every participant's server. This is the Matrix event-graph insight, deliberately simplified for HERALD's closed-membership setting.

### 4.1 Events

Everything in a thread is an event:

```json
{
  "event_id": "$7f3a...:herald.deloitte.com",
  "thread_id": "!01J8X2M0AB:herald.deloitte.com",
  "seq": 42,
  "prev_event": "$6e2b...",
  "type": "h.message",
  "sender": "diprish:deloitte",
  "origin_server": "herald.deloitte.com",
  "created_at": "2026-07-21T09:32:00.000Z",
  "content": { "...type-specific..." },
  "device_key_id": "DEVKEY:AB12",
  "signature": "<Ed25519 over canonical event>"
}
```

Core event types:

| Type | Purpose |
|---|---|
| `h.message` | A message body (see §5) |
| `h.member` | Membership change: invite, join, leave, remove |
| `h.thread.meta` | Subject/name change |
| `h.read` | Read marker (per-user, replaces loose read receipts) |
| `h.react` | Reaction to an event |
| `h.edit` | Supersedes a prior event's content (original retained in log) |
| `h.redact` | Blanks a prior event's content (tombstone retained) |
| `h.recovery` | Identity-recovered notice (§3.7) |
| `h.bridge` | Bridged-content marker (§14) |

### 4.2 Ordering and Consistency (simplified vs. Matrix)

Because HERALD threads have a **closed, verified membership** (trust chain — §6), full Byzantine state resolution is unnecessary. Instead:

- Each thread has a **sequencing server**: the origin server of the thread creator (transferable via an `h.thread.meta` handover event, e.g., if that server retires).
- The sequencing server assigns the monotonic `seq` and the `prev_event` back-link. All participant servers replicate the resulting linear log.
- If the sequencing server is unreachable, participant servers buffer outbound events and deliver on reconnect; clients render buffered events optimistically, marked "sending."
- Divergence is detectable (broken hash chain) and resolved by re-fetching the canonical log from the sequencing server. There is no merge algorithm to get wrong.

This trades a small availability cost for a drastic reduction in protocol complexity — appropriate because HERALD threads are correspondence, not 50,000-person public chatrooms.

### 4.3 What this buys

- **Group messaging** falls out naturally: a thread with N members is the same object as a thread with 2. (`h.member` events are trust-chain-checked like any delivery.)
- **Multi-device consistency** is automatic: every device replays the same log.
- **History sync** on a new device = fetch the log (windowed via sliding sync, §8.4).
- **Read state, edits, reactions** are ordinary events — no side-channel protocols.

### 4.4 One-off messages

A classic "email" is simply a new thread containing one `h.member` set and one `h.message`. There is no separate envelope pathway.

---

## 5. Message Content Format

`h.message` content:

```json
{
  "format": "text/herald",
  "text": "Hi, please find the Q3 numbers attached.",
  "blocks": [
    { "kind": "paragraph", "text": "Hi, please find the Q3 numbers attached." },
    { "kind": "table", "header": ["Region", "Revenue"], "rows": [["EMEA", "€4.2M"]] },
    { "kind": "image", "attachment_ref": "att-01", "alt": "Q3 revenue chart" },
    { "kind": "code", "lang": "python", "text": "print('hello')" }
  ],
  "mentions": ["boss:deloitte"],
  "links": [
    {
      "display": "Q3 Report",
      "declared_url": "https://dttshort.link/q3",
      "resolved_url": "https://drive.deloitte.com/files/q3-2025.pdf",
      "hops": 1,
      "verdict": "clean",
      "verified_at": "2026-07-21T09:31:58Z"
    }
  ]
}
```

**Structured blocks (NEW in 1.1):** paragraphs, tables, inline images (by attachment reference), code, quotes, and lists cover the legitimate uses of HTML mail. Still no scripts, no CSS, no external resource loading, no forms.

**Link handling (CHANGED in 1.1):** the sending server resolves every link at send time and records the full redirect chain. Policy:

- `verdict: clean` → rendered normally; client shows the resolved destination on hover/long-press.
- `verdict: mismatch` (display text is itself a URL that differs from destination, or chain > 2 hops) → rendered with an inline warning; still clickable.
- `verdict: malicious` (matches threat registry) → link neutralized (plain text), event still delivered.

Hard rejection is reserved for `malicious` only. Unsubscribe links, tracking parameters, and corporate short-links all work — the user is informed, never blocked (Principle 2.7: no support tickets).

### 5.1 Attachments

Unchanged in structure from v1.0 (encrypted blob store, per-recipient hybrid-encrypted AES-256-GCM keys, SHA-256 content hash, server holds ciphertext only), now referenced from events:

```json
{
  "attachment_id": "att-01",
  "filename": "q3-report.pdf",
  "content_type": "application/pdf",
  "size_bytes": 204800,
  "sha256": "e3b0c442...",
  "storage_ref": "herald://store/01J8X3KQ9E/att-01",
  "encrypted_keys": { "boss": "<...>", "colleague": "<...>" }
}
```

---

## 6. Trust Chain

### 6.1 Trust Tiers

A delivery (thread invite, or first event from a new sender) is admitted if any of:

**Tier 1 — Mutual contact.** Sender's GID is in the recipient's contact list or vice versa.

**Tier 2 — Shared organizational context.** Both hold currently valid grants from the same CA (`alice:deloitte` ↔ `diprish:deloitte`).

**Tier 3 — Accepted Connection Request.** Explicit acceptance of a quarantined request.

**Tier 4 — Implicit grant (NEW in 1.1).** See §6.2.

### 6.2 Implicit Trust Grants (NEW in 1.1)

Implicit grants encode Principle 2.7: the user's own actions create trust without an approval screen.

**Transactional grant.** When a user hands their HERALD address to an entity in an authenticated flow (checkout, booking, account signup), the flow includes a signed `TrustGrant` token minted by the *user's client*:

```json
{
  "grant_type": "transactional",
  "grantee": "receipts:acmeair",
  "scope": "thread-initiate",
  "max_threads": 5,
  "valid_until": "2027-07-21T00:00:00Z",
  "signature": "<user identity key>"
}
```

The web-integration API (`herald://grant` handler / JS SDK) makes "enter your HERALD address" simultaneously mint the grant. Revocation is one tap on any message from that grantee. Granting takes zero taps — it is the address entry itself.

**Introduction forwarding.** If A (trusted by C) adds B to a thread with C, or forwards B's contact card into a thread with C, B receives *provisional* trust with C scoped to that thread. Full Tier 1 trust forms silently after C replies to B.

**Context inheritance.** An organizational grant carries a CA-defined default trust set (e.g., `:mit` inherits trust for `registrar:mit`, `bursar:mit`, all `*:mit` faculty contexts). Joining the org is the consent.

### 6.3 Delivery Decision

```
ADMIT if Tier 1 ∨ Tier 2 ∨ Tier 3 ∨ valid Tier 4 grant
QUARANTINE if valid Connection Request (rate-limit passed)
REJECT otherwise → generic TRUST_DENIED, no existence oracle
```

### 6.4 No Cold Sending

Unchanged: no bulk-send primitive exists. Threads with >50 members require the creator to hold an organizational context, and every member addition is individually trust-checked.

### 6.5 Adaptive Connection-Request Limits (CHANGED in 1.1)

The flat 10/day limit is replaced by a reputation function requiring zero configuration:

```
daily_cap = base(level) × f(acceptance_rate, account_age, verification_level)
```

- Level 0: base 0 (cannot send requests).
- Level 1: base 5, scaling to 50 with sustained ≥60% acceptance.
- Level 2: base 10, scaling to 100.
- Sustained acceptance <10% decays the cap toward 1 and flags the GID for IRA review.

Legitimate networkers earn headroom automatically; purchased identities burn out on rejection.

### 6.6 Connection Request contents

Unchanged: mandatory 20–300 character introduction, recipient sees full GID, verification level, and mutual-contact count. Requests live in a quarantine surface, never the inbox.

---

## 7. APIs — Split Architecture (NEW in 1.1)

v1.0's single HRTP is split, following the Matrix client/federation separation that enabled its client ecosystem:

### 7.1 HERALD Client-Server API (HCS)

What client apps implement. HTTPS + WebSocket (JSON), covering: auth (§8), sliding sync (§8.4), event send, thread management, contact management, grants, attachments, device cross-signing, recovery. A client developer never touches federation, key distribution internals, or the registry.

Any number of clients may attach to one account simultaneously and interchangeably; the event-log model (§4) guarantees they converge.

### 7.2 HERALD Federation API (HFA)

What servers implement, server↔server. mTLS between registered servers, covering: event relay (`/hfa/v1/relay`), log backfill (`/hfa/v1/thread/{id}/log`), trust-chain assertions, key/certificate queries, bridge ingress (§14).

### 7.3 Conformance

A product may implement HCS only (a client), HFA+HCS (a full server), or the Bridge API (§14). Test suites are published per-API (§16).

---

## 8. Authentication, Sessions, and Sync

### 8.1 OIDC-based Auth (CHANGED in 1.1)

HERALD does not define bespoke credential handling. Client login is standard **OAuth 2.0 / OIDC** against the user's home server (which may itself federate to an org IdP — "sign in with Deloitte SSO"). The OIDC flow yields a session bound to a device key via DPoP-style proof-of-possession; the device key (not a password) is what signs events.

Consequences:
- Org users onboard with credentials they already have.
- Password reset, MFA, passkeys — all inherited from mature IdP stacks, not reinvented.
- eID / bank-KYC identity anchoring (§3.4) is just another OIDC assertion.

### 8.2 Session Establishment

```
Client → Server: OIDC auth code flow → access token (DPoP-bound to device key)
Client → Server: WebSocket upgrade with token
Server → Client: HELLO { server_pubkey, supported_versions }
```

### 8.3 Real-time Channel

Persistent WebSocket, TLS 1.3, push delivery of events, typing (`h.typing`, ephemeral), presence (ephemeral, user-controlled).

### 8.4 Sliding Sync (NEW in 1.1, mandatory)

Clients MUST NOT full-sync. The sync endpoint accepts a window specification:

```json
{
  "lists": [
    { "name": "inbox", "range": [0, 30], "sort": "recent_activity",
      "filters": { "unread_first": true } }
  ],
  "thread_subscriptions": { "!01J8X2M0AB": { "timeline_limit": 50 } }
}
```

The server returns only the visible window; scrolling extends the range; history backfills lazily. Login on a new device renders a usable inbox in one round trip regardless of account size. (Adopted from Matrix sliding sync / Element X.)

### 8.5 Delivery Guarantees and Offline Retention (CHANGED in 1.1)

- Events are acknowledged end-to-end; exactly-once presentation is guaranteed by `event_id` dedup.
- Offline queue retention is **recipient-configurable**, floor 30 days, default 180 days.
- Events past retention are **never silently dropped**: the recipient receives a signed non-delivery **manifest** (sender, thread, timestamp, count) on reconnect, and senders of expired events receive `DELIVERY_EXPIRED`.

---

## 9. Cryptography

| Purpose | Algorithm |
|---|---|
| Event & certificate signing | Ed25519 |
| Key agreement | X25519 (ECDH), ephemeral per session (PFS) |
| Content encryption | AES-256-GCM, fresh key per event batch |
| Key derivation | HKDF-SHA512 |
| Transport | TLS 1.3 (client-server), mTLS (federation) |
| Hashing | SHA-512 (certs, canonical events), SHA-256 (attachments) |
| Cross-signing | Ed25519 signature chains (§3.6) |
| Recovery shards | Shamir secret sharing over the recovery key (§3.7) |

End-to-end encryption: event content is encrypted client-side; per-recipient keys wrapped via X25519 against recipient device keys (fanned out through the cross-signing chain, so new devices decrypt future events without per-contact re-verification). Servers relay and store ciphertext plus unencrypted routing/trust metadata only (sender, thread, seq — required for trust evaluation).

Post-quantum note: the signature and KEM registries are versioned; ML-KEM/ML-DSA hybrid suites are targeted for a 1.x minor revision without wire-format breakage.

---

## 10. Anti-Spam and Anti-Phishing Guarantees

### 10.1 Spam — structural impossibility

- No anonymous sending: every event is device-signed and identity-chained.
- No bulk primitive; membership additions individually trust-checked.
- Delivery requires trust-chain admission; Level 0 identities cannot even request connections.
- Adaptive request caps make purchased-identity campaigns self-extinguishing (§6.5).
- One-identity enforcement at Level 2 blocks account farms from the roles that matter (context issuance, high-volume sending).

### 10.2 Phishing — structural impossibility

- Sender identity is signature-verified against the registry before render; display names never replace the verified address.
- `boss:deloitte` requires a currently-valid Deloitte CA grant — unforgeable, and revoked grants fail at acceptance time.
- No HTML: no fake login pages, overlays, or visual spoofing. Structured blocks render identically in every client.
- Links carry their resolved destination and verdict in the signed event; the client always surfaces the true destination.
- Attachments are content-hashed and sandbox-scanned before delivery; hashes are immutable in the log.

### 10.3 The legacy boundary

The only spam/phish ingress is the SMTP bridge (§14.2). Bridged content is structurally segregated: distinct surface, `h.bridge` marker, "unverified legacy sender" banner, links defanged by default. The protocol's guarantees apply to HERALD-native traffic; the bridge makes the boundary visible rather than pretending it away.

---

## 11. Server Architecture

### 11.1 Components

**Identity Registry (IR).** Federated ledger: `GID → identity_pubkey → level → anchor_type`. Level-2 records additionally bind the deduplication anchor hash. Read-optimized.

**Context Authority (CA).** Per-organization grant issuance/revocation service; operator must be Level 2. Publishes revocations to the federation in real time.

**HERALD Home Server (HHS).** Implements HCS + HFA: session termination, trust evaluation, thread log replication, sequencing for locally-created threads, offline queues. Horizontally scalable; thread logs shard naturally by `thread_id`.

**Attachment Store.** Ciphertext blob storage with content-addressed dedup, quarantine API, and per-org retention policy hooks.

**Key Distribution Server (KDS).** Resolves `GID → identity_pubkey + device tree`. Cache TTL 1 hour **plus push invalidation** (CHANGED in 1.1): key rotations and revocations are broadcast over the federation mesh; caches drop affected entries immediately, closing the v1.0 rotation/TTL race.

**Bridge Hosts.** See §14.

### 11.2 Federation

Peer-to-peer between registered HHS instances over mTLS. Server registration requires a Level-2 operator identity and IRA listing — federation is a permissioned mesh of accountable operators, not an open relay network.

### 11.3 Self-Hosting

Any organization can run an HHS. The reference implementation and conformance suite are open source (§16).

---

## 12. Client Requirements

A conformant HERALD client MUST:

- Verify event signatures before rendering; refuse unverifiable events.
- Display the verified address always; display names only in addition.
- Show context-grant validity badges, and revocation/recovery notices in-thread.
- Render only `text/herald` structured blocks; never HTML.
- Surface resolved link destinations and verdicts (§5).
- Hold keys in hardware-backed storage; implement cross-signing (§3.6) and default-on recovery escrow (§3.7).
- Implement sliding sync (§8.4); full-sync clients are non-conformant.
- Implement the `herald://grant` handler for transactional trust (§6.2).
- Render bridged (legacy) content in a visually distinct, banner-marked surface (§14.2).

---

## 13. Migration Path (REWRITTEN in 1.1)

**The user migrates by doing nothing.** A HERALD client is, from day one, a complete replacement for the user's email client:

**Day one — bidirectional SMTP bridge.** Every HERALD account gets a bridged legacy address (and can attach existing addresses via standard IMAP/SMTP OAuth linking). Inbound legacy mail arrives in the Legacy surface, converted to `h.bridge` events. Outbound mail to any SMTP address leaves via the bridge transparently — the user types an address; the client routes HERALD-native if the recipient resolves in the registry, SMTP otherwise, and shows which occurred.

**Continuous — silent upgrading.** When both parties of a legacy correspondence are found to hold HERALD identities, the clients propose (one tap, or automatic under an org policy) to continue the thread HERALD-native. The network upgrades relationship by relationship, invisibly.

**Eventually — org sunset.** Organizations that reach internal saturation set the bridge to inbound-only, then off, on their own schedule. No global flag day exists or is needed.

---

## 14. Bridge API (NEW in 1.1)

Bridges connect HERALD to foreign networks. The SMTP gateway is bridge #1, but the API is generic (per the Matrix bridging lesson: interoperability is an ecosystem, not a feature).

### 14.1 Model

A bridge is a registered federation participant that:
- Mints **shadow identities** in a reserved namespace: `smtp~alice.smith~gmail.com`, `slack~jdoe~acmecorp`. Shadow identities are Level B ("bridged"), can never send Connection Requests, and exist only within threads a real user initiated or accepted.
- Translates foreign content into `h.bridge`-wrapped events (content converted to structured blocks, active content stripped, links defanged-by-default).
- Enforces per-bridge rate and reputation policy; the recipient's trust rules for bridged senders (allow thread continuation only / quarantine all / block) are user- or org-configurable with safe defaults.

### 14.2 SMTP bridge specifics

- Inbound: DKIM/SPF/DMARC evaluated and recorded in the `h.bridge` metadata; failures escalate the warning banner.
- Outbound: HERALD structured blocks render to clean multipart text/HTML email; the bridge signs with the user's linked legacy domain where authorized.
- Threading: `Message-ID`/`References` mapped to HERALD threads bidirectionally.

---

## 15. Real-Time Features

| Feature | Mechanism |
|---|---|
| Delivery receipt | Server ack chain on event acceptance |
| Read state | `h.read` events, per-user, opt-out |
| Typing | Ephemeral `h.typing`, 5s expiry, thread-scoped |
| Presence | Ephemeral, user-controlled, off by default outside org contexts |
| Reactions | `h.react` events |
| Edits/deletes | `h.edit` / `h.redact` with retained tombstones |
| Voice/video signaling | Reserved event namespace `h.rtc.*` (future HIP; SDP/ICE over thread events) |

---

## 16. Governance (NEW in 1.1)

- **HERALD Foundation**: neutral steward of the spec, the GID root registry policy, IRA accreditation, and trademark. Modeled on the Matrix.org Foundation / IETF hybrid.
- **HIP process** (HERALD Improvement Proposals): public proposals, working-group review, reference implementation required before spec merge, versioned spec releases. Every HIP must include a **zero-interaction analysis** (Principle 2.7) and a threat-model delta.
- **Conformance suites** published per API (HCS, HFA, Bridge); the "HERALD" mark requires passing conformance.
- **GID disputes** (trademarks, impersonation of famous names, deceased persons, legal name changes): handled under a UDRP-like Foundation policy — deliberately out of protocol scope.

---

## 17. Open Questions

- Sequencing-server handover liveness: automatic election among participant servers vs. explicit `h.thread.meta` handover only.
- Anonymous-but-human messaging: `HERALD-ANON` companion protocol via zero-knowledge proof of Level-2 status without identity disclosure.
- Group primitives beyond threads: named org-wide lists (`engineering:deloitte` as an addressable set) — likely a CA-managed alias expanding to membership at send time.
- Offline-first clients on intermittent links: whether the linear-log model needs CRDT augmentation for drafts and read state (content events remain server-sequenced).
- Post-quantum suite activation timeline.

---

## Appendix A — Error Codes

| Code | Meaning |
|---|---|
| `TRUST_DENIED` | Sender not admitted by any trust tier |
| `IDENTITY_INVALID` | Identity certificate expired/revoked |
| `CONTEXT_REVOKED` | Context grant revoked (post-grace) |
| `CONTEXT_MOVED` | Grace-period redirect hint (§3.9) |
| `SIGNATURE_INVALID` | Event signature verification failed |
| `SEQ_CONFLICT` | Event log divergence detected; refetch canonical log |
| `RATE_LIMITED` | Adaptive request cap exceeded |
| `LINK_MALICIOUS` | Link matched threat registry (neutralized, not bounced) |
| `ATTACHMENT_REJECTED` | Sandbox analysis flagged attachment |
| `DELIVERY_EXPIRED` | Recipient retention window elapsed (§8.5) |
| `GID_NOT_FOUND` | Recipient GID not in registry |
| `LEVEL_INSUFFICIENT` | Operation requires higher verification level |

## Appendix B — Version Negotiation

Announced in the WebSocket `HELLO`; server selects highest mutual version. Wire compatibility: 1.1 servers accept 1.0 envelopes during a deprecation window, translating them into single-message threads.

---

*HERALD Protocol — Draft v1.1. Living document; all wire formats subject to HIP revision.*
