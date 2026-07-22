# HERALD Protocol Specification
## Human Entity Realtime Authenticated Link Delivery
### Version 1.0 — Draft

---

## 1. Abstract

HERALD is a next-generation messaging protocol designed to replace SMTP-based email. It is built on three foundational principles: **one physical identity per person**, **trust-chain-gated delivery**, and **real-time encrypted transport**. HERALD eliminates spam and phishing by design — not by filtering — because the protocol itself makes unauthenticated and untrusted delivery structurally impossible.

---

## 2. Design Principles

1. **One person, one identity.** A human being registers a single global identifier, anchored to a real-world identity via government-issued ID or biometric verification. No pseudonymous accounts, no throwaway addresses.

2. **Contexts, not inboxes.** A person's identifier can be extended with organizational namespaces (`:home`, `:deloitte`, `:mit`) that represent different life contexts. These are managed by the identity holder and by verified organizations.

3. **Trust before delivery.** A message can only be delivered if the sender is within the recipient's trust chain. Cold messages are impossible by default.

4. **Cryptographic authenticity.** Every message is signed by the sender's private key. Spoofing is mathematically impossible.

5. **Real-time as first-class.** The protocol is built on persistent WebSocket connections, not a store-and-forward model. Messages are delivered in milliseconds, not minutes.

6. **No HTML rendering.** Messages are structured data. Phishing through formatted hyperlinks, CSS tricks, and embedded images is not possible.

---

## 3. Identity System

### 3.1 Global Identifier (GID)

A Global Identifier (GID) is a lowercase alphanumeric string, 3–32 characters, registered once per physical person.

```
GID = [a-z0-9][a-z0-9_-]{2,31}
```

**Examples:** `diprish`, `alice`, `bob99`

A GID is:
- Globally unique
- Permanent (cannot be re-assigned after deletion)
- Cryptographically bound to the holder's biometric or government-issued ID at registration time

### 3.2 Context Address (CA)

A Context Address extends the GID with a colon-delimited namespace representing a life context.

```
ContextAddress = GID ":" ContextName
ContextName    = [a-z0-9][a-z0-9_-]{1,31}
```

**Examples:**
```
diprish:home       → personal context (self-managed)
diprish:deloitte   → work context (Deloitte-verified)
diprish:mit        → school context (MIT-verified)
diprish:personal   → second personal context
```

A bare GID (`diprish`) is equivalent to `diprish:default` and always refers to the person's primary, ungrouped inbox.

### 3.3 Full HERALD Address

```
HERALDAddress = ( GID | ContextAddress ) [ "@" Domain ]
```

The `@Domain` suffix is optional and used only for federation with external HERALD servers. Within a single HERALD network, the GID alone is globally unique.

**Examples:**
```
diprish
diprish:deloitte
diprish:home@herald.example.org
```

---

## 4. Registration and Identity Verification

### 4.1 Identity Registration Authority (IRA)

The IRA is a distributed, federated registry of GIDs. It is analogous to a PKI Certificate Authority but for human identities. A global consortium of IRAs maintains consensus on GID ownership through a distributed ledger.

### 4.2 Registration Process

1. User submits a requested GID and identity proof (government-issued ID scan or biometric hash) to a registered IRA node.
2. The IRA verifies that the identity proof has not been previously used to register a GID (preventing duplicate identities).
3. A key pair is generated client-side (private key never leaves the device).
4. The public key and GID are published to the distributed registry.
5. The IRA issues a signed Identity Certificate binding `GID → PublicKey → BiometricHash`.

### 4.3 Key Rotation

A user may rotate their keypair at any time by presenting a new public key signed with the current private key, plus a fresh identity proof.

### 4.4 Context Registration

**Personal contexts** (e.g., `:home`, `:personal`) are created freely by the GID holder with no external verification.

**Organizational contexts** (e.g., `:deloitte`, `:mit`) require:
1. The organization registers as a verified Context Authority (CA) with the IRA.
2. The organization provisions a user by cryptographically signing a context grant: `diprish:deloitte` is valid because Deloitte's CA certificate has countersigned it.
3. When the relationship ends (e.g., employee leaves), the organization revokes the context grant. The context becomes invalid for new message delivery immediately.

---

## 5. Trust Chain

### 5.1 Trust Tiers

Every delivery attempt is evaluated against the recipient's trust chain. There are three ways a message is admitted:

**Tier 1 — Mutual Contact**
The sender's GID appears in the recipient's verified contact list, or vice versa. This is the primary trust relationship.

**Tier 2 — Shared Organizational Context**
Both sender and recipient hold a valid context grant from the same organization. For example, `alice:deloitte` and `diprish:deloitte` can message each other because both hold a valid Deloitte CA-signed context grant.

**Tier 3 — Accepted Connection Request**
The sender has previously sent a Connection Request, and the recipient explicitly accepted it. Connection Requests are rate-limited (10 per day per GID) and carry a mandatory brief introduction (max 300 characters). Connection Requests themselves are delivered to a quarantine queue, separate from the main inbox.

### 5.2 Delivery Decision

```
DELIVER if:
  sender.GID ∈ recipient.contacts
  OR sender.context.orgCA == recipient.context.orgCA
  OR recipient.accepted(sender.connectionRequest)

REJECT otherwise
```

Rejected messages are silently dropped. The sender receives a generic `TRUST_DENIED` response with no information about whether the address exists.

### 5.3 No Cold Sending

There is no mechanism in HERALD to send a message to an arbitrary address without going through the trust chain. The protocol does not have a "bulk send" primitive. Sending to more than 50 recipients in a single message requires organizational context verification.

---

## 6. Message Format — HERALD Message Format (HMF)

### 6.1 Envelope

```json
{
  "hmf_version": "1.0",
  "message_id": "01J8X3KQ9E-5A2F-4B1C-9D3E-7F2A1B4C8D5E",
  "created_at": "2025-11-14T09:32:00.000Z",
  "from": "diprish:deloitte",
  "to": ["boss:deloitte", "colleague:deloitte"],
  "cc": [],
  "thread_id": "01J8X2M0AB-3C1D-4E2F-8A9B-2C5D7E1F3A4B",
  "reply_to": null,
  "subject": "Q3 Financial Report Review",
  "signature": "<Ed25519 signature of canonical body hash>",
  "sender_cert": "<IRA-issued identity certificate>",
  "context_cert": "<Deloitte CA context grant for diprish:deloitte>",
  "body": { ... },
  "attachments": [ ... ]
}
```

### 6.2 Body

```json
{
  "content_type": "text/herald",
  "encoding": "utf-8",
  "text": "Hi, please find the Q3 numbers attached.",
  "mentions": ["boss:deloitte"],
  "links": [
    {
      "display": "Q3 Report",
      "resolved_url": "https://drive.deloitte.com/files/q3-2025.pdf",
      "safe": true,
      "verified_at": "2025-11-14T09:31:58Z"
    }
  ]
}
```

`text/herald` is plain text with a minimal markdown-like subset (bold, italic, inline code, block code). No HTML. No CSS. No `<img>` tags.

All links are pre-resolved server-side at send time. The final resolved URL must be a direct link — no URL shorteners, no redirect chains. If resolution fails or reveals a redirect chain longer than 1 hop, the link is rejected.

### 6.3 Attachments

```json
{
  "attachment_id": "att-01",
  "filename": "q3-report.pdf",
  "content_type": "application/pdf",
  "size_bytes": 204800,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "storage_ref": "herald://store/01J8X3KQ9E/att-01",
  "encrypted_key": "<recipient's-public-key-encrypted AES-256-GCM key>"
}
```

Attachments are stored encrypted. The AES-256-GCM key is encrypted per-recipient using the recipient's public key (hybrid encryption). The server cannot read attachment content.

---

## 7. Transport Protocol — HERALD Realtime Transport Protocol (HRTP)

### 7.1 Transport Layer

HRTP runs over WebSocket with mandatory TLS 1.3. Connections are persistent. Clients maintain a long-lived connection to their HERALD server and receive push-delivered messages with no polling.

**Default port:** 8765 (TLS)

### 7.2 Handshake

```
Client → Server:  TLS ClientHello
Server → Client:  TLS ServerHello + Server Certificate
Client → Server:  HERALD_AUTH { gid, timestamp, signature }
Server → Client:  HERALD_AUTH_OK { session_token, server_pubkey }
```

The `HERALD_AUTH` packet is signed with the client's private key. The server verifies the signature against the IRA-registered public key for the GID.

### 7.3 Message Flow

```
Sender Client → Sender Server:  HERALD_SEND { envelope }
Sender Server:  validates signature, resolves links, checks attachment safety
Sender Server → IRA:            lookup recipient's server and public key
Sender Server → Recipient Server: HERALD_RELAY { envelope }
Recipient Server: evaluates trust chain
Recipient Server → Recipient Client: HERALD_DELIVER { envelope }
Recipient Client → Sender Client:   HERALD_READ { message_id, timestamp } (when opened)
```

### 7.4 Delivery Guarantees

- Messages are delivered **at most once** with acknowledgment.
- If the recipient is offline, messages are queued server-side (encrypted at rest) for up to 30 days.
- After 30 days, the message is deleted. The sender is notified of non-delivery.

### 7.5 Real-Time Features

| Feature | Behaviour |
|---|---|
| Delivery receipt | `HERALD_DELIVERED` sent when message reaches recipient's server |
| Read receipt | `HERALD_READ` sent when recipient's client opens the message (opt-out per user) |
| Typing indicator | `HERALD_TYPING` sent in thread context, expires after 5 seconds |
| Presence | `HERALD_PRESENCE { status: online/busy/away/offline }`, user-controlled |
| Reactions | `HERALD_REACT { message_id, emoji_codepoint }` |

---

## 8. Cryptography

| Purpose | Algorithm |
|---|---|
| Signing (message signatures) | Ed25519 |
| Key agreement | X25519 (ECDH) |
| Message encryption | AES-256-GCM |
| Key derivation | HKDF-SHA512 |
| Transport | TLS 1.3 (ChaCha20-Poly1305 preferred) |
| Identity certificate hashing | SHA-512 |
| Perfect forward secrecy | X25519 ephemeral keys per session |

### 8.1 End-to-End Encryption

Messages are encrypted with a fresh AES-256-GCM key per message. The key is then encrypted once per recipient using X25519 key agreement between the sender's ephemeral key and the recipient's registered long-term public key. The server never holds plaintext message bodies.

### 8.2 Message Signing

Before sending, the client computes:
```
canonical_body = canonicalize(envelope_without_signature)
signature = Ed25519Sign(sender.private_key, SHA512(canonical_body))
```

The receiving client verifies:
```
Ed25519Verify(sender.public_key_from_IRA, SHA512(canonical_body), envelope.signature)
```

A message with an invalid signature is rejected and not displayed.

---

## 9. Anti-Spam and Anti-Phishing Guarantees

### 9.1 Why spam is impossible by design

- There is no anonymous sending. Every sender is cryptographically identified.
- There is no bulk-send mechanism for unknown recipients.
- Delivery requires trust chain membership. Unknown senders cannot reach inboxes.
- Rate limiting on Connection Requests (10/day) makes mass outreach economically unviable.
- One identity per person prevents throwaway account farms.

### 9.2 Why phishing is impossible by design

- Every message's sender identity is verified by a cryptographic signature against the IRA registry. Display names cannot be spoofed.
- Organizational contexts are CA-signed. `boss:deloitte` can only be sent by a person whose `:deloitte` context grant is currently valid and signed by Deloitte's registered CA. A criminal cannot impersonate this.
- No HTML rendering means no fake login pages, no invisible iframe overlays, no CSS-based visual deception.
- All links are pre-resolved and verified at send time. The client displays the final destination URL, not the display text of the link.
- Attachments are content-hashed. The server performs sandbox analysis on all attachments before delivery. The hash is immutable once delivered.

### 9.3 Connection Request Abuse Mitigation

Connection Requests (Tier 3 trust) are rate-limited but represent the only path for unknown senders. Mitigations:

- Hard limit of 10 Connection Requests per day per GID.
- Mandatory introduction text (20–300 characters). Blank connection requests are rejected.
- Recipients see sender's full GID, identity verification status, and mutual contacts count.
- IRA monitors GIDs that generate high rejection rates. Persistent abuse triggers identity review.

---

## 10. Server Architecture

### 10.1 Components

**Identity Registry (IR):** Distributed ledger of `GID → PublicKey → BiometricAnchor`. Federated across multiple IRA operators. No single point of failure or control. Read-heavy; optimized for public key lookup by GID.

**Context Authority (CA):** Per-organization service that issues and revokes context grants (e.g., Deloitte's CA for all `:deloitte` grants). Context grants are cryptographically signed and carry an expiry timestamp.

**HERALD Message Server (HMS):** Receives messages from authenticated clients, validates signatures and trust chains, relays to recipient's HMS, queues for offline delivery. Stateless between sessions. Horizontally scalable.

**Attachment Store:** Encrypted blob storage. Keys are held only by sender/recipients. Server stores only ciphertext.

**Key Distribution Server (KDS):** Public endpoint for resolving `GID → PublicKey`. Backed by the Identity Registry. Cached aggressively (TTL 1 hour, invalidated on key rotation).

### 10.2 Federation

HERALD servers federate peer-to-peer. A message from `diprish:deloitte` on `herald.deloitte.com` to `ceo:acme` on `herald.acme.com` is routed:

```
1. diprish's HMS queries KDS for ceo:acme's server
2. diprish's HMS opens a TLS connection to herald.acme.com
3. herald.acme.com verifies the relaying server's certificate
4. Message is delivered if trust chain is satisfied
```

### 10.3 Self-Hosting

Any organization can run their own HMS. HERALD is an open protocol. Self-hosted servers must register with the IRA network to participate in identity lookup.

---

## 11. Client Requirements

A conformant HERALD client MUST:

- Verify the sender's `Ed25519` signature before rendering any message content.
- Display the full verified GID and context as the sender identity. Custom display names are shown only in addition to, never instead of, the GID.
- Display the context grant badge for organizational contexts (indicating whether the grant is currently valid).
- Not render HTML. Body content is rendered as `text/herald` (plain text + limited markdown).
- Resolve and display the final destination URL for all links before the user clicks them.
- Store the private key in the device's secure enclave or equivalent hardware-backed storage. Never transmit the private key.
- Warn the user if a message's sender certificate or context grant has expired or been revoked.

---

## 12. Migration Path

### Phase 1 — HERALD Standalone (Year 1)
Deploy HERALD as a new messaging system. No SMTP compatibility. Early adopters onboard through IRA-registered clients. Focus on organizational deployments.

### Phase 2 — SMTP Gateway (Year 2)
Deploy an optional SMTP-to-HERALD gateway for legacy compatibility. Inbound SMTP is accepted, wrapped in a `[LEGACY]` sender badge that makes clear the message did not pass full HERALD identity verification, and delivered to a separate "legacy" folder.

### Phase 3 — Universal (Year 3+)
Legacy email is sunset for organizations that have fully migrated. SMTP gateway becomes read-only (inbound only). No outbound SMTP from HERALD clients.

---

## 13. Open Questions and Future Work

- **GID namespace governance:** Who arbitrates disputes over desirable short GIDs? An ICANN-like body is needed.
- **Legal name changes:** Protocol for updating the biometric anchor when a person legally changes their identity.
- **Anonymous communication:** HERALD does not support anonymous messaging. A companion protocol (`HERALD-ANON`) using zero-knowledge proofs for "verified human, identity withheld" use cases is under design.
- **Group messaging:** Formal group address primitives (e.g., `engineering:deloitte` as a group, not a person) need specification.
- **Offline-first clients:** CRDT-based message state sync for clients with intermittent connectivity.
- **Voice and video signaling:** HERALD as a signaling layer for encrypted calls, replacing SIP.

---

## Appendix A — Protocol Version Negotiation

Client announces supported versions in the `HERALD_AUTH` handshake. Server selects the highest mutually supported version.

```json
{ "gid": "diprish", "supported_versions": ["1.0"], "timestamp": "...", "signature": "..." }
```

## Appendix B — Error Codes

| Code | Meaning |
|---|---|
| `TRUST_DENIED` | Sender not in recipient's trust chain |
| `IDENTITY_INVALID` | Sender's IRA certificate is expired or revoked |
| `CONTEXT_REVOKED` | Sender's context grant has been revoked by the issuing CA |
| `SIGNATURE_INVALID` | Message body hash does not match signature |
| `RATE_LIMITED` | Connection Request quota exceeded |
| `LINK_UNSAFE` | Pre-resolution detected an unsafe or redirect chain link |
| `ATTACHMENT_REJECTED` | Sandbox analysis flagged the attachment |
| `GID_NOT_FOUND` | Recipient GID does not exist in the IRA |

---

*HERALD Protocol — Draft v1.0. This is a living document. All section numbers, wire formats, and algorithm choices are subject to revision.*
