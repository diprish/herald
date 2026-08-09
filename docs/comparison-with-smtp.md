# HERALD vs. SMTP and the Legacy Email Stack

This document explains how HERALD differs from — and aims to improve upon —
SMTP and the protocols layered around it (IMAP/POP, SPF/DKIM/DMARC, PGP/S-MIME).
Section references (§) point to [`spec/HERALD_Protocol_Specification_v1.1.md`](../spec/HERALD_Protocol_Specification_v1.1.md).

---

## The core structural difference

SMTP was designed for a small set of trusted, cooperative hosts with **no notion
of identity**. Every anti-abuse mechanism since — SPF, DKIM, DMARC, spam filters,
greylisting, reputation blocklists — is a bolt-on *around* a protocol that still,
at its core, lets any host open a connection and assert any `From:` address.
Filtering is therefore probabilistic and adversarial forever.

HERALD removes the primitive that causes the problem: **there is no
unauthenticated or untrusted delivery path in the protocol itself** (§10). Not
"filtered better" — structurally absent. Every comparison below follows from that
one decision.

---

## Feature-by-feature comparison

| Dimension | SMTP + legacy stack | HERALD |
|---|---|---|
| **Sender identity** | Unauthenticated by default; `From:` is free text. SPF/DKIM/DMARC authenticate *domains*, added later, unevenly adopted. | Every event is Ed25519-signed and chained to a registry identity (§4, §9). Spoofing is mathematically impossible. |
| **Spam control** | Probabilistic filtering; permanent arms race. | Structural: no bulk primitive, delivery gated by trust chain, adaptive request caps make purchased identities self-extinguish (§6, §10.1). |
| **Phishing control** | HTML rendering enables fake login pages, overlays, lookalike links; display-name spoofing rampant. | No HTML — structured blocks only (§5). Verified address always shown; links carry resolved destination + verdict (§10.2). |
| **Transport** | Store-and-forward envelopes between relays. | Real-time replicated append-only event logs over persistent WebSockets (§4, §8.3). |
| **Encryption** | E2EE only via PGP/S-MIME bolt-ons; famously unusable, rarely deployed. | E2EE by default: X25519 + AES-256-GCM, per-event keys, PFS, cross-signed devices (§9). |
| **Mailbox sync** | IMAP/POP; full-folder sync, slow on large mailboxes. | Mandatory sliding sync — usable inbox in one round trip regardless of size (§8.4). |
| **Group / threading** | Heuristic threading on `References`; no native group object. | A thread with N members *is* the same object as a 2-party thread; membership individually trust-checked (§4.3, §6.4). |
| **Read state, edits, reactions** | Non-standard bolt-ons or absent. | Ordinary signed events: `h.read`, `h.edit`, `h.react` (§4.1, §15). |
| **User effort for security** | High — the reason PGP/S-MIME failed. | Bound to a zero-interaction principle: security must cost the user nothing extra (§2.7). |

---

## Where HERALD beats SMTP specifically

### 1. Spam is eliminated by construction, not filtering (§10.1)

- No anonymous sending — every event is device-signed and identity-chained.
- No bulk-send primitive; every thread member is individually trust-checked (§6.4).
- Delivery requires trust-chain admission (mutual contact, shared org context,
  accepted request, or implicit grant). *Cold sending does not exist.*
- Adaptive connection-request caps decay toward 1 when acceptance stays low,
  so purchased-identity campaigns self-extinguish (§6.5).

SMTP can never do this: its delivery decision has no identity input to gate on.

### 2. Phishing becomes visually impossible (§10.2)

- **No HTML rendering** (§5) removes email's single largest phishing surface.
  Structured blocks (paragraphs, tables, code, images-by-reference) render
  identically everywhere — no fake login pages, CSS overlays, or lookalike buttons.
- Sender identity is signature-verified against the registry *before* render;
  display names never replace the verified address.
- `boss:deloitte` requires a currently-valid Deloitte-issued grant; a revoked
  grant fails at acceptance time. Organizational affiliation is unforgeable.
- Every link carries its *resolved* destination and a verdict in the signed
  event, so the true target is always surfaced (§5).

DMARC only asserts a domain was authorized — it does nothing about lookalike
domains, display-name spoofs, or HTML deception. HERALD attacks all three at the
protocol layer.

### 3. Real-time transport replaces store-and-forward (§4, §8.3)

Threads are replicated, signed, append-only event logs over persistent
WebSockets, so group messaging, multi-device sync, edits, reactions, read state,
and typing indicators fall out as ordinary events instead of the incompatible
bolt-ons email accretes.

### 4. End-to-end encryption that people actually use (§9)

X25519 + AES-256-GCM with per-event keys and perfect forward secrecy is wired
into the base protocol, and cross-signing (§3.6) lets a new device decrypt future
events with one QR scan and no per-contact re-verification.

---

## Where HERALD beats the rest of the stack

- **vs. IMAP/POP:** replaced by mandatory sliding sync (§8.4) — a new device
  renders a usable inbox in one round trip regardless of mailbox size.
- **vs. SPF/DKIM/DMARC:** those authenticate *domains* post-hoc; HERALD
  authenticates *people and their organizational contexts* cryptographically,
  and uses it to gate inbound delivery, not merely to classify after the fact.
- **vs. Matrix** (which HERALD borrows from): HERALD deliberately simplifies the
  hard part. Because membership is closed and trust-verified, it uses a single
  sequencing server per thread with a linear log (§4.2) instead of full Byzantine
  state resolution — "there is no merge algorithm to get wrong." It trades a
  little availability for a large drop in complexity, appropriate for
  correspondence rather than 50,000-person public rooms.

---

## The decisive design move: zero-interaction security (§2.7)

Every prior secure-email attempt (PGP, S/MIME) died because security cost the
user effort. HERALD makes *no added effort* a binding constraint: any mechanism
requiring a user decision must have a path where that decision is inferred from
something the user already did.

- Level 0 → Level 1 verification usually happens by *receiving a job or school
  context* — the employer already ID-checked the person during onboarding (§3.4).
- Trust grants are minted by *entering your address* at checkout — granting takes
  zero taps (§6.2).
- Key recovery reuses existing org SSO; no seed phrases or printed codes (§3.7).

This is the honest answer to "why won't this fail like PGP did."

---

## Honest caveats

A fair comparison has to name the two hard problems the spec itself confronts:

1. **Migration / network effect.** A protocol with no users is worse than SMTP
   for everyone. HERALD's answer is the day-one bidirectional SMTP bridge
   (§13, §14): users migrate "by doing nothing," relationships upgrade to native
   silently when both sides have HERALD, and organizations sunset the bridge on
   their own schedule. But §10.3 is candid that *the bridge is the one spam/phish
   ingress* — during the long coexistence era, HERALD is only as clean as the
   legacy mail it still gateways. The guarantees are absolute only for
   native-to-native traffic.

2. **Identity / centralization trade-off.** "One person, one identity" with
   real-world anchoring (eID, KYC, biometric Level 2) is exactly what makes spam
   structurally impossible — and exactly what raises privacy, censorship, and
   pseudonymity concerns that SMTP's messiness sidesteps. The spec answers with a
   permissioned federation mesh (§11.2), a governance foundation (§16), and an
   open question about an anonymous-but-human companion protocol (§17). It is a
   real philosophical cost, not a bug to be patched.

---

## Bottom line

HERALD is "better than SMTP" in a specific, defensible sense: it makes spam and
phishing **structural impossibilities** rather than an eternal filtering arms
race, delivers modern messaging (real-time, encrypted, multi-device, group) as
base primitives, and — its sharpest move — refuses to charge the user any effort
for that security. Its two open risks are the classic ones for any SMTP
replacement: bootstrapping adoption, and the centralization inherent in tying
delivery to verified human identity. The spec confronts both explicitly rather
than hand-waving them away.
