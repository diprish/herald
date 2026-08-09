# HIP Draft — Cold Contact: Manufactured Trust Without Broken Pillars

**Status:** Pre-HIP draft (for discussion; not yet submitted to the HIP process, §16)
**Requires:** HERALD Protocol Specification v1.1
**Related:** [HIP Draft — Offers](HIP-draft-offers.md) (shares the surface-routing pattern)
**Section references (§)** point to [`spec/HERALD_Protocol_Specification_v1.1.md`](../../spec/HERALD_Protocol_Specification_v1.1.md).

---

## 1. Problem

HERALD v1.1 makes cold sending structurally impossible (§6.4). That is the
protocol's central anti-spam guarantee — and it also excludes a class of
legitimate, socially valuable contact:

- A recruiter reaching a candidate; a journalist reaching a source.
- A stranger returning a lost wallet.
- A customer contacting a business's sales address; a reader contacting an
  author.
- Professional networking between people with no mutual contact or shared
  organizational context.

Tier 3 Connection Requests (§6.1, §6.6) permit cold *contact* but not cold
*delivery*: a 20–300 character introduction in a quarantine surface, gated by
adaptive caps. This draft asks whether fuller cold messaging can be enabled
without compromising any founding pillar.

## 2. Reframing the pillar

The pillar is not "pre-existing trust before delivery." It is:

> **Delivery is always gated by an accountable trust decision, and nothing
> reaches the inbox without one.**

Cold messaging becomes safe when trust can be **manufactured at send time** —
through recipient-published consent, earned reputation, economic stake, or a
third party's vouch — rather than bypassed. The trust chain gains admission
evidence types; it gains no holes. The inbox invariant survives untouched:
under every mechanism below, cold traffic routes to dedicated surfaces
(the §6.6 quarantine / §14.2 Legacy / Offers-draft pattern), never the inbox.

## 3. Mechanism 1 — Open Contexts (primary; consent by publication)

A context holder MAY mark a context **open-inbound**:

```json
{
  "context": "diprish:openforwork",
  "open_inbound": true,
  "intent": "freelance-inquiries",
  "policy": {
    "min_sender_level": 1,
    "max_blocks": 10,
    "attachments": false,
    "daily_inbound_cap": 20
  }
}
```

Semantics:

- **Publishing the address is the consent.** Handing out or listing
  `diprish:openforwork` is the action from which the admission decision is
  inferred — no approval screen exists anywhere in the flow (Principle 2.7).
- Cold messages to an open context are admitted as ordinary signed threads but
  route to a **per-context surface**, never the main inbox.
- The `intent` field is machine-readable; clients display it to senders before
  composing, and policy violations are rejected at the sender's server with a
  specific error (`OPEN_POLICY_VIOLATION`) — the sender is told *why*, since
  the context's openness is already public.
- The `daily_inbound_cap` is recipient protection with a safe default: excess
  cold messages queue and trickle in under the cap rather than flooding.
- Closing the context (or unsetting `open_inbound`) ends exposure immediately.
  No grace redirect applies — there is no pre-existing relationship to
  preserve; subsequent sends fail with generic `TRUST_DENIED`.
- Replying to a cold message forms Tier 1 trust with that sender, scoped
  thread-wide, exactly like the introduction-forwarding rule (§6.2).

Open contexts subsume the "business address" case: `sales:acme`,
`support:acme`, `press:acme` are open contexts on org-context holders.

## 4. Mechanism 2 — Reputation-Gated Cold Sends (accountability layer)

The one-person-one-identity pillar is not threatened by cold messaging — it is
the **asset that makes it possible**. A Level 2 identity is biometrically
deduplicated (§3.4) and therefore genuinely scarce; its reputation is
collateral.

Extend the §6.5 adaptive-cap model from Connection Requests to sends into open
contexts (and, if the Foundation later chooses, to a small general cold-send
allowance):

```
cold_cap(sender) = base(level) × f(reply_rate, complaint_rate, account_age)
```

- Level 0: cap 0 (cannot cold-send, unchanged from v1.1).
- Level 1: small base (e.g. 3/day), growing with sustained reply rate.
- Level 2: larger base, larger ceiling.
- Complaints (one-tap "unwanted") collapse the cap toward 0 and flag the GID
  for IRA review — and a burned Level 2 identity **cannot be replaced**,
  because the person already has one. Campaign economics that §6.5 makes
  expensive, deduplication makes impossible at scale.
- Cold-context surfaces display the sender's verification level, historical
  reply rate band, and mutual-contact count (the §6.6 disclosure pattern).

## 5. Mechanism 3 — Attention Bonds (future extension; economic backstop)

For senders who are both unknown and unvouched, a refundable stake:

- Sender escrows a small bond at send time; it is refunded on reply or after
  quiet expiry, and forfeited — to the recipient or a Foundation abuse fund —
  on a one-tap "unwanted" mark.
- The recipient does nothing by default; the single optional tap is punitive
  and compensated. Bulk spam becomes a self-funding bounty against itself.
- **Deferred:** this requires an escrow/payments primitive HERALD does not
  define. Flagged for a separate HIP; the admission-evidence framing in §2
  is designed so a `bond` evidence type slots in without rework.

## 6. Mechanism 4 — Vouched Introductions (generalizing §6.2)

Introduction forwarding (§6.2) already lets A introduce B into a thread with C.
Generalize it into a standalone **voucher grant**: a mutual contact or an org
CA signs a voucher for a specific cold message or sender–recipient pair,
without joining the thread.

- The voucher stakes a slice of the voucher's own cold/request cap: if the
  vouched message is marked unwanted, the *voucher's* cap decays too.
- Covers the friend-of-a-friend case that constitutes most legitimate cold
  outreach, at near-zero spec cost (one new grant type).

## 7. Surface and client requirements

A conformant client (§12 additions):

- MUST route open-context and any future cold-path traffic to surfaces
  distinct from the inbox, labeled with the context and the sender disclosure
  of §4.
- MUST provide the one-tap "unwanted" action, which simultaneously: blocks the
  sender for this recipient, feeds the sender's complaint rate, and (when
  bonds exist) claims the forfeit.
- MUST NOT emit `h.read` events from cold surfaces by default.
- SHOULD offer one-tap promotion of a cold thread to the inbox (which is also
  the Tier 1 trust formation of §3).

## 8. Zero-interaction analysis (required by §16)

| Decision | Zero-interaction path |
|---|---|
| Accept cold contact at all | Inferred from publishing an open context — an action taken for its own sake (getting inquiries). Users who never publish one never receive cold messages; the default is closed. |
| Filter who may cold-send | Automatic: sender-level floors and adaptive caps; no recipient configuration. Policy defaults are safe out of the box. |
| Stop cold contact | Close the context — one action ends everything; no per-sender cleanup. |
| Trust a cold sender permanently | Inferred from replying (existing §6.2 rule). |
| Punish abuse | Optional single tap, never required; caps decay from complaint *rates* so no individual recipient must act. |
| Vouch for someone | Inferred from the existing act of forwarding a contact card / adding to a thread; the standalone voucher is an explicit but sender-side action. |

Explicit-approval fallbacks used: none on the recipient side. All recipient
interactions are optional.

## 9. Threat-model delta (required by §16)

- **Spam to open contexts.** Bounded by four independent limits: sender-level
  floor, adaptive per-sender caps with unreplaceable-identity collateral (§4),
  recipient-side `daily_inbound_cap` trickling, and surface isolation. The
  worst case is a capped trickle into a surface the user opened on purpose —
  not an inbox flood.
- **Existence oracle.** Open-context *discovery* must reveal only contexts
  explicitly published or directory-listed by their holders. Probing a
  non-open context or nonexistent GID returns the same generic `TRUST_DENIED`
  as §6.3 — `OPEN_POLICY_VIOLATION` is returned only for contexts that are
  already publicly open. Rate limits on lookups apply.
- **Reputation laundering.** A sender could farm reply rate with collusive
  recipients, then burst-spam. Mitigations: cap growth is slow and rate-based,
  complaint collapse is fast and asymmetric, and Level 2 deduplication caps
  the number of identities a real operation can burn.
- **Voucher abuse.** Vouchers stake the voucher's own cap; a compromised or
  colluding voucher decays with their vouchees. CA vouchers are additionally
  bounded by the CA operator's Level 2 accountability (§3.9).
- **Coercion / harassment via open contexts.** A harasser burns identity-level
  collateral per attempt, is blocked on first tap, and cannot follow the user
  across contexts (the block is GID-wide). Closing the context is a unilateral
  kill switch. Residual risk is materially lower than email, where blocking is
  advisory.
- **Recipient-side social pressure.** Because bonds compensate the "unwanted"
  tap, recipients might over-mark to farm forfeits. Mitigation when bonds
  arrive: forfeits from senders with high global reply rates route to the
  Foundation fund rather than the recipient, removing the incentive to farm
  legitimate senders.

## 10. Compatibility

- Fully additive: a new context attribute (`open_inbound` + policy), one new
  sender-side error code (`OPEN_POLICY_VIOLATION`), an extension of the §6.5
  cap function's domain, and one new grant type (voucher). No changes to
  existing trust tiers, event formats, or wire formats.
- Servers unaware of open contexts simply never admit cold traffic — behavior
  degrades to v1.1 exactly.
- Interacts cleanly with the Offers draft: an `offers` grant and an open
  context are orthogonal admission evidence; a merchant cold-pitching an open
  `vendor-inquiries:acme` context still cannot reach anyone's inbox or Offers
  surface without the respective grants.

## 11. Explicitly out of scope

- Payments/escrow for attention bonds (future HIP; see §5).
- Anonymous cold contact. The §17 `HERALD-ANON` idea (zero-knowledge proof of
  Level 2 status without identity disclosure) could later serve whistleblower
  and source-protection cases; it composes with open contexts but is a
  separate, harder proposal.
- Directory/search infrastructure for discovering open contexts — a product
  and governance question (Foundation policy), not a protocol one.
