# HIP Draft — Offers: Marketing as Expiring State, Not Messages

**Status:** Pre-HIP draft (for discussion; not yet submitted to the HIP process, §16)
**Requires:** HERALD Protocol Specification v1.1
**Section references (§)** point to [`spec/HERALD_Protocol_Specification_v1.1.md`](../../spec/HERALD_Protocol_Specification_v1.1.md).

---

## 1. Problem

The bulk of legacy email volume is marketing. It has two structural defects that
no filtering fixes:

1. **Inbox pollution.** Offers interleave with correspondence, burying messages
   from actual humans.
2. **Staleness.** An SMTP message is an immutable document. "20% off until
   Friday" is *state*, but email can only ship it as a *snapshot* — so inboxes
   accumulate offers that no longer exist, and the user cannot tell live from
   dead without clicking through.

SMTP cannot repair this: sent mail cannot expire, update, or retract itself.
HERALD's append-only event-log model (§4) — with `h.edit` and `h.redact`
supersession already specified — can.

## 2. Proposal summary

Three cooperating additions, smallest possible delta on v1.1:

1. **An `offers` grant scope** (§6.2 extension) — marketing traffic is admitted
   under a distinct transactional-grant scope and **never enters the inbox**.
2. **An `h.offer` event type** (§4.1 extension) with a **mandatory
   `valid_until`** — a dead offer can never render as live.
3. **A client-side Offers surface** (§12 extension) — one consolidated,
   searchable view of all current offers across merchants, sectioned by
   relevance computed **locally**.

A pull-based "offer feed" model is sketched in §8 as a possible successor HIP;
it is explicitly out of scope here.

## 3. The `offers` grant scope

§6.2 transactional grants currently carry `scope: "thread-initiate"`. This HIP
adds `scope: "offers"`:

```json
{
  "grant_type": "transactional",
  "grantee": "promos:acmeair",
  "scope": "offers",
  "valid_until": "2027-07-21T00:00:00Z",
  "signature": "<user identity key>"
}
```

Semantics:

- Events sent under an `offers` grant MUST be of type `h.offer` (or thread-meta
  events for the offer thread itself). Anything else is rejected with
  `TRUST_DENIED`.
- Offer threads are routed to the **Offers surface**, never the inbox — the same
  routing-by-class pattern already used for the quarantine surface (§6.6) and
  the Legacy surface (§14.2).
- An `offers` grant conveys no right to initiate correspondence threads. A
  merchant that also needs transactional messaging (receipts, booking changes)
  holds a separate `thread-initiate` grant; the two are independently revocable.
- The `herald://grant` handler (§6.2) lets checkout/signup flows request either
  or both scopes; the client displays which scopes are being granted. Entering
  your address for a receipt does not silently subscribe you to marketing.

## 4. The `h.offer` event type

```json
{
  "type": "h.offer",
  "sender": "promos:acmeair",
  "content": {
    "title": "20% off flights to Lisbon",
    "category": "travel",
    "valid_from": "2026-08-09T00:00:00Z",
    "valid_until": "2026-08-15T00:00:00Z",
    "summary_blocks": [
      { "kind": "paragraph", "text": "Book by Friday for 20% off all LIS routes." }
    ],
    "link": {
      "display": "Book now",
      "declared_url": "https://acmeair.example/lisbon",
      "resolved_url": "https://acmeair.example/lisbon",
      "hops": 0,
      "verdict": "clean"
    },
    "terms_ref": "att-01"
  }
}
```

Rules:

- **`valid_until` is REQUIRED.** Servers reject `h.offer` events without it.
  A ceiling (e.g. 180 days) prevents effectively-permanent offers; merchants
  re-issue or `h.edit` to extend.
- After `valid_until`, conformant clients MUST NOT render the offer as live:
  it is hidden by default, or collapsed into an expired-count line (§6).
- Merchants update an offer with the existing `h.edit` (§4.1) — price changes,
  extensions — and withdraw one early with `h.redact`. The append-only log
  preserves the audit trail ("what was I shown on Tuesday?"); the user only
  ever *sees* current state.
- Content is structured blocks only (§5): typed fields (`category`,
  `valid_until`, sender) make search and filtering trivial, versus scraping
  HTML mail. Link rules from §5 apply unchanged, including send-time resolution
  and verdicts.

## 5. The Offers surface

A conformant client (§12 additions):

- MUST route `h.offer` threads to a dedicated Offers surface, visually distinct
  from the inbox.
- MUST hide or collapse expired offers by default.
- SHOULD provide search and filtering over the typed offer fields, across all
  merchants — the "one consolidated view" this HIP exists to deliver.
- SHOULD section the surface by locally computed relevance, e.g.:
  - **Expiring soon** — sorted by `valid_until`.
  - **From merchants you engage with** — local open/click/redeem history.
  - **New since last visit.**
- MUST compute relevance **client-side only**. No engagement signal is
  reported to merchants or servers. (Read events — `h.read` — SHOULD NOT be
  emitted for offer threads by default.)

This is where HERALD structurally beats provider-side promotions tabs: there
are no tracking pixels to strip (no external resource loading, §5), and the
E2EE model (§9) means neither merchant nor server can observe engagement.
Relevance ranking without surveillance is only possible because ranking runs
on the client.

## 6. Expiry manifests and zero-interaction unsubscribe

Mirroring the §8.5 principle that nothing disappears silently:

- Offers that expire unviewed collapse into a per-merchant count line
  ("14 offers expired unviewed"), not silent deletion.
- Sustained non-engagement is the unsubscribe signal: if every offer from a
  grantee expires unviewed across a rolling window (default: 90 days or 3
  consecutive campaigns, whichever is longer), the client MAY auto-decay the
  grant — first demoting the merchant to a "low engagement" section, then
  suspending the grant with a one-line notice the user can undo with one tap.
- Explicit revocation remains one tap on any offer (§6.2), and revocation is
  effective at the protocol layer — the merchant's events stop being admitted.
  There is no "unsubscribe request" for the merchant to ignore.

## 7. Zero-interaction analysis (required by §16)

Per Principle 2.7, every user decision must have a path inferred from an action
the user already took:

| Decision | Zero-interaction path |
|---|---|
| Subscribe to a merchant's offers | Granted by the address-entry action itself when the checkout/signup flow requests `offers` scope — zero additional taps (§6.2 mechanism, unchanged). |
| Remove dead offers | Automatic: `valid_until` expiry hides them. The user does nothing, ever. |
| Rank offers by relevance | Automatic and local, from actions the user already takes (opening, clicking, redeeming). |
| Unsubscribe | Inferred from sustained non-engagement (grant auto-decay, §6). Explicit one-tap revocation remains as the faster manual path. |
| Separate marketing from correspondence | Structural: scope-based routing. There is no folder to configure and no filter to train. |

Explicit-approval fallbacks used: none in the default flow. The only
interaction ever *offered* is the one-tap undo on grant auto-suspension.

## 8. Future direction (out of scope): pull-based offer feeds

A stronger end-state replaces offer *messages* with merchant-hosted offer
*catalogs*: a grant subscribes the user to a small state object the client
reads at view time (windowed like sliding sync, §8.4). Staleness becomes
impossible because nothing is stored client-side to go stale, and merchant
"send volume" becomes meaningless — the user sees one current snapshot.
This requires a new fetch pathway in HCS/HFA and new caching/availability
semantics, so it is deferred to a separate HIP. The `h.offer` model in this
draft is forward-compatible: a catalog entry serializes to the same content
schema.

## 9. Threat-model delta (required by §16)

New surface introduced, and its mitigations:

- **Offer spam via purchased grants.** A merchant could solicit `offers` grants
  deceptively. Mitigations: the grant is scope-labeled at mint time in the
  client UI; volume is bounded per-grant (server-enforced cap, e.g. 10 live
  offers and 30 `h.offer` events per grantee per 30 days); auto-decay (§6)
  extinguishes ignored grantees; one-tap revocation is protocol-effective.
- **Phishing dressed as offers.** `h.offer` inherits every §10.2 guarantee:
  signed sender identity, no HTML, resolved links with verdicts. An offer from
  `promos:acmeair` requires a valid Acme CA grant; a lookalike cannot obtain
  the context.
- **Engagement surveillance.** Explicitly prevented: relevance is client-side,
  `h.read` suppressed by default on offer threads, no external resources.
  The merchant learns only what SMTP marketing could never avoid leaking —
  nothing.
- **Expiry abuse (artificial urgency).** A merchant could re-issue "expiring"
  offers perpetually. This is a content-honesty problem, not a protocol one;
  the per-grant volume cap bounds the annoyance, and auto-decay punishes it
  (constant re-issues to a non-engaging user accelerate grant suspension).
- **Storage growth.** Offer threads are low-volume by the caps above, and
  expired-offer events are eligible for the recipient's normal retention
  policy (§8.5) once superseded or expired.

## 10. Compatibility

- No changes to existing event types, the trust tiers of §6.1, or wire formats;
  this is additive (new scope value, new event type, new client surface).
- Servers that do not recognize `h.offer` relay it as an opaque event
  (standard unknown-type handling); clients that do not recognize it fall back
  to rendering `summary_blocks` in the thread — degraded but safe.
- The SMTP bridge (§14.2) MAY classify inbound legacy marketing (e.g.
  `List-Unsubscribe` present) into the Offers surface as `h.bridge`-wrapped
  pseudo-offers with `valid_until` unset — displayed with the legacy banner
  and without live-state guarantees. This gives users the consolidated view
  even during the coexistence era, clearly marked as best-effort.
