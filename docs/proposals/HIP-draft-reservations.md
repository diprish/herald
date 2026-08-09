# HIP Draft — Reservations: The Booking as a Live Thread

**Status:** Pre-HIP draft (for discussion; not yet submitted to the HIP process, §16)
**Requires:** HERALD Protocol Specification v1.1
**Related:** [HIP Draft — Offers](HIP-draft-offers.md) (shares grant-scope routing, expiry
semantics, and client-side computation); introduces `h.action`, a general-purpose
primitive proposed here but deliberately specified domain-neutrally.
**Section references (§)** point to [`spec/HERALD_Protocol_Specification_v1.1.md`](../../spec/HERALD_Protocol_Specification_v1.1.md).

---

## 1. Problem

A reservation — a flight, a train seat, a hotel room, a medical appointment — is
**one object with a lifecycle**: booked → seat assigned → check-in open → gate
assigned → delayed → boarding. Today each transition is fired as a separate
email, SMS, and app push through uncoordinated channels, none of which can
update or retract the previous one. Consequences:

- **Stale truth.** A "14:30 departure" email sits above a "now 16:10" SMS;
  the user must reconstruct current state by hand.
- **Fragmentation as exclusion.** Full functionality often requires the
  carrier's own smartphone app — a real accessibility and inclusion barrier.
  Email and SMS users get a degraded, delayed subset.
- **A mass-scale phishing surface.** Fake "your flight was changed, click
  here" SMS is among the most common smishing patterns, and it
  disproportionately harms less tech-savvy users. Neither SMS nor email can
  authenticate the carrier.
- **Engagement friction.** Acting on a notification (check in, accept an
  upgrade, pick a seat) means leaving the channel for a website or app login.

This is the same defect the Offers draft names — live state shipped as
disconnected snapshots — in its most acute form, plus an interaction problem
Offers does not have: reservations require the user to *act*, not just read.

## 2. Core reframe

**The booking is a thread.** One thread per reservation, created at purchase
through the transactional grant the user already mints by booking (§6.2 —
zero additional taps). That thread is the single channel for the entire trip
lifecycle: state, notifications, actions, and support.

Four cooperating pieces:

1. A `reservations` grant scope (§3) routing lifecycle traffic and gating
   urgency privileges.
2. An `h.itinerary` event type (§4): the reservation as supersedable state.
3. An `h.action` primitive (§5): one-tap, cryptographically signed
   request/response interaction — the general-purpose piece.
4. Client-side trip intelligence (§6): reminders and leave-by-X computed
   locally, never via carrier surveillance.

## 3. The `reservations` grant scope

Sibling of the Offers draft's `offers` scope, minted by the booking flow:

```json
{
  "grant_type": "transactional",
  "grantee": "notifications:acmeair",
  "scope": "reservations",
  "booking_ref": "PNR-X7K2M9",
  "max_urgency": "critical",
  "valid_until": "2026-09-30T00:00:00Z",
  "signature": "<user identity key>"
}
```

- Events under a `reservations` grant MUST be `h.itinerary`, `h.action`,
  `h.message` (support conversation), or thread-meta events, within threads
  tied to the grant's booking. Marketing is structurally excluded — an
  `h.offer` under a `reservations` grant is rejected.
- The grant's natural lifetime is the trip: `valid_until` defaults to shortly
  after the final segment ends. Post-trip marketing requires a separate,
  separately-revocable `offers` grant.
- `max_urgency` (default `critical` for transport bookings) caps the urgency
  class (§7) the grantee may use.

## 4. `h.itinerary` — reservation as supersedable state

```json
{
  "type": "h.itinerary",
  "sender": "notifications:acmeair",
  "content": {
    "booking_ref": "PNR-X7K2M9",
    "status": "delayed",
    "segments": [
      {
        "mode": "flight",
        "id": "AA123",
        "from": { "code": "SFO", "terminal": "2", "gate": "B27" },
        "to": { "code": "JFK", "terminal": "8" },
        "scheduled_departure": "2026-08-15T14:30:00-07:00",
        "estimated_departure": "2026-08-15T16:10:00-07:00",
        "seat": "14C",
        "cabin": "economy"
      }
    ],
    "passengers": ["diprish"],
    "supersedes": "$prev-itinerary-event"
  }
}
```

Rules:

- Each `h.itinerary` supersedes the previous one (via `supersedes`, following
  the `h.edit` pattern of §4.1); the client renders **only current state** in
  a pinned position — a stale departure time can never sit above a newer one.
- The append-only log (§4) retains every version: an audit trail of "this
  flight moved three times," each version signed by the carrier's org context.
  Because grants are unforgeable (§10.2) and events immutable, the log is
  **non-repudiable evidence** for delay-compensation claims — something no
  email or SMS trail provides.
- The schema is deliberately mode-generic: `flight`, `rail`, `lodging`,
  `appointment`, `event` share the segment envelope with mode-specific fields.
- Content is structured blocks / typed fields only (§5 of the spec); no HTML,
  links carry resolved destinations and verdicts as usual.

## 5. `h.action` — signed one-tap interaction (general-purpose)

The pillar forbids HTML and forms (§2 principle 6), so engagement needs a
native primitive. `h.action` is proposed here because reservations need it
most urgently, but it is specified domain-neutrally: RSVPs, approvals,
delivery rescheduling, and payment confirmations are the same shape.

**Request** (sent by the grantee):

```json
{
  "type": "h.action",
  "content": {
    "action_id": "act-checkin-01",
    "prompt": "Check-in is open for AA123.",
    "options": [
      { "id": "checkin", "label": "Check in now" },
      { "id": "later", "label": "Remind me 3h before departure" }
    ],
    "expires_at": "2026-08-15T13:30:00-07:00",
    "urgency": "time-sensitive"
  }
}
```

**Response** (emitted by the user's client on tap):

```json
{
  "type": "h.action.response",
  "content": {
    "action_ref": "$event-id-of-request",
    "action_id": "act-checkin-01",
    "chosen": "checkin"
  }
}
```

Binding rules (the security core):

- The response's signature covers `action_ref` — the exact request *event*,
  not just the `action_id` — so consent binds to the precise prompt and
  options the user saw. A grantee cannot edit a request after the fact and
  claim consent to the new text: `h.edit` on an `h.action` invalidates all
  prior responses and MUST be re-presented.
- Option semantics live entirely in the signed request; the response carries
  only a choice reference. There is no free-form field a malicious client
  could inject, and nothing executes locally — a response is data, and any
  real-world effect (issuing the boarding pass) happens grantee-side.
- Expired requests are unanswerable: clients MUST NOT allow responses after
  `expires_at`, and grantees MUST reject late responses.
- Completed and expired actions collapse in the rendering (the Offers expiry
  pattern) — a thread never nags about a check-in already done.
- Options MUST be side-effect-symmetric in cost: an option that commits the
  user to payment MUST carry an explicit `commits_payment` amount field the
  client renders distinctly (and MAY require confirmation — the one permitted
  extra tap, since spending money is precisely the decision Principle 2.7's
  budget exists for).

What this buys over the status quo: the carrier receives a **signed,
non-repudiable response tied to the exact question asked** — stronger consent
evidence than any web form — and the user acts in one tap without leaving the
thread, downloading an app, or following a link (eliminating the smishing
"click here to rebook" pattern wholesale).

## 6. Client-side trip intelligence — the privacy inversion

Because the itinerary is typed data, the *client* — which already knows the
user's location, calendar, and timezone — computes locally:

- **Leave-by reminders** ("leave by 15:40; traffic on I-880 is heavy") from
  local position + a traffic source of the client's choosing. The carrier
  never learns the user's location — inverting today's model, where this
  feature is the pretext for carrier apps collecting location data.
- **Calendar materialization**: segments auto-create/update calendar entries;
  a supersession updates the entry in place.
- **Cross-booking awareness**: a delayed inbound flight tightening a separate
  rail connection is visible only to the client, which holds both threads.

None of this requires protocol support beyond the typed schema — it is a
client-competition surface, listed here to fix the design intent: **the
protocol ships state; intelligence stays local** (same doctrine as the Offers
draft's client-side relevance ranking).

## 7. Urgency classes

`h.itinerary` and `h.action` events carry `urgency`:

| Class | Examples | Notification behavior |
|---|---|---|
| `info` | Seat change, schedule confirmed | Normal thread notification rules |
| `time-sensitive` | Check-in open, boarding soon | Elevated; respects quiet hours |
| `critical` | Cancellation, gate change in progress, major delay | MAY break through quiet hours / muted state |

The break-through privilege is the abuse surface, so it is collateralized like
everything else in HERALD:

- Available only under scopes whose grants carry `max_urgency` (this draft:
  `reservations`; conceivably future scopes like medical). `offers`-scope
  events have no urgency field at all — marketing physically cannot ride the
  urgent channel.
- Per-grantee **urgency reputation**: user taps of "this wasn't urgent"
  (one-tap, optional) decay the grantee's effective `max_urgency` — first to
  `time-sensitive`, then `info` — recovering only slowly. An airline that
  cries wolf loses the wolf-channel.
- `critical` volume is server-capped per grant per day; floods degrade to
  `time-sensitive` delivery rather than being dropped (§8.5 doctrine: nothing
  silent).

## 8. Inclusivity properties

- **One channel replaces email + SMS + per-carrier app.** The full-fidelity
  experience — live state, urgent alerts, one-tap actions — works on any
  conformant client. No smartphone-app-per-airline; typed blocks render
  cleanly to screen readers and low-bandwidth clients in a way HTML mail and
  app UIs never have.
- **Shared trips are group threads.** An N-member thread is the same object
  as a 2-member one (§4.3), so adding family, a caregiver, or an assistant to
  the booking thread gives everyone the *same live state*, each addition
  individually trust-checked. Today's equivalent is forwarding stale
  confirmation emails. `h.action` requests MAY be scoped to specific members
  (only the account holder may accept a paid upgrade; anyone may view).
- **Phishing immunity as safety equity.** A reservation update MUST arrive
  signed by the carrier's org context under a currently-valid CA grant, in a
  thread the user's own purchase created. The fake-flight-change SMS has no
  primitive to exist through. During coexistence, bridged legacy
  notifications render in the banner-marked Legacy surface (§14.2), making
  the trust difference visible rather than implicit.
- **Support continuity.** A reply in the thread reaches the carrier *in
  context* — the agent or bot sees the live itinerary and full history.
  "Please provide your booking reference" disappears; the thread is the
  booking reference.

## 9. Zero-interaction analysis (required by §16)

| Decision | Zero-interaction path |
|---|---|
| Subscribe to trip updates | Inferred from booking: the purchase flow mints the `reservations` grant. Zero taps. |
| Keep state current | Automatic supersession; the user never reconciles messages. |
| Check in / respond | One tap in-thread — strictly fewer interactions than any current channel (link → site → login → form). The tap is the action itself, not an approval screen. |
| Get leave-by reminders | Automatic, client-local, from data the client already holds. |
| Share the trip | Inferred from the existing act of adding a member to the thread. |
| End the relationship | Automatic: grant expires with the trip. Post-trip contact needs a separate grant the user can decline by simply not granting it. |
| Police false urgency | Optional one-tap signal; class decay works from rates, so no individual user must act. |

Explicit-approval screens in the default flow: none. The single permitted
confirmation is on payment-committing `h.action` options (§5), which is a
deliberate spend of the Principle 2.7 budget.

## 10. Threat-model delta (required by §16)

- **Urgency abuse.** Covered in §7: scope-gated, capped, reputation-decayed.
  Worst case converges to today's normal-notification behavior.
- **Consent forgery / bait-and-switch on actions.** Prevented by binding
  responses to the exact request event and invalidating responses on edit
  (§5). A grantee cannot obtain a signature over text the user never saw.
- **Replay of action responses.** Responses reference a unique request event
  in a specific thread and are deduplicated by `event_id` (§8.5); a response
  replayed elsewhere fails `action_ref` validation.
- **Malicious "carrier" threads.** Creating the thread requires a
  `reservations` grant, which only the user's own booking flow mints, and
  sending under an org context requires a valid CA grant (§3.9). A scammer
  holds neither. Residual risk is a *compromised* carrier context — mitigated
  by CA revocation propagating in real time (§11.1) and grant validity being
  checked at event-acceptance time.
- **Member-scoping leaks.** In shared trip threads, action requests scoped to
  one member are still visible to all (thread E2EE is thread-wide); carriers
  MUST NOT put confidential per-passenger data (e.g. medical notes) in a
  shared thread — the spec pattern is a separate 1:1 thread under the same
  grant. Flagged as guidance, not mechanism.
- **Grant lifetime creep.** Carriers could set distant `valid_until` to keep
  a channel open. Mitigation: clients display grant expiry at mint time, and
  a `reservations` grant that has had no `h.itinerary` activity for 90 days
  past the last segment is auto-suspended client-side (zero-interaction
  cleanup, mirroring the Offers auto-decay).
- **Surveillance shift.** The design deliberately moves intelligence
  client-side (§6); the carrier learns taps on its own actions and nothing
  else. `h.read` remains suppressed by default on grant-scoped threads
  (Offers-draft rule, extended here).

## 11. Compatibility

- Additive: one new scope value, two new event types (`h.itinerary`,
  `h.action`/`h.action.response`), one new content field (`urgency`) valid
  only under scopes that declare it. No changes to trust tiers, thread
  mechanics, or wire formats.
- Clients that do not recognize the new types render their `summary_blocks`
  fallback (same degradation rule as the Offers draft) — a delayed flight
  still reads as a message; only the live-state pinning and one-tap actions
  are lost.
- The SMTP bridge (§14.2) can down-convert: an `h.itinerary` supersession
  renders to legacy recipients as a normal update email; inbound legacy
  confirmation emails MAY be parsed into read-only pseudo-itineraries in the
  Legacy surface, clearly marked best-effort (mirroring the Offers bridge
  rule).
- `h.action` is expected to be extracted into its own HIP once a second
  consumer (e.g. calendar RSVPs) is specified; this draft is written so the
  extraction is a copy, not a rewrite.

## 12. Explicitly out of scope

- Payment execution inside `h.action` (the option only *declares* a
  commitment; settlement is grantee-side — a payments primitive is the same
  future HIP the Cold Contact draft's attention bonds await).
- Boarding-pass credentials (barcodes/NFC): carried as ordinary encrypted
  attachments (§5.1) for now; a wallet-grade credential format is a separate
  proposal.
- Traffic/location data sources for client-side reminders — client
  implementation choice, not protocol.
- Carrier-side adoption incentives (signed consent evidence, guaranteed
  critical delivery, zero SMS gateway cost) — argued in the thread of this
  proposal, not specified.
