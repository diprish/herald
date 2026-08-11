# Implementation Findings

Questions the reference implementation raised about the specification itself.
Each is a candidate HIP (§16); none is resolved here. Section references (§)
point to [`../../spec/HERALD_Protocol_Specification_v1.1.md`](../../spec/HERALD_Protocol_Specification_v1.1.md).

---

## 1. Sequencing conflicts with signature coverage

**Raised by:** Phase 2, `crates/herald-server/src/engine.rs`.

§4.2 says the thread's sequencing server "assigns the monotonic `seq` and the
`prev_event` back-link." §4.1 puts `seq` and `prev_event` inside the event body,
and §9 has the sender's device key sign that body. Both cannot hold at once: if
the server assigns a position after the sender signs, the signature no longer
covers the event as stored, and if the sender signs a position first, the server
is validating a claim rather than assigning one.

Three resolutions are available:

1. **Optimistic concurrency (implemented).** The sender reads the current head,
   builds a draft claiming that position, signs, and submits. The server accepts
   only if the thread has not moved, and otherwise returns `SEQ_CONFLICT` — the
   remedy §4.2 already prescribes for divergence. Costs a round trip before each
   send and a retry under contention; keeps position inside the signed body,
   so a relay cannot silently reorder history.
2. **Split envelope.** Move `seq`/`prev_event` out of the signed body into a
   server-assigned envelope, with the sender signing only content and thread
   identity. Removes the round trip, but the sequencing server becomes able to
   reorder or reposition events without detection, weakening §4.2's
   "divergence is detectable (broken hash chain)" property.
3. **Server counter-signature.** The sender signs content; the sequencing server
   adds position and signs the combination. Preserves detectability and removes
   the round trip, at the cost of a second signature per event and a server key
   in the verification path — which every client must then also verify.

**Recommendation:** keep (1) for now — it is the only option that requires no
spec change and no new trust in the sequencing server — and evaluate (3) as a
HIP if the pre-send round trip proves costly under real latency. A decision
should also state explicitly whether a sequencing server is trusted for
*ordering* as well as *availability*; the spec currently implies not, and only
(1) and (3) deliver that.

---

## 2. Membership as a standing admission decision

**Raised by:** Phase 2, `Hhs::create_thread` / `Hhs::submit`.

§6.1 gates "a delivery (thread invite, or first event from a new sender)" on the
trust chain, which leaves ongoing threads ambiguous: is every event re-evaluated,
or does membership stand in for admission once granted?

The implementation evaluates trust when a member is added and treats membership
as the admission thereafter. This makes an active conversation cheap, and it
matches the parenthetical in §6.1. But it means revoking trust (removing a
contact, or a block) does not by itself stop an existing thread — the member
must be removed from the thread as well.

**Question for a HIP:** should a block (§6.3's absolute override) implicitly
eject the blocked party from shared threads, or only prevent new ones? The
implementation currently does the latter, which is very likely the wrong
behavior for a user who blocks someone mid-conversation.

---

## 3. Appendix A has no server-fault error code

**Raised by:** Phase 2, `ServerError::error_code`.

Every code in Appendix A describes something the *client* or *sender* did, or a
state they must react to. A storage or internal failure has nothing correct to
report; the implementation currently returns `SEQ_CONFLICT`, whose prescribed
remedy (refetch the canonical log) is at least harmless, but which misdescribes
what happened.

**Suggestion:** add a `SERVER_ERROR` code, explicitly carrying no information
about the request, so servers are not forced to misreport internal failures as
client-visible protocol states.

---

## 4. Thread identifiers must be allocated by the store, not the engine

**Raised by:** Phase 2, adding `SqliteStore`.

The engine originally held its thread counter in memory. Against the in-memory
store that is indistinguishable from correct, because process lifetime and data
lifetime coincide. Against a durable store it is a bug: a restarted server would
begin numbering from the start again and mint thread identifiers that already
exist in the database, silently colliding with live threads.

The counter now lives behind `Store::allocate_thread_number`, so it is as
durable as the data it names, and `tests/store_conformance.rs` asserts that a
restart does not reissue an identifier.

This is not a specification defect — §4.2 says nothing about how a sequencing
server picks identifiers — but it is worth recording as guidance: **any
monotonic protocol state must be as durable as the objects it names.** The same
argument applies to anything else a future implementation might keep in engine
memory.

---

## 5. Device identifiers are only unique within an identity

**Raised by:** Phase 3, implementing end-to-end encryption.

An encrypted event wraps the content key once per recipient device, filed under
that device's identifier. The first implementation keyed those wrapped keys by
`device_key_id` alone — which is wrong, because nothing in §3.6 makes a device
identifier globally unique. Two people whose clients both name the first device
`DEVKEY:0001` collide: sealing for both writes one wrapped key over the other,
and one of the two recipients silently cannot read the message.

Wrapped keys are now addressed by `gid/device_key_id`, and that qualified
address is bound into the HKDF derivation of the wrapping key, so a wrapped key
also cannot be refiled under a different device.

**Suggestion for the spec:** state explicitly that `device_key_id` is scoped to
its GID, and that any structure addressing devices across identities must
qualify it. The same care applies to the KDS device tree (§11.1) and to anything
else that indexes devices globally.

---

## 6. §9 does not say what the content encryption is bound to

**Raised by:** Phase 3, implementing end-to-end encryption.

§9 specifies the primitives (X25519, AES-256-GCM, HKDF-SHA512) but not the
associated data — what a sealed payload is cryptographically tied to. That
choice has real consequences, and an unstated one means two implementations can
differ while both looking compliant.

This implementation binds `thread_id` and `sender`, so a server cannot move a
sealed payload into another thread or reattribute it. It deliberately does not
bind `seq`: under the optimistic-concurrency sequencing of finding 1, a send
that loses a race is re-signed at a new position, and binding `seq` would force
re-encryption for every recipient on each retry. Position is already covered by
the event signature.

**Suggestion:** the specification should fix the associated data explicitly, and
the choice interacts with finding 1 — if sequencing moves to a server
counter-signature, binding `seq` into the ciphertext becomes cheap and would be
worth doing.
