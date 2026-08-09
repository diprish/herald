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
