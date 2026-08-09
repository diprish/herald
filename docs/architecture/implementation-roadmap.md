# HERALD Reference Implementation — Roadmap

**Status:** Active plan; phases are strict vertical slices — each leaves the
repository strictly more valuable even if work pauses after it.
**Companion:** [`tech-stack.md`](tech-stack.md) records *what* we build with and
why; this document records *in what order* and *when a phase is done*.
**Section references (§)** point to [`spec/HERALD_Protocol_Specification_v1.1.md`](../../spec/HERALD_Protocol_Specification_v1.1.md).

---

## Phase 0 — Foundation documents

**Scope:** The tech-stack decision record and this roadmap.

**Done when:** both documents are merged to `main`. Every later PR is
reviewable against a stated plan instead of relitigating direction.

**Status:** complete.

---

## Phase 1 — `herald-core`: the shared protocol core

**Scope:** A Cargo workspace with one pure, no-I/O library crate that every
other component will consume — natively on the server, via WASM on the web,
via UniFFI on mobile.

Deliverables:

- **Workspace scaffold**: `crates/herald-core`. (`herald-server` and
  `herald-cli` are created in Phase 2 rather than committed empty — the target
  shape is recorded in [`tech-stack.md`](tech-stack.md) §6.)
- **Types**: GID and context-address parsing/validation against the §3.1–3.3
  grammars; event envelope; core event types (§4.1).
- **Canonical serialization** (JCS, RFC 8785 style) — the bit-identical-
  everywhere requirement.
- **Signing and verification**: Ed25519 over canonical events; signature →
  device key → cross-signing chain → identity key validation (§3.6).
- **Hash-chain log validation**: `seq`/`prev_event` integrity and divergence
  detection with `SEQ_CONFLICT` semantics (§4.2).
- **Trust-chain engine** as pure functions: the §6.3 admit/quarantine/reject
  decision across Tiers 1–4, including transactional-grant validation (§6.2),
  covered by table-driven and property tests.
- **Published test vectors** in `vectors/` (JSON): canonical forms, signatures,
  valid and invalid chains, trust decisions. These seed the conformance suites
  and any second implementation, and are expected to graduate into a spec
  appendix.
- **CI** (GitHub Actions): fmt, clippy, tests, and a **WASM build check** —
  cheap insurance that the core stays WASM-clean long before a web client
  exists.

**Done when:** CI is green, the vectors directory round-trips through the
library, and a second implementer could start from `vectors/` alone.

**Explicitly out:** networking, storage, async — the crate stays pure.

**Status:** complete. 87 tests pass (80 unit, 6 vector-conformance, 1 doc);
clippy is clean under `-D warnings` with `clippy::pedantic` enabled; the crate
builds for `wasm32-unknown-unknown`; and `vectors/` regenerates byte-identically,
which CI enforces.

---

## Phase 2 — Minimal HHS + CLI: two identities talk

**Scope:** The smallest server and client that produce a real, signed,
trust-checked HERALD exchange end to end. **This is the "hello world" moment —
after this phase, HERALD exists.**

Deliverables:

- `herald-server` (tokio/axum): WebSocket `HELLO` and version negotiation
  (§8.2, Appendix B); event submission → trust check → sequencing → append
  (§4.2); sliding-sync-lite endpoint honoring the §8.4 window shape with
  minimal filters.
- **Storage trait** with a SQLite implementation (PostgreSQL slots in later
  without touching server logic; SQLite keeps this phase testable anywhere and
  keeps the §11.3 small-self-host story honest).
- `herald-cli`: register two Level-0 identities (§3.5), establish mutual
  contact (Tier 1), exchange signed messages through a local server, read them
  back via sync.
- **Integration test**: the full send → verify → trust-check → sequence →
  sync round trip in one test.

**Done when:** `cargo test` runs the round trip green, and the CLI demo works
against a locally running server from a clean checkout.

**Explicitly out:** federation, E2EE payload encryption (events are signed but
plaintext this phase), OIDC (stub auth), offline queues.

**Status:** in progress.

*Landed:* the transport-independent engine (`Hhs`) doing registration with
cross-signing verification, trust-gated thread creation, membership checks,
signature verification, sequencing, log append, and sliding-sync reads; the
`Store` trait with an in-memory implementation; `herald-cli` running a narrated
two-identity conversation; and an eight-case round-trip integration suite
covering the happy path, cold-contact refusal, non-member posting and probing,
sequence conflict and retry, tampering, unsound identity chains, and group
threads.

*Landed since:* the axum HTTP/WebSocket transport — `HELLO` on connect with
version negotiation (§8.2, Appendix B), id-correlated request/response frames,
and real-time server push (§8.3) that reaches every member's connections except
the submitting one, so a user's second device stays current without the sender
being echoed its own event. A `herald-server` binary serves it, and five
integration tests drive a listening server over real sockets.

*Remaining:* the SQLite `Store` implementation, and authentication.
**Authentication is not implemented** — §8.1 specifies OIDC with DPoP-bound
device keys, and until that exists a connection simply asserts an identity.
Events stay signature-verified so nothing can be forged, but *reads* are
unprotected, so the binary refuses to start without an explicit
`--insecure-dev-auth` acknowledging it.

*Surfaced:* a genuine specification tension between server-assigned sequencing
and signature coverage, written up in
[`implementation-findings.md`](implementation-findings.md).

---

## Phase 3 — Depth (ordered by need, not strictly sequenced)

Candidate slices, each independently mergeable:

- **Cross-signing flows end-to-end** (§3.6): add-device ceremony, chain
  validation against counterparties.
- **E2EE payload encryption** (§9): X25519 + AES-256-GCM wiring through core
  and server; server holds ciphertext only.
- **Draft event types** (`h.offer`, `h.itinerary`, `h.action` — see
  [`../proposals/`](../proposals/)): mostly schemas plus validation rules once
  core exists, and implementing them is the cheapest way to pressure-test the
  pre-HIP drafts before HIP submission.
- **Registry stub + KDS cache** (§11.1): `GID → keys` resolution with TTL and
  a push-invalidation hook.

**Done when:** each slice lands with tests; no collective gate.

---

## Deferred (deliberately, not indefinitely)

Multi-service integration work that is premature before Phases 1–2 stabilize
the wire formats:

- Federation mesh: HFA, mTLS between servers, NATS fan-out (§7.2, §11.2).
- OIDC against a real IdP (Keycloak/Ory) with DPoP token binding (§8.1).
- SMTP bridge on the Stalwart crates (§14).
- Web client (TS/React over the WASM core) and mobile bindings (UniFFI).
- Go conformance suites (HCS/HFA/Bridge) — seeded by the Phase 1 vectors.
- Docker Compose reference deployment (§11.3).

---

## Sequencing rationale

The order follows the dependency chain: every component consumes
`herald-core`, so it comes first; a server and client that exercise it come
second, because nothing validates a protocol library like a live round trip;
depth and integration follow once wire formats have survived contact with a
real exchange. The published vectors are placed in Phase 1 — not deferred with
the conformance suites — because they are what make independent
implementations (including the Elixir second-implementation recommendation in
[`tech-stack.md`](tech-stack.md) §4) possible at all.
