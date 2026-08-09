# HERALD Reference Implementation — Tech Stack

**Status:** Decided for the reference implementation; revisable by HIP as the
project matures.
**Section references (§)** point to [`spec/HERALD_Protocol_Specification_v1.1.md`](../../spec/HERALD_Protocol_Specification_v1.1.md).

---

## 1. Requirements that drive the choices

The stack is derived from what the spec demands, not preference:

- **Bit-identical canonical signing everywhere.** Every event is Ed25519-signed
  over a canonical serialization (§4.1, §9) and verified by servers *and* every
  client. Two implementations of canonicalization that disagree by one byte is
  the worst class of protocol bug available to us.
- **Heavy modern crypto:** Ed25519, X25519, AES-256-GCM, HKDF-SHA512,
  cross-signing chains, Shamir shards (§9, §3.6, §3.7), with a versioned suite
  registry for post-quantum hybrids.
- **Massive persistent-connection fan-out:** real-time WebSocket push is
  first-class (§8.3), with per-session sliding-sync state (§8.4).
- **Append-only event logs** with per-thread monotonic sequencing (§4.2),
  sharding naturally by `thread_id` (§11.1).
- **Permissioned mTLS federation** (§7.2, §11.2) and CT-style verifiable
  identity records (§11.1).
- **OIDC, not bespoke auth** (§8.1 — explicitly inherited, never reinvented).
- **A bidirectional SMTP bridge** with real DKIM/SPF/DMARC evaluation (§14.2).
- **Self-hostability as a promise, not a footnote** (§11.3): a small
  organization must be able to run an HHS without a platform team.

One precedent weighs on everything: HERALD borrows Matrix's architecture
(§4, §7), so Matrix's implementation history is our cheat sheet. Synapse
(Python) became the ecosystem's performance albatross; Matrix's corrective
bets were Rust (`matrix-rust-sdk`, `vodozemac`) and Go (Dendrite). We start
where they ended up.

## 2. The keystone decision: one shared Rust protocol core

**`herald-core`** — a pure, no-I/O Rust crate owning:

- GID / context-address grammar (§3.1–3.3), event envelope and core event
  types (§4.1);
- canonical serialization (JCS, RFC 8785 style);
- signing/verification: Ed25519 over canonical events, device key →
  cross-signing chain → identity key (§3.6);
- hash-chain log validation (`seq` / `prev_event`, divergence detection, §4.2);
- the trust-chain decision engine (§6.3) as pure functions;
- E2EE primitives: X25519 key agreement, AES-256-GCM, HKDF (§9).

It compiles **natively** for the server, to **WASM** for the web client, and
via **UniFFI** bindings for iOS/Android — the `matrix-rust-sdk`/`vodozemac`
playbook. Every other component consumes this crate; no protocol logic is ever
reimplemented per platform. The WASM build is a CI target from day one so the
core stays WASM-clean before any web client exists.

## 3. Component decisions

| Component | Choice | Rationale |
|---|---|---|
| Protocol core | **Rust** — RustCrypto (`ed25519-dalek`, `x25519-dalek`, `aes-gcm`, `hkdf`), `serde` | Memory-safe, audited crates; WASM + UniFFI reach; `ml-kem`/`ml-dsa` crates available when the §9 post-quantum revision lands |
| Home Server (HHS) | **Rust** — `tokio` + `axum` + `tungstenite`, `rustls` (TLS 1.3 / mTLS) | Security-critical, connection-heavy, I/O-bound: tokio's sweet spot. Conduit-class Rust homeservers run in a fraction of Synapse's footprint |
| Event storage | **PostgreSQL** (SQLite behind the same storage trait for dev/small self-host) | Append-only logs with monotonic `seq` are an ideal relational workload; JSONB content, `LISTEN/NOTIFY` for intra-node wakeups; shard by `thread_id` later (partitioning/Citus). No FoundationDB-class complexity pre-launch |
| Fan-out / federation pubsub | **NATS (JetStream)** | Cross-node relay and KDS push-invalidation broadcast (§11.5) are its native model; far lighter to self-host than Kafka, which §11.3 cares about |
| Attachment Store | **S3 API**, MinIO reference deployment | Ciphertext blobs, content-addressed dedup (§11.1); one code path for self-hosters and cloud |
| KDS | **Redis** cache-aside in front of the registry, invalidated via NATS | 1h TTL + push invalidation (§11.5) is textbook cache-aside |
| Identity Registry | **PostgreSQL + a transparency log** (Trillian or Sunlight-style Merkle log) | "Federated ledger" (§11.1) means CT-style verifiable append-only key bindings — auditable, misbehavior detectable — the Key Transparency design (CONIKS / WhatsApp KT). Explicitly **not** a blockchain |
| Auth | **Keycloak** (or Ory Hydra) as reference IdP; `openidconnect` crate client-side; DPoP token binding | §8.1 mandates inheriting mature IdP stacks. Matrix built `matrix-authentication-service` (Rust) for the identical migration — validated path |
| SMTP bridge | **Rust** on the Stalwart mail crates (`mail-parser`, `mail-auth`, `mail-send`) | §14.2 needs DKIM/SPF/DMARC evaluation and clean MIME both directions; Stalwart's crates are the modern maintained Rust mail stack, and the bridge stays in the workspace language |
| Web client | **TypeScript + React**, `herald-core` via WASM | Crypto/canonicalization from the shared core; TS/React is where client contributors are; sliding sync (§8.4) maps to windowed list virtualization |
| Mobile | **Native Swift/Kotlin shells over UniFFI** bindings to `herald-core` | The Element X architecture, proven at scale; React Native is the fallback if team size demands one codebase |
| Conformance suites | **Go + Docker**, Complement-style, one suite per API (HCS / HFA / Bridge) | §16 requires per-API suites; a *different* language from the reference implementation is a feature — it catches spec ambiguity rather than echoing implementation behavior |
| Ops | **Docker Compose** for self-host, Helm for scale, **OpenTelemetry** throughout | A single `docker compose up` HHS is what makes §11.3 true |

## 4. Considered alternatives

### Elixir/BEAM for the HHS — the serious contender

The HHS runtime profile is the BEAM's founding use case, and the case is
genuinely close:

**Where Elixir wins.** Massive cheap persistent connections with per-connection
state (Phoenix Channels; WhatsApp/ejabberd/Discord-gateway territory). The
per-thread sequencer (§4.2) maps one-to-one onto a GenServer — serialization by
mailbox, no locks, hibernation when idle. Sliding-sync session state (§8.4) is
a process holding its own state. Fault isolation by supervision tree is
resilience-by-default for correspondence infrastructure. Phoenix Presence's
CRDT is literally built for §15's ephemeral presence, and distributed Erlang +
Phoenix PubSub could absorb NATS for intra-cluster fan-out. The crypto
objection mostly dissolves: `herald-core` is Rust regardless, consumed via
Rustler NIFs at native speed (Discord's pattern).

**Why the reference implementation is Rust anyway.** (1) The shared-core
argument: the server must run the same canonicalization/crypto code as the
clients, and that core must be Rust for WASM/UniFFI reach — an Elixir server
puts an FFI boundary (with NIF crash-discipline requirements) at the most
security-critical seam. (2) HERALD's simplified linear-log model (§4.2)
removed most of the algorithmic churn where BEAM ergonomics pay off; what
remains is the high-connection, crypto-heavy workload where Rust's costs buy
the most. (3) A one-language workspace keeps the contributor and self-hoster
bar low for the implementation whose job is to *define* correct behavior.

**Standing recommendation.** The spec isn't real until two independent
implementations pass conformance (the Matrix lesson; §16). **An Elixir/Phoenix
HHS is the ideal second implementation** — different enough in runtime
philosophy to flush out spec ambiguities, and plausibly the operational winner
at scale. A team that is already Elixir-strong could defensibly flip the choice
for the server; nowhere else.

### Other rejections

- **Go for the HHS** (Dendrite precedent): faster iteration, easier hiring —
  but loses the shared-core argument the same way Elixir does, without BEAM's
  runtime advantages in exchange. Go wins where we've placed it: the
  conformance suites, and likely the Trillian-adjacent registry tooling.
- **Node.js for the HHS**: WebSocket fan-out at scale plus constant CPU-bound
  crypto is the wrong fit for a single-threaded event loop; worker-thread
  architectures rebuild, poorly, what tokio/BEAM give natively.
- **Blockchain for the Identity Registry**: a transparency log provides the
  required auditability (§11.1) without consensus overhead, token economics,
  or governance capture. The registry is permissioned and accountable (§11.2);
  Byzantine consensus solves a problem HERALD does not have.
- **Bespoke IdP / credential handling**: prohibited by the spec itself (§8.1).

## 5. Build order

Phases are vertical slices; each leaves the repo strictly more valuable.

| Phase | Deliverable | Definition of done |
|---|---|---|
| **0** | Architecture docs | This document + roadmap merged |
| **1** | `herald-core` | Workspace scaffold; types, canonical serialization, signing/verification, hash-chain validation, trust-chain engine; **published JSON test vectors** (canonical forms, signatures, valid/invalid chains — the seed of the conformance suite and any second implementation); CI (fmt, clippy, test, WASM build check) |
| **2** | Minimal HHS + CLI | `herald-server`: WebSocket `HELLO`/version negotiation (§8.2, App. B), event submit → trust check → sequence → append, sliding-sync-lite; SQLite behind the storage trait. `herald-cli`: two Level-0 identities exchange signed messages through a local server. Integration test covers the full round trip. **This is the "hello world" moment** |
| **3** | Depth (pick by need) | Cross-signing flows end-to-end; E2EE payload encryption wiring; the draft event types (`h.offer`, `h.itinerary`, `h.action`) — implementing them is the cheapest way to pressure-test the pre-HIP drafts; registry stub + KDS cache |
| **Deferred** | Federation mesh (mTLS/NATS), OIDC against a real IdP, SMTP bridge, mobile bindings, web client, Go conformance suites | Multi-service integration work, premature before Phases 1–2 stabilize wire formats. The WASM CI target from Phase 1 is the cheap insurance that the web client path stays open |

## 6. Repository shape (target)

```
herald/
  spec/                 Protocol specifications
  docs/                 Architecture, comparisons, proposals
  crates/
    herald-core/        Shared protocol core (WASM- and UniFFI-ready)
    herald-server/      HHS (HCS now; HFA when federation lands)
    herald-cli/         Reference CLI client / demo harness
  vectors/              Published protocol test vectors (JSON)
  conformance/          Go conformance suites (later)
  deploy/               Docker Compose reference deployment (later)
```
