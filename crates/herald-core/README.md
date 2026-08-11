# herald-core

The shared protocol core for [HERALD](../../README.md): canonical
serialization, event signing and verification, cross-signing chains, thread-log
integrity, and trust-chain evaluation.

Every HERALD component consumes this crate — the home server natively, the web
client through WebAssembly, mobile clients through UniFFI — so that the rules a
signature depends on exist exactly once. Two implementations of canonical JSON
that disagree by a single byte cannot verify each other's events; keeping that
code in one place is the point of the crate. See
[`docs/architecture/tech-stack.md`](../../docs/architecture/tech-stack.md) §2.

## Design constraints

- **No I/O.** Nothing here opens a socket, reads a clock, or touches a file.
  Timestamps arrive as parameters; key material arrives as bytes.
- **No operating-system randomness.** Keys are built from caller-supplied
  seeds, which keeps the crate free of `getrandom` and therefore buildable for
  `wasm32-unknown-unknown` with no JavaScript shim. Key *generation* belongs to
  the host (server, client app, or hardware-backed store per spec §12).
- **Pure decisions.** Trust evaluation (§6) is a function of explicit state, so
  it can be exhaustively tested and shared byte-for-byte between server and
  client.

## Modules

| Module | Specification | Contents |
|---|---|---|
| `canonical` | §4.1, §9 | JCS/RFC 8785 canonical JSON and SHA-512 hashing. Floats are rejected outright, as in Matrix canonical JSON |
| `crypto` | §9 | Ed25519 signing keys and X25519 encryption keys; hex wire encoding |
| `id` | §3.1–3.3 | `Gid`, `ContextName`, `ContextAddress`, `HeraldAddress` grammars |
| `identity` | §3.4, §3.6 | Verification levels and the identity → self-signing → device certificate chain, certifying each device's signing *and* encryption key |
| `encryption` | §9 | End-to-end encryption: fresh content key and ephemeral X25519 pair per event, wrapped per recipient device |
| `event` | §4.1 | Event drafts, content-derived `event_id`, signing and verification |
| `log` | §4.2 | Thread-log sequence and hash-chain validation, including sliding-sync windows |
| `trust` | §6 | Tier 1–4 admission decisions, context-grant grace states, adaptive Connection Request caps |
| `error` | Appendix A | Wire error codes |

## Test vectors

[`vectors/`](../../vectors) holds the published protocol vectors: canonical
forms and their hashes, cross-signing chains (sound and unsound), signed events
with their exact signing payloads and signatures, and trust decisions with
their inputs. They are the contract an independent implementation builds
against, and CI fails if the committed files drift from what the code produces.

Regenerate deliberately — a diff here is a wire-format change:

```sh
cargo run -p herald-core --example gen_vectors
```

## Development

```sh
cargo test -p herald-core                                  # unit, vector, and doc tests
cargo clippy -p herald-core --all-targets -- -D warnings   # lints
cargo build -p herald-core --target wasm32-unknown-unknown # WebAssembly path
```
