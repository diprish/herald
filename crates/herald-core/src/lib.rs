//! # herald-core
//!
//! The shared protocol core for [HERALD](https://github.com/diprish/herald):
//! canonical serialization, event signing and verification, cross-signing
//! chains, thread-log integrity, and trust-chain evaluation.
//!
//! Every HERALD component consumes this crate — the home server natively, the
//! web client through WebAssembly, mobile clients through `UniFFI` — so that the
//! rules a signature depends on exist exactly once. Two implementations of
//! canonical JSON that disagree by a single byte cannot verify each other's
//! events; keeping that code in one place is the point of this crate.
//!
//! ## Design constraints
//!
//! * **No I/O.** Nothing here opens a socket, touches a clock, or reads a file.
//!   Timestamps arrive as parameters; key material arrives as bytes.
//! * **No operating-system randomness.** Keys are built from caller-supplied
//!   seeds, which keeps the crate free of `getrandom` and therefore buildable
//!   for `wasm32-unknown-unknown` without a JavaScript shim.
//! * **Pure decisions.** Trust evaluation (§6) is a function of explicit state,
//!   so it can be exhaustively tested and shared between server and client.
//!
//! Section references (§) throughout point to the HERALD Protocol
//! Specification v1.1 in `spec/`.
//!
//! ## Example
//!
//! ```
//! use herald_core::{
//!     crypto::PrivateKey,
//!     event::{EventDraft, EventType},
//!     id::{ContextAddress, Gid},
//!     identity::{IdentityBundle, KeyCertificate, KeyPurpose, VerificationLevel},
//! };
//!
//! let gid = Gid::parse("diprish")?;
//! let identity = PrivateKey::from_seed(&[1; 32]);
//! let self_signing = PrivateKey::from_seed(&[2; 32]);
//! let device = PrivateKey::from_seed(&[3; 32]);
//!
//! // Publish a cross-signed key bundle: identity -> self-signing -> device.
//! let bundle = IdentityBundle {
//!     gid: gid.clone(),
//!     level: VerificationLevel::Anchored,
//!     identity_key: identity.public_key(),
//!     self_signing: KeyCertificate::issue(
//!         &identity,
//!         gid.clone(),
//!         "SSK:0001",
//!         KeyPurpose::SelfSigning,
//!         self_signing.public_key(),
//!     )?,
//!     devices: vec![KeyCertificate::issue(
//!         &self_signing,
//!         gid,
//!         "DEVKEY:AB12",
//!         KeyPurpose::Device,
//!         device.public_key(),
//!     )?],
//! };
//!
//! // Sign an event with the device key and verify it against the bundle.
//! let event = EventDraft {
//!     thread_id: "!01J8X2M0AB:herald.deloitte.com".into(),
//!     seq: 1,
//!     prev_event: None,
//!     event_type: EventType::Message,
//!     sender: ContextAddress::parse("diprish:deloitte")?,
//!     origin_server: "herald.deloitte.com".into(),
//!     created_at: "2026-07-21T09:32:00.000Z".into(),
//!     content: serde_json::json!({ "format": "text/herald", "text": "Hello" }),
//!     device_key_id: "DEVKEY:AB12".into(),
//! }
//! .sign(&device)?;
//!
//! event.verify(&bundle)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Every fallible function returns a named error enum whose variants are
// individually documented; restating them per call site is noise, not information.
#![allow(clippy::missing_errors_doc)]

pub mod canonical;
pub mod crypto;
pub mod error;
pub mod event;
pub mod id;
pub mod identity;
pub mod log;
pub mod trust;

pub use canonical::{canonical_hash, canonicalize, CanonicalError};
pub use crypto::{CryptoError, PrivateKey, PublicKey, Signature};
pub use error::ErrorCode;
pub use event::{Event, EventDraft, EventError, EventType};
pub use id::{ContextAddress, ContextName, Gid, HeraldAddress, IdError};
pub use identity::{IdentityBundle, IdentityError, KeyCertificate, KeyPurpose, VerificationLevel};
pub use log::{validate_chain, validate_signed_chain, LogError};
pub use trust::{
    daily_connection_request_cap, evaluate, ConnectionRequest, ContextGrant, Decision, GrantType,
    RecipientPolicy, SenderInfo, TrustGrant, TrustTier,
};

/// The specification version this crate implements.
pub const SPEC_VERSION: &str = "1.1";
