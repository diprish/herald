//! # herald-server
//!
//! The HERALD Home Server: trust evaluation, thread sequencing, log append, and
//! sliding sync, built on [`herald_core`].
//!
//! The engine ([`Hhs`]) is transport-independent — no sockets, no clock, no
//! ambient state — so the protocol rules stay unit-testable and a client can
//! drive a server in-process. Persistence sits behind the [`Store`] trait, with
//! [`MemoryStore`] as the reference implementation used by tests.
//!
//! Section references (§) point to the HERALD Protocol Specification v1.1 in
//! `spec/`.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Every fallible function returns a named error enum whose variants are
// individually documented; restating them per call site is noise, not information.
#![allow(clippy::missing_errors_doc)]

pub mod api;
pub mod engine;
pub mod store;

pub use api::{router, AppState, ClientFrame, ServerFrame, SUPPORTED_VERSIONS};
pub use engine::{
    Hhs, ListRequest, ListResponse, ServerError, Subscription, SyncRequest, SyncResponse, Timeline,
};
pub use store::{
    Account, MemoryStore, SqliteStore, Store, StoreError, Thread, ThreadHead, ThreadSummary,
};
