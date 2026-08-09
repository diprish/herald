//! Storage abstraction and an in-memory implementation.
//!
//! The engine talks only to [`Store`], so the durable backend is a swap rather
//! than a rewrite: `SQLite` for a small self-hosted deployment (§11.3),
//! `PostgreSQL` for scale (see `docs/architecture/tech-stack.md` §3). Thread logs
//! shard naturally by `thread_id`, which is why every read here is scoped to
//! one thread.
//!
//! Two backends ship today: [`MemoryStore`] for tests and the in-process demo,
//! and [`SqliteStore`] for a durable single-node deployment. Both are held to
//! the same behaviour by `tests/store_conformance.rs`.

use herald_core::event::Event;
use herald_core::id::{ContextAddress, Gid};
use herald_core::identity::IdentityBundle;
use herald_core::trust::{ContextGrant, RecipientPolicy};
use serde::{Deserialize, Serialize};

/// Failures a storage backend can report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The backend rejected an operation.
    #[error("storage failure: {0}")]
    Backend(String),
}

/// A thread's membership and sequencing metadata (§4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    /// Thread identifier, `!<id>:<server>`.
    pub thread_id: String,
    /// The address that created the thread.
    pub creator: ContextAddress,
    /// Identities admitted to the thread.
    pub members: Vec<Gid>,
    /// The server that assigns `seq` for this thread.
    pub sequencing_server: String,
}

impl Thread {
    /// Whether `gid` is a member.
    #[must_use]
    pub fn has_member(&self, gid: &Gid) -> bool {
        self.members.iter().any(|member| member == gid)
    }
}

/// The position a new event must claim to extend a thread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadHead {
    /// The `seq` the next event must carry.
    pub seq: u64,
    /// The `prev_event` the next event must link to.
    pub prev_event: Option<String>,
}

/// A thread as it appears in a sync list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadSummary {
    /// Thread identifier.
    pub thread_id: String,
    /// Sequence number of the most recent event.
    pub last_seq: u64,
    /// `created_at` of the most recent event, used for recency ordering.
    pub last_activity: String,
}

/// What an account's registration holds beyond its key bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Context grants the identity holds (§3.9).
    pub contexts: Vec<ContextGrant>,
    /// The trust state inbound deliveries are evaluated against (§6).
    pub policy: RecipientPolicy,
}

/// Everything the engine needs to persist.
pub trait Store {
    /// Records a verified identity bundle.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn put_identity(&mut self, bundle: IdentityBundle) -> Result<(), StoreError>;

    /// Fetches a published identity bundle.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn identity(&self, gid: &Gid) -> Result<Option<IdentityBundle>, StoreError>;

    /// Replaces an account's contexts and trust policy.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn put_account(&mut self, gid: &Gid, account: Account) -> Result<(), StoreError>;

    /// Fetches an account, or the default (no contexts, no trust) if absent.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn account(&self, gid: &Gid) -> Result<Account, StoreError>;

    /// Reserves the next thread number for this server.
    ///
    /// Thread identifiers must never be reused, so the counter lives with the
    /// data rather than in the engine: a server restart against a durable store
    /// would otherwise hand out identifiers that already exist.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn allocate_thread_number(&mut self) -> Result<u64, StoreError>;

    /// Creates a thread.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn put_thread(&mut self, thread: Thread) -> Result<(), StoreError>;

    /// Fetches a thread's metadata.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn thread(&self, thread_id: &str) -> Result<Option<Thread>, StoreError>;

    /// Appends an event to a thread's log.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn append_event(&mut self, event: Event) -> Result<(), StoreError>;

    /// Reads a window of a thread's log starting at `from_seq`.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn events(
        &self,
        thread_id: &str,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<Event>, StoreError>;

    /// The position a new event must claim.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn head(&self, thread_id: &str) -> Result<ThreadHead, StoreError>;

    /// Threads `gid` belongs to, most recently active first.
    ///
    /// # Errors
    /// Propagates backend failures.
    fn threads_for(&self, gid: &Gid) -> Result<Vec<ThreadSummary>, StoreError>;
}

/// Allocates thread numbers, and everything else the engine must persist.
///
/// Implementations live in [`memory`] and [`sqlite`].
pub mod memory;
pub mod sqlite;

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;
