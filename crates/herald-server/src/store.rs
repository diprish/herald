//! Storage abstraction and an in-memory implementation.
//!
//! The engine talks only to [`Store`], so the durable backend is a swap rather
//! than a rewrite: `SQLite` for a small self-hosted deployment (§11.3),
//! `PostgreSQL` for scale (see `docs/architecture/tech-stack.md` §3). Thread logs
//! shard naturally by `thread_id`, which is why every read here is scoped to
//! one thread.

use std::collections::BTreeMap;

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

/// An in-memory [`Store`], used by tests and by `herald-cli`'s local demo.
#[derive(Debug, Default)]
pub struct MemoryStore {
    identities: BTreeMap<String, IdentityBundle>,
    accounts: BTreeMap<String, Account>,
    threads: BTreeMap<String, Thread>,
    logs: BTreeMap<String, Vec<Event>>,
}

impl MemoryStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn put_identity(&mut self, bundle: IdentityBundle) -> Result<(), StoreError> {
        self.identities.insert(bundle.gid.to_string(), bundle);
        Ok(())
    }

    fn identity(&self, gid: &Gid) -> Result<Option<IdentityBundle>, StoreError> {
        Ok(self.identities.get(gid.as_str()).cloned())
    }

    fn put_account(&mut self, gid: &Gid, account: Account) -> Result<(), StoreError> {
        self.accounts.insert(gid.to_string(), account);
        Ok(())
    }

    fn account(&self, gid: &Gid) -> Result<Account, StoreError> {
        Ok(self.accounts.get(gid.as_str()).cloned().unwrap_or_default())
    }

    fn put_thread(&mut self, thread: Thread) -> Result<(), StoreError> {
        self.logs.entry(thread.thread_id.clone()).or_default();
        self.threads.insert(thread.thread_id.clone(), thread);
        Ok(())
    }

    fn thread(&self, thread_id: &str) -> Result<Option<Thread>, StoreError> {
        Ok(self.threads.get(thread_id).cloned())
    }

    fn append_event(&mut self, event: Event) -> Result<(), StoreError> {
        self.logs
            .entry(event.draft.thread_id.clone())
            .or_default()
            .push(event);
        Ok(())
    }

    fn events(
        &self,
        thread_id: &str,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<Event>, StoreError> {
        Ok(self.logs.get(thread_id).map_or_else(Vec::new, |log| {
            log.iter()
                .filter(|event| event.draft.seq >= from_seq)
                .take(limit)
                .cloned()
                .collect()
        }))
    }

    fn head(&self, thread_id: &str) -> Result<ThreadHead, StoreError> {
        let last = self.logs.get(thread_id).and_then(|log| log.last());
        Ok(match last {
            None => ThreadHead {
                seq: herald_core::log::FIRST_SEQ,
                prev_event: None,
            },
            Some(event) => ThreadHead {
                seq: event.draft.seq + 1,
                prev_event: Some(event.event_id.clone()),
            },
        })
    }

    fn threads_for(&self, gid: &Gid) -> Result<Vec<ThreadSummary>, StoreError> {
        let mut summaries: Vec<ThreadSummary> = self
            .threads
            .values()
            .filter(|thread| thread.has_member(gid))
            .filter_map(|thread| {
                let last = self.logs.get(&thread.thread_id)?.last()?;
                Some(ThreadSummary {
                    thread_id: thread.thread_id.clone(),
                    last_seq: last.draft.seq,
                    last_activity: last.draft.created_at.clone(),
                })
            })
            .collect();

        // Most recent first; ties broken by id so ordering is deterministic.
        summaries.sort_by(|a, b| {
            b.last_activity
                .cmp(&a.last_activity)
                .then_with(|| a.thread_id.cmp(&b.thread_id))
        });
        Ok(summaries)
    }
}
