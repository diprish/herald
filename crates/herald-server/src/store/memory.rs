//! An in-memory [`Store`](super::Store): no durability, no dependencies.

use std::collections::BTreeMap;

use herald_core::event::Event;
use herald_core::id::Gid;
use herald_core::identity::IdentityBundle;

use super::{Account, Store, StoreError, Thread, ThreadHead, ThreadSummary};

/// An in-memory [`Store`], used by tests and by `herald-cli`'s local demo.
#[derive(Debug, Default)]
pub struct MemoryStore {
    next_thread: u64,
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

    fn allocate_thread_number(&mut self) -> Result<u64, StoreError> {
        self.next_thread += 1;
        Ok(self.next_thread)
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
