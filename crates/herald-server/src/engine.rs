//! The HERALD Home Server protocol engine.
//!
//! Transport-independent on purpose: this type performs registration, trust
//! evaluation, thread sequencing, log append, and sync entirely over a
//! [`Store`], with no sockets and no clock of its own. The HTTP/WebSocket layer
//! is a thin shell over it, which keeps the protocol rules unit-testable and
//! keeps `herald-cli` able to drive a server in-process.
//!
//! ## Sequencing and signatures
//!
//! Specification §4.2 has the sequencing server assign `seq` and `prev_event`,
//! but §4.1 puts both inside the body the sender's device key signs. The server
//! therefore cannot assign a position after the fact without invalidating the
//! signature. This engine resolves that with optimistic concurrency: a sender
//! reads [`Hhs::head`], builds a draft claiming that position, signs it, and
//! submits. If another event landed first the submission is refused with
//! `SEQ_CONFLICT` and the sender retries against the new head — the same remedy
//! §4.2 already prescribes for divergence. See `docs/architecture/` for the
//! note raising this as a specification question.

use std::collections::BTreeMap;

use herald_core::error::ErrorCode;
use herald_core::event::{Event, EventError};
use herald_core::id::{ContextAddress, Gid};
use herald_core::identity::{IdentityBundle, IdentityError};
use herald_core::trust::{evaluate, Decision, RecipientPolicy, SenderInfo, Timestamp};
use serde::{Deserialize, Serialize};

use crate::store::{Account, Store, StoreError, Thread, ThreadHead, ThreadSummary};

/// Failures the engine reports to a caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServerError {
    /// The identity is not registered with this server.
    #[error("identity {gid} is not registered")]
    UnknownIdentity {
        /// The unregistered identity.
        gid: String,
    },
    /// No such thread.
    #[error("thread {thread_id} does not exist")]
    UnknownThread {
        /// The thread that was requested.
        thread_id: String,
    },
    /// The sender is not a member of the thread.
    #[error("{gid} is not a member of {thread_id}")]
    NotAMember {
        /// The would-be sender.
        gid: String,
        /// The thread they addressed.
        thread_id: String,
    },
    /// A recipient's trust chain refused the delivery (§6.3).
    #[error("{recipient} refused delivery: {code}")]
    TrustDenied {
        /// The recipient that refused.
        recipient: String,
        /// The wire code to report.
        code: ErrorCode,
    },
    /// The event claimed a position the thread has already moved past.
    #[error("thread moved: expected seq {expected}, event claimed {found}")]
    SeqConflict {
        /// The position the thread is at now.
        expected: u64,
        /// The position the event claimed.
        found: u64,
    },
    /// The event failed verification.
    #[error(transparent)]
    Event(#[from] EventError),
    /// The identity bundle failed verification.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The storage backend failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl ServerError {
    /// The wire error code this failure maps to (Appendix A).
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            // A non-member and an unregistered sender both get the generic
            // denial: distinguishing them would be an existence oracle (§6.3).
            Self::UnknownIdentity { .. } | Self::NotAMember { .. } => ErrorCode::TrustDenied,
            Self::UnknownThread { .. } => ErrorCode::GidNotFound,
            Self::TrustDenied { code, .. } => *code,
            Self::Event(_) => ErrorCode::SignatureInvalid,
            Self::Identity(_) => ErrorCode::IdentityInvalid,
            // A storage failure is not the client's fault, but the wire
            // vocabulary of Appendix A has no server-error code; refetching the
            // canonical log is the closest correct remedy to advertise.
            Self::SeqConflict { .. } | Self::Store(_) => ErrorCode::SeqConflict,
        }
    }
}

/// One list in a sliding-sync request (§8.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRequest {
    /// Caller-chosen list name, echoed in the response.
    pub name: String,
    /// Inclusive `[start, end]` window into the ordered thread list.
    pub range: [usize; 2],
}

/// A subscription to one thread's timeline (§8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// How many trailing events to return.
    pub timeline_limit: usize,
}

/// A sliding-sync request. Clients must not full-sync (§8.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRequest {
    /// Windows into the account's thread list.
    #[serde(default)]
    pub lists: Vec<ListRequest>,
    /// Threads whose timelines should be included.
    #[serde(default)]
    pub thread_subscriptions: BTreeMap<String, Subscription>,
}

/// One list in a sliding-sync response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResponse {
    /// The requested list name.
    pub name: String,
    /// Total threads available, so the client can size its scrollbar.
    pub count: usize,
    /// The requested window.
    pub threads: Vec<ThreadSummary>,
}

/// A window of one thread's log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeline {
    /// The `seq` the window starts at.
    pub from_seq: u64,
    /// The events in the window, in order.
    pub events: Vec<Event>,
}

/// A sliding-sync response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResponse {
    /// One entry per requested list.
    pub lists: Vec<ListResponse>,
    /// One entry per subscribed thread the account may see.
    pub threads: BTreeMap<String, Timeline>,
}

/// A HERALD Home Server.
#[derive(Debug)]
pub struct Hhs<S: Store> {
    store: S,
    server_name: String,
    next_thread: u64,
}

impl<S: Store> Hhs<S> {
    /// Creates a server backed by `store`, serving `server_name`.
    #[must_use]
    pub fn new(store: S, server_name: impl Into<String>) -> Self {
        Self {
            store,
            server_name: server_name.into(),
            next_thread: 1,
        }
    }

    /// The server's federation name.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Borrows the backing store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Registers an identity, verifying its cross-signing chain first (§3.6).
    ///
    /// # Errors
    /// Returns [`ServerError::Identity`] if the chain is unsound.
    pub fn register(&mut self, bundle: IdentityBundle) -> Result<(), ServerError> {
        bundle.verify()?;
        self.store.put_identity(bundle)?;
        Ok(())
    }

    /// Replaces an account's contexts and trust policy.
    ///
    /// # Errors
    /// Propagates storage failures.
    pub fn set_account(&mut self, gid: &Gid, account: Account) -> Result<(), ServerError> {
        self.store.put_account(gid, account)?;
        Ok(())
    }

    /// Adds `contact` to `owner`'s contact list, forming Tier 1 trust (§6.1).
    ///
    /// # Errors
    /// Propagates storage failures.
    pub fn add_contact(&mut self, owner: &Gid, contact: &Gid) -> Result<(), ServerError> {
        let mut account = self.store.account(owner)?;
        account.policy.contacts.insert(contact.clone());
        self.store.put_account(owner, account)?;
        Ok(())
    }

    /// Opens a thread, trust-checking the creator against every invitee (§6.3).
    ///
    /// Membership is the admission decision: once a thread exists, its members
    /// may post to it without re-evaluating the trust chain per event, which is
    /// what makes an ongoing conversation cheap.
    ///
    /// # Errors
    /// Returns [`ServerError::TrustDenied`] if any invitee's trust chain refuses
    /// the creator, or [`ServerError::UnknownIdentity`] for unregistered parties.
    pub fn create_thread(
        &mut self,
        creator: &ContextAddress,
        invitees: &[Gid],
        now: Timestamp,
    ) -> Result<String, ServerError> {
        let sender = self.sender_info(creator)?;

        for invitee in invitees {
            if invitee == creator.gid() {
                continue;
            }
            self.require_identity(invitee)?;
            let policy = self.store.account(invitee)?.policy;
            match evaluate(&sender, &policy, None, now) {
                Decision::Admit { .. } => {}
                Decision::Quarantine => {
                    return Err(ServerError::TrustDenied {
                        recipient: invitee.to_string(),
                        code: ErrorCode::TrustDenied,
                    })
                }
                Decision::Reject { code } => {
                    return Err(ServerError::TrustDenied {
                        recipient: invitee.to_string(),
                        code,
                    })
                }
            }
        }

        let thread_id = format!("!{:010}:{}", self.next_thread, self.server_name);
        self.next_thread += 1;

        let mut members = vec![creator.gid().clone()];
        for invitee in invitees {
            if !members.contains(invitee) {
                members.push(invitee.clone());
            }
        }

        self.store.put_thread(Thread {
            thread_id: thread_id.clone(),
            creator: creator.clone(),
            members,
            sequencing_server: self.server_name.clone(),
        })?;
        Ok(thread_id)
    }

    /// The position a new event must claim to extend `thread_id`.
    ///
    /// # Errors
    /// Returns [`ServerError::UnknownThread`] if the thread does not exist.
    pub fn head(&self, thread_id: &str) -> Result<ThreadHead, ServerError> {
        self.require_thread(thread_id)?;
        Ok(self.store.head(thread_id)?)
    }

    /// Accepts an event into a thread: membership, signature, and position are
    /// all checked before it is appended.
    ///
    /// # Errors
    /// Returns [`ServerError::NotAMember`], [`ServerError::Event`] for a bad
    /// signature or id, or [`ServerError::SeqConflict`] if the thread moved.
    pub fn submit(&mut self, event: Event) -> Result<(), ServerError> {
        let thread = self.require_thread(&event.draft.thread_id)?;
        let sender_gid = event.draft.sender.gid();

        if !thread.has_member(sender_gid) {
            return Err(ServerError::NotAMember {
                gid: sender_gid.to_string(),
                thread_id: event.draft.thread_id.clone(),
            });
        }

        let bundle = self.require_identity(sender_gid)?;
        event.verify(&bundle)?;

        let head = self.store.head(&event.draft.thread_id)?;
        if event.draft.seq != head.seq || event.draft.prev_event != head.prev_event {
            return Err(ServerError::SeqConflict {
                expected: head.seq,
                found: event.draft.seq,
            });
        }

        self.store.append_event(event)?;
        Ok(())
    }

    /// Serves a sliding-sync request for `gid` (§8.4).
    ///
    /// Threads the account is not a member of are omitted rather than refused,
    /// so a subscription cannot be used to probe for thread existence.
    ///
    /// # Errors
    /// Propagates storage failures.
    pub fn sync(&self, gid: &Gid, request: &SyncRequest) -> Result<SyncResponse, ServerError> {
        let all = self.store.threads_for(gid)?;

        let mut lists = Vec::with_capacity(request.lists.len());
        for list in &request.lists {
            let [start, end] = list.range;
            let window = if start >= all.len() {
                Vec::new()
            } else {
                all[start..=end.min(all.len() - 1)].to_vec()
            };
            lists.push(ListResponse {
                name: list.name.clone(),
                count: all.len(),
                threads: window,
            });
        }

        let mut threads = BTreeMap::new();
        for (thread_id, subscription) in &request.thread_subscriptions {
            let Some(thread) = self.store.thread(thread_id)? else {
                continue;
            };
            if !thread.has_member(gid) {
                continue;
            }

            let head = self.store.head(thread_id)?;
            let last_seq = head.seq.saturating_sub(1);
            let limit = u64::try_from(subscription.timeline_limit).unwrap_or(u64::MAX);
            let from_seq = last_seq
                .saturating_sub(limit.saturating_sub(1))
                .max(herald_core::log::FIRST_SEQ);

            threads.insert(
                thread_id.clone(),
                Timeline {
                    from_seq,
                    events: self
                        .store
                        .events(thread_id, from_seq, subscription.timeline_limit)?,
                },
            );
        }

        Ok(SyncResponse { lists, threads })
    }

    fn sender_info(&self, address: &ContextAddress) -> Result<SenderInfo, ServerError> {
        let bundle = self.require_identity(address.gid())?;
        let account = self.store.account(address.gid())?;
        Ok(SenderInfo {
            address: address.clone(),
            level: bundle.level,
            contexts: account.contexts,
        })
    }

    fn require_identity(&self, gid: &Gid) -> Result<IdentityBundle, ServerError> {
        self.store
            .identity(gid)?
            .ok_or_else(|| ServerError::UnknownIdentity {
                gid: gid.to_string(),
            })
    }

    fn require_thread(&self, thread_id: &str) -> Result<Thread, ServerError> {
        self.store
            .thread(thread_id)?
            .ok_or_else(|| ServerError::UnknownThread {
                thread_id: thread_id.to_owned(),
            })
    }
}

/// The trust policy an account starts with: nothing is admitted.
#[must_use]
pub fn closed_policy() -> RecipientPolicy {
    RecipientPolicy::default()
}
