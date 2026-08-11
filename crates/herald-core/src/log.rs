//! Thread log integrity (§4.2).
//!
//! HERALD threads have closed, trust-checked membership, so the specification
//! deliberately avoids Byzantine state resolution: a thread is a linear log
//! sequenced by one server, and divergence is *detected* rather than merged.
//! This module is that detection — a broken `seq` run or `prev_event` link is
//! a [`ErrorCode::SeqConflict`], whose remedy is refetching the canonical log.

use crate::error::ErrorCode;
use crate::event::{Event, EventError};
use crate::id::Gid;
use crate::identity::IdentityBundle;

/// The `seq` the first event of a thread carries.
pub const FIRST_SEQ: u64 = 1;

/// Ways a thread log can fail validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// Events from more than one thread were presented as a single log.
    #[error("event at seq {seq} belongs to thread {found}, expected {expected}")]
    ThreadMismatch {
        /// Position of the offending event.
        seq: u64,
        /// The thread the event claims.
        found: String,
        /// The thread being validated.
        expected: String,
    },
    /// The sequence numbers are not a contiguous ascending run.
    #[error("expected seq {expected}, found {found}")]
    SeqGap {
        /// The sequence number required at this position.
        expected: u64,
        /// The sequence number present.
        found: u64,
    },
    /// An event's back-link does not name its predecessor.
    #[error("event at seq {seq} links to {found:?}, expected {expected:?}")]
    BrokenLink {
        /// Position of the offending event.
        seq: u64,
        /// The link the event carries.
        found: Option<String>,
        /// The link it should carry.
        expected: Option<String>,
    },
    /// An event failed signature or id verification.
    #[error(transparent)]
    Event(#[from] EventError),
}

impl LogError {
    /// The wire error code this failure maps to (Appendix A).
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::ThreadMismatch { .. } | Self::SeqGap { .. } | Self::BrokenLink { .. } => {
                ErrorCode::SeqConflict
            }
            Self::Event(_) => ErrorCode::SignatureInvalid,
        }
    }
}

/// Validates the hash chain and sequence run of a log slice.
///
/// The slice must start at the thread's first event. An empty slice is
/// vacuously valid. This checks structure only; use
/// [`validate_signed_chain`] to also verify every signature.
pub fn validate_chain(events: &[Event]) -> Result<(), LogError> {
    validate_chain_from(events, FIRST_SEQ, None)
}

/// Validates a log window that begins partway through a thread.
///
/// `start_seq` is the sequence number the first event of `events` must carry,
/// and `preceding_event_id` is the id of the event immediately before it
/// (`None` when the window starts at the beginning of the thread). This is what
/// a client uses when backfilling a sliding-sync window (§8.4).
pub fn validate_chain_from(
    events: &[Event],
    start_seq: u64,
    preceding_event_id: Option<&str>,
) -> Result<(), LogError> {
    let Some(first) = events.first() else {
        return Ok(());
    };
    let thread_id = first.draft.thread_id.as_str();

    let mut expected_link = preceding_event_id.map(str::to_owned);

    for (expected_seq, event) in (start_seq..).zip(events) {
        if event.draft.thread_id != thread_id {
            return Err(LogError::ThreadMismatch {
                seq: event.draft.seq,
                found: event.draft.thread_id.clone(),
                expected: thread_id.to_owned(),
            });
        }
        if event.draft.seq != expected_seq {
            return Err(LogError::SeqGap {
                expected: expected_seq,
                found: event.draft.seq,
            });
        }
        if event.draft.prev_event != expected_link {
            return Err(LogError::BrokenLink {
                seq: event.draft.seq,
                found: event.draft.prev_event.clone(),
                expected: expected_link,
            });
        }

        expected_link = Some(event.event_id.clone());
    }
    Ok(())
}

/// Validates structure as [`validate_chain`] does, and additionally verifies
/// every event's id and signature against the sender's key bundle.
///
/// `resolve` maps a sender's GID to their published bundle; an event whose
/// sender cannot be resolved is rejected rather than skipped.
pub fn validate_signed_chain<'a, F>(events: &[Event], mut resolve: F) -> Result<(), LogError>
where
    F: FnMut(&Gid) -> Option<&'a IdentityBundle>,
{
    validate_chain(events)?;
    for event in events {
        let gid = event.draft.sender.gid();
        let bundle = resolve(gid).ok_or_else(|| {
            LogError::Event(EventError::SenderMismatch {
                sender: event.draft.sender.to_string(),
                bundle: "<unresolved>".to_owned(),
            })
        })?;
        event.verify(bundle)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::event::{EventDraft, EventType};
    use crate::id::ContextAddress;
    use crate::identity::{KeyCertificate, KeyPurpose, VerificationLevel};
    use serde_json::json;

    fn bundle_and_device() -> (IdentityBundle, PrivateKey) {
        let gid = Gid::parse("diprish").unwrap();
        let identity = PrivateKey::from_seed(&[1; 32]);
        let self_signing = PrivateKey::from_seed(&[2; 32]);
        let device = PrivateKey::from_seed(&[3; 32]);
        let device_encryption = crate::crypto::EncryptionPrivateKey::from_seed(&[4; 32]);
        let bundle = IdentityBundle {
            gid: gid.clone(),
            level: VerificationLevel::Anchored,
            identity_key: identity.public_key(),
            self_signing: KeyCertificate::issue(
                &identity,
                gid.clone(),
                "SSK:0001",
                KeyPurpose::SelfSigning,
                self_signing.public_key(),
            )
            .unwrap(),
            devices: vec![KeyCertificate::issue_device(
                &self_signing,
                gid,
                "DEVKEY:AB12",
                device.public_key(),
                device_encryption.public_key(),
            )
            .unwrap()],
        };
        (bundle, device)
    }

    fn chain(len: u64) -> Vec<Event> {
        let (_, device) = bundle_and_device();
        let mut events: Vec<Event> = Vec::new();
        for seq in FIRST_SEQ..=len {
            let draft = EventDraft {
                thread_id: "!thread:herald.example.com".into(),
                seq,
                prev_event: events.last().map(|e: &Event| e.event_id.clone()),
                event_type: EventType::Message,
                sender: ContextAddress::parse("diprish:deloitte").unwrap(),
                origin_server: "herald.example.com".into(),
                created_at: format!("2026-07-21T09:3{seq}:00.000Z"),
                content: json!({ "text": format!("message {seq}") }),
                device_key_id: "DEVKEY:AB12".into(),
            };
            events.push(draft.sign(&device).unwrap());
        }
        events
    }

    #[test]
    fn empty_log_is_valid() {
        assert!(validate_chain(&[]).is_ok());
    }

    #[test]
    fn well_formed_chain_validates() {
        assert!(validate_chain(&chain(5)).is_ok());
    }

    #[test]
    fn signed_chain_validates() {
        let (bundle, _) = bundle_and_device();
        assert!(validate_signed_chain(&chain(3), |_| Some(&bundle)).is_ok());
    }

    #[test]
    fn detects_missing_event() {
        let mut events = chain(4);
        events.remove(2);
        let error = validate_chain(&events).unwrap_err();
        assert!(matches!(
            error,
            LogError::SeqGap {
                expected: 3,
                found: 4
            }
        ));
        assert_eq!(error.error_code(), ErrorCode::SeqConflict);
    }

    #[test]
    fn detects_broken_back_link() {
        let mut events = chain(3);
        events[2].draft.prev_event = Some("$forged:herald.example.com".into());
        assert!(matches!(
            validate_chain(&events),
            Err(LogError::BrokenLink { seq: 3, .. })
        ));
    }

    #[test]
    fn detects_genesis_event_with_a_link() {
        let mut events = chain(1);
        events[0].draft.prev_event = Some("$ghost:herald.example.com".into());
        assert!(matches!(
            validate_chain(&events),
            Err(LogError::BrokenLink { seq: 1, .. })
        ));
    }

    #[test]
    fn detects_events_from_another_thread() {
        let mut events = chain(2);
        events[1].draft.thread_id = "!other:herald.example.com".into();
        assert!(matches!(
            validate_chain(&events),
            Err(LogError::ThreadMismatch { seq: 2, .. })
        ));
    }

    #[test]
    fn detects_reordering() {
        let mut events = chain(3);
        events.swap(1, 2);
        assert!(matches!(
            validate_chain(&events),
            Err(LogError::SeqGap { .. })
        ));
    }

    #[test]
    fn window_validates_from_an_offset() {
        let events = chain(5);
        let window = &events[2..];
        assert!(validate_chain_from(window, 3, Some(&events[1].event_id)).is_ok());
    }

    #[test]
    fn window_rejects_wrong_preceding_link() {
        let events = chain(5);
        let window = &events[2..];
        assert!(matches!(
            validate_chain_from(window, 3, Some("$wrong:herald.example.com")),
            Err(LogError::BrokenLink { seq: 3, .. })
        ));
    }

    #[test]
    fn signed_chain_rejects_tampering() {
        let (bundle, _) = bundle_and_device();
        let mut events = chain(3);
        events[1].draft.content = json!({ "text": "tampered" });
        // Relink so the structural check passes and only signing catches it.
        events[1].event_id = events[1].draft.event_id().unwrap();
        events[2].draft.prev_event = Some(events[1].event_id.clone());
        events[2].event_id = events[2].draft.event_id().unwrap();

        assert!(matches!(
            validate_signed_chain(&events, |_| Some(&bundle)),
            Err(LogError::Event(_))
        ));
    }

    #[test]
    fn signed_chain_rejects_unresolvable_sender() {
        assert!(validate_signed_chain(&chain(1), |_| None).is_err());
    }
}
