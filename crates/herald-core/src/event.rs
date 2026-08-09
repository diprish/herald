//! Thread events: the unit of everything in HERALD (§4.1).
//!
//! An event is signed over the canonical form of its *draft* — every field
//! except `event_id` and `signature`. The `event_id` is then derived from that
//! same canonical form, so it is a verifiable function of the content rather
//! than an assertion the sender makes. A receiver therefore checks two things:
//! that the id matches the body, and that the signature verifies under the
//! device key named in `device_key_id`, resolved through the sender's
//! cross-signing chain (§3.6).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha512};

use crate::canonical::{canonicalize_to_string, CanonicalError};
use crate::crypto::{PrivateKey, Signature};
use crate::id::ContextAddress;
use crate::identity::{IdentityBundle, IdentityError};

/// Number of hex characters of the content hash used in an `event_id`.
const EVENT_ID_HASH_CHARS: usize = 32;

/// The event types defined in §4.1, plus an escape hatch for types this
/// version does not know: unknown events still relay and their ids still
/// verify, which is what lets servers forward future event types unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    /// A message body (§5).
    Message,
    /// Membership change: invite, join, leave, remove.
    Member,
    /// Subject or name change.
    ThreadMeta,
    /// Read marker.
    Read,
    /// Reaction to an event.
    React,
    /// Supersedes a prior event's content.
    Edit,
    /// Blanks a prior event's content, retaining a tombstone.
    Redact,
    /// Identity-recovered notice (§3.7).
    Recovery,
    /// Bridged-content marker (§14).
    Bridge,
    /// A type this implementation does not model.
    Other(String),
}

impl EventType {
    /// The type's wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Message => "h.message",
            Self::Member => "h.member",
            Self::ThreadMeta => "h.thread.meta",
            Self::Read => "h.read",
            Self::React => "h.react",
            Self::Edit => "h.edit",
            Self::Redact => "h.redact",
            Self::Recovery => "h.recovery",
            Self::Bridge => "h.bridge",
            Self::Other(raw) => raw,
        }
    }
}

impl From<&str> for EventType {
    fn from(raw: &str) -> Self {
        match raw {
            "h.message" => Self::Message,
            "h.member" => Self::Member,
            "h.thread.meta" => Self::ThreadMeta,
            "h.read" => Self::Read,
            "h.react" => Self::React,
            "h.edit" => Self::Edit,
            "h.redact" => Self::Redact,
            "h.recovery" => Self::Recovery,
            "h.bridge" => Self::Bridge,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl Serialize for EventType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from(String::deserialize(deserializer)?.as_str()))
    }
}

/// Errors produced while signing or verifying events.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    /// The `event_id` does not match the event's content.
    #[error("event id {found} does not match content (expected {expected})")]
    IdMismatch {
        /// The id carried by the event.
        found: String,
        /// The id derived from its content.
        expected: String,
    },
    /// The signature did not verify under the named device key.
    #[error("signature verification failed for event {event_id}")]
    SignatureInvalid {
        /// The event whose signature failed.
        event_id: String,
    },
    /// The sender's bundle does not contain the device key the event names.
    #[error("device key {device_key_id} is not in the sender's cross-signing chain")]
    UnknownDevice {
        /// The device key id the event named.
        device_key_id: String,
    },
    /// The event's sender is a different identity than the bundle's.
    #[error("event sender {sender} does not match bundle identity {bundle}")]
    SenderMismatch {
        /// The event's sender address.
        sender: String,
        /// The GID of the bundle used for verification.
        bundle: String,
    },
    /// The event body could not be canonicalized (see [`CanonicalError`]).
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// The sender's cross-signing chain is unsound.
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

/// An event that has not been signed yet: every field a signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDraft {
    /// The thread this event belongs to.
    pub thread_id: String,
    /// Monotonic position assigned by the thread's sequencing server (§4.2).
    pub seq: u64,
    /// The id of the preceding event, or `None` for the first event.
    pub prev_event: Option<String>,
    /// The event type.
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// The sending context address.
    pub sender: ContextAddress,
    /// The server that originated the event.
    pub origin_server: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// Type-specific content.
    pub content: Value,
    /// The device key that signs this event.
    pub device_key_id: String,
}

impl EventDraft {
    /// The exact bytes a signature is computed over.
    pub fn signing_payload(&self) -> Result<String, CanonicalError> {
        canonicalize_to_string(self)
    }

    /// Derives the event id this draft would have: `$<hash>:<origin_server>`.
    pub fn event_id(&self) -> Result<String, CanonicalError> {
        let digest = Sha512::digest(self.signing_payload()?.as_bytes());
        let hash = hex::encode(digest);
        Ok(format!(
            "${}:{}",
            &hash[..EVENT_ID_HASH_CHARS],
            self.origin_server
        ))
    }

    /// Signs the draft, producing a complete event.
    pub fn sign(self, device_key: &PrivateKey) -> Result<Event, EventError> {
        let payload = self.signing_payload()?;
        let event_id = self.event_id()?;
        let signature = device_key.sign(payload.as_bytes());
        Ok(Event {
            event_id,
            draft: self,
            signature,
        })
    }
}

/// A signed event (§4.1).
///
/// Serializes flat, matching the wire shape in the specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Content-derived identifier, `$<hash>:<origin_server>`.
    pub event_id: String,
    /// Every signed field.
    #[serde(flatten)]
    pub draft: EventDraft,
    /// Ed25519 signature over the draft's canonical form.
    pub signature: Signature,
}

impl Event {
    /// Recomputes the event id from the body and compares it to the one carried.
    pub fn verify_id(&self) -> Result<(), EventError> {
        let expected = self.draft.event_id()?;
        if expected == self.event_id {
            Ok(())
        } else {
            Err(EventError::IdMismatch {
                found: self.event_id.clone(),
                expected,
            })
        }
    }

    /// Fully verifies the event against the sender's published key material:
    /// the id matches the body, the sender matches the bundle, the bundle's
    /// cross-signing chain is sound, and the signature verifies under the named
    /// device key.
    ///
    /// A conformant client must call this before rendering (§12).
    pub fn verify(&self, sender_bundle: &IdentityBundle) -> Result<(), EventError> {
        if self.draft.sender.gid() != &sender_bundle.gid {
            return Err(EventError::SenderMismatch {
                sender: self.draft.sender.to_string(),
                bundle: sender_bundle.gid.to_string(),
            });
        }
        self.verify_id()?;

        let device_key = sender_bundle
            .device_key(&self.draft.device_key_id)?
            .ok_or_else(|| EventError::UnknownDevice {
                device_key_id: self.draft.device_key_id.clone(),
            })?;

        device_key
            .verify(self.draft.signing_payload()?.as_bytes(), &self.signature)
            .map_err(|_| EventError::SignatureInvalid {
                event_id: self.event_id.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::Gid;
    use crate::identity::{KeyCertificate, KeyPurpose, VerificationLevel};
    use serde_json::json;

    fn bundle_and_device() -> (IdentityBundle, PrivateKey) {
        let gid = Gid::parse("diprish").unwrap();
        let identity = PrivateKey::from_seed(&[1; 32]);
        let self_signing = PrivateKey::from_seed(&[2; 32]);
        let device = PrivateKey::from_seed(&[3; 32]);

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
            devices: vec![KeyCertificate::issue(
                &self_signing,
                gid,
                "DEVKEY:AB12",
                KeyPurpose::Device,
                device.public_key(),
            )
            .unwrap()],
        };
        (bundle, device)
    }

    fn draft() -> EventDraft {
        EventDraft {
            thread_id: "!01J8X2M0AB:herald.deloitte.com".into(),
            seq: 1,
            prev_event: None,
            event_type: EventType::Message,
            sender: ContextAddress::parse("diprish:deloitte").unwrap(),
            origin_server: "herald.deloitte.com".into(),
            created_at: "2026-07-21T09:32:00.000Z".into(),
            content: json!({ "format": "text/herald", "text": "Hello" }),
            device_key_id: "DEVKEY:AB12".into(),
        }
    }

    #[test]
    fn signs_and_verifies() {
        let (bundle, device) = bundle_and_device();
        let event = draft().sign(&device).unwrap();
        assert!(event.verify(&bundle).is_ok());
    }

    #[test]
    fn event_id_is_derived_from_content() {
        let (_, device) = bundle_and_device();
        let event = draft().sign(&device).unwrap();
        assert!(event.event_id.starts_with('$'));
        assert!(event.event_id.ends_with(":herald.deloitte.com"));
        assert_eq!(event.event_id, draft().event_id().unwrap());
    }

    #[test]
    fn event_id_is_stable_across_runs() {
        let (_, device) = bundle_and_device();
        let first = draft().sign(&device).unwrap();
        let second = draft().sign(&device).unwrap();
        assert_eq!(first.event_id, second.event_id);
        assert_eq!(first.signature, second.signature);
    }

    #[test]
    fn detects_tampered_content() {
        let (bundle, device) = bundle_and_device();
        let mut event = draft().sign(&device).unwrap();
        event.draft.content = json!({ "format": "text/herald", "text": "Goodbye" });
        assert!(matches!(
            event.verify(&bundle),
            Err(EventError::IdMismatch { .. })
        ));
    }

    #[test]
    fn detects_tampered_content_even_when_id_is_updated() {
        // Recomputing the id is not enough: the signature still covers the body.
        let (bundle, device) = bundle_and_device();
        let mut event = draft().sign(&device).unwrap();
        event.draft.content = json!({ "format": "text/herald", "text": "Goodbye" });
        event.event_id = event.draft.event_id().unwrap();
        assert!(matches!(
            event.verify(&bundle),
            Err(EventError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn rejects_event_signed_by_an_uncertified_device() {
        let (bundle, _) = bundle_and_device();
        let rogue = PrivateKey::from_seed(&[99; 32]);
        let event = draft().sign(&rogue).unwrap();
        assert!(matches!(
            event.verify(&bundle),
            Err(EventError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn rejects_unknown_device_key_id() {
        let (bundle, device) = bundle_and_device();
        let mut source = draft();
        source.device_key_id = "DEVKEY:GHOST".into();
        let event = source.sign(&device).unwrap();
        assert!(matches!(
            event.verify(&bundle),
            Err(EventError::UnknownDevice { .. })
        ));
    }

    #[test]
    fn rejects_bundle_for_a_different_identity() {
        let (bundle, device) = bundle_and_device();
        let mut source = draft();
        source.sender = ContextAddress::parse("mallory:deloitte").unwrap();
        let event = source.sign(&device).unwrap();
        assert!(matches!(
            event.verify(&bundle),
            Err(EventError::SenderMismatch { .. })
        ));
    }

    #[test]
    fn context_change_changes_the_signature() {
        // diprish:home must not be able to reuse a signature made as
        // diprish:deloitte — the sending context is part of the signed body.
        let (_, device) = bundle_and_device();
        let work = draft().sign(&device).unwrap();
        let mut source = draft();
        source.sender = ContextAddress::parse("diprish:home").unwrap();
        let home = source.sign(&device).unwrap();
        assert_ne!(work.signature, home.signature);
        assert_ne!(work.event_id, home.event_id);
    }

    #[test]
    fn wire_shape_is_flat_and_round_trips() {
        let (bundle, device) = bundle_and_device();
        let event = draft().sign(&device).unwrap();
        let json = serde_json::to_value(&event).unwrap();

        for field in [
            "event_id",
            "thread_id",
            "seq",
            "type",
            "sender",
            "origin_server",
            "created_at",
            "content",
            "device_key_id",
            "signature",
        ] {
            assert!(json.get(field).is_some(), "missing {field}");
        }

        let parsed: Event = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, event);
        assert!(parsed.verify(&bundle).is_ok());
    }

    #[test]
    fn unknown_event_types_survive_round_trip() {
        let (bundle, device) = bundle_and_device();
        let mut source = draft();
        source.event_type = EventType::from("h.offer");
        let event = source.sign(&device).unwrap();

        let parsed: Event = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(parsed.draft.event_type, EventType::Other("h.offer".into()));
        assert!(parsed.verify(&bundle).is_ok());
    }

    #[test]
    fn float_content_is_rejected_at_signing_time() {
        let (_, device) = bundle_and_device();
        let mut source = draft();
        source.content = json!({ "amount": 4.2 });
        assert!(matches!(
            source.sign(&device),
            Err(EventError::Canonical(CanonicalError::FloatNotPermitted(_)))
        ));
    }
}
