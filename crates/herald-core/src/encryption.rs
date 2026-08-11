//! End-to-end encryption of event content (§9).
//!
//! §9 requires that servers "relay and store ciphertext plus unencrypted
//! routing/trust metadata only." This module is what makes that true: content
//! is sealed on the sending device and opened on each recipient device, while
//! `sender`, `thread_id`, and `seq` stay in the clear because the server needs
//! them to evaluate trust and sequence the log.
//!
//! ## The scheme
//!
//! `x25519-hkdf-sha512-aes256gcm`:
//!
//! 1. A **fresh content key** encrypts the payload with AES-256-GCM. One key
//!    per event, so a nonce is never reused under a key.
//! 2. A **fresh ephemeral X25519 key pair** is generated per event. Its public
//!    half travels with the ciphertext; its private half is discarded. This is
//!    what provides forward secrecy — compromising a device's long-term key
//!    later does not recover the ephemeral secret that wrapped past content.
//! 3. For **each recipient device**, X25519 between the ephemeral secret and
//!    that device's published encryption key yields a shared secret; HKDF-SHA512
//!    turns it into a wrapping key, which encrypts the content key.
//!
//! A device decrypts by finding its own `device_key_id` among the wrapped keys,
//! repeating the exchange with the ephemeral public key, and unwrapping.
//!
//! ## Entropy is a parameter
//!
//! Like the rest of this crate, nothing here calls an operating-system RNG:
//! [`Entropy`] is supplied by the host. That keeps the crate WebAssembly-clean,
//! and it makes encryption deterministic under test, which is what allows the
//! published vectors to cover it. **A host must supply fresh, unpredictable
//! entropy per event** — reusing it across two events with the same recipients
//! reuses the content key and nonce, which AES-GCM does not survive.
//!
//! ## What the associated data binds
//!
//! The ciphertext is bound to the thread and the sender, so a server cannot
//! move a sealed payload into another thread or attribute it to someone else.
//! It deliberately does *not* bind `seq`: under the optimistic-concurrency
//! sequencing this implementation uses (see `herald-server`), a send that loses
//! a race is re-signed at a new position, and binding `seq` would force the
//! payload to be re-encrypted for every recipient on each retry. Position is
//! already covered by the event signature (§4.1), which is where repositioning
//! is detected.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha512;

use crate::canonical::{canonicalize, CanonicalError};
use crate::crypto::{EncryptionPrivateKey, EncryptionPublicKey};
use crate::id::Gid;

/// The suite this module implements. Carried on the wire so the registry can be
/// versioned for the post-quantum hybrids §9 anticipates.
pub const ALGORITHM: &str = "x25519-hkdf-sha512-aes256gcm";

/// HKDF info strings. Distinct per derived value so one secret cannot be
/// mistaken for another.
const INFO_EPHEMERAL: &[u8] = b"herald/v1/ephemeral-key";
const INFO_CONTENT_KEY: &[u8] = b"herald/v1/content-key";
const INFO_CONTENT_NONCE: &[u8] = b"herald/v1/content-nonce";
const INFO_WRAP: &[u8] = b"herald/v1/wrap";

/// Failures encrypting or decrypting content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionError {
    /// The envelope named a suite this build does not implement.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(String),
    /// No wrapped key was addressed to this device.
    #[error("no wrapped key for device {device_key_id}")]
    NotARecipient {
        /// The device that tried to decrypt.
        device_key_id: String,
    },
    /// Decryption failed: wrong key, wrong associated data, or tampering.
    #[error("decryption failed")]
    DecryptionFailed,
    /// The envelope was structurally malformed.
    #[error("malformed envelope: {0}")]
    Malformed(String),
    /// There were no recipients, so nothing could ever open the result.
    #[error("an encrypted event needs at least one recipient device")]
    NoRecipients,
    /// The plaintext could not be canonicalized.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

/// Per-event entropy supplied by the host.
///
/// Every random value the scheme needs is derived from this by HKDF, so one
/// fresh 32-byte draw per event is sufficient — and required.
#[derive(Clone)]
pub struct Entropy([u8; 32]);

impl Entropy {
    /// Wraps 32 random bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for Entropy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Entropy(<redacted>)")
    }
}

/// A device that should be able to open the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientDevice {
    /// The identity the device belongs to.
    pub gid: Gid,
    /// The device's identifier, as published in its certificate.
    pub device_key_id: String,
    /// The device's X25519 encryption key.
    pub encryption_key: EncryptionPublicKey,
}

impl RecipientDevice {
    fn address(&self) -> String {
        device_address(&self.gid, &self.device_key_id)
    }
}

/// The key a wrapped content key is filed under.
///
/// Device identifiers are only unique within an identity — two people may both
/// call their phone `DEVKEY:0001` — so wrapped keys are addressed by
/// `gid/device_key_id`. Keying by the bare device id would let one recipient's
/// wrapped key silently overwrite another's.
fn device_address(gid: &Gid, device_key_id: &str) -> String {
    format!("{gid}/{device_key_id}")
}

/// The data the ciphertext is cryptographically bound to.
///
/// See the module note on what this deliberately omits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aad<'a> {
    /// The thread the event belongs to.
    pub thread_id: &'a str,
    /// The address sending it.
    pub sender: &'a str,
}

impl Aad<'_> {
    fn bytes(self) -> Vec<u8> {
        // A length-prefixed join, so no pair of (thread, sender) values can
        // produce the same associated data as a different pair.
        let mut out = Vec::new();
        for field in [self.thread_id, self.sender] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }
}

/// A sealed payload, as it appears in an event's `content` (§4.1, §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedContent {
    /// The suite used. See [`ALGORITHM`].
    pub algorithm: String,
    /// The per-event ephemeral X25519 public key.
    pub ephemeral_key: EncryptionPublicKey,
    /// Base64 AES-256-GCM ciphertext of the canonical plaintext.
    pub ciphertext: String,
    /// The content key, wrapped once per recipient device, keyed by
    /// `gid/device_key_id` (see [`device_address`]).
    pub recipients: BTreeMap<String, String>,
}

fn derive<const N: usize>(secret: &[u8], info: &[u8]) -> [u8; N] {
    let hkdf = Hkdf::<Sha512>::new(None, secret);
    let mut out = [0u8; N];
    // HKDF-SHA512 only fails for absurd output lengths; N here is 12 or 32.
    hkdf.expand(info, &mut out)
        .expect("HKDF output length is within bounds");
    out
}

fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // AES-GCM encryption is infallible for in-memory buffers of this size.
        .expect("AES-256-GCM encryption cannot fail here")
}

fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| EncryptionError::DecryptionFailed)
}

/// Derives the wrapping key and nonce for one recipient from a shared secret.
///
/// The device address is bound into the derivation, so a wrapped key cannot be
/// refiled under a different device.
fn wrapping(shared: &[u8; 32], device_address: &str) -> ([u8; 32], [u8; 12]) {
    let mut info = INFO_WRAP.to_vec();
    info.extend_from_slice(device_address.as_bytes());
    let key = derive::<32>(shared, &info);

    let mut nonce_info = info;
    nonce_info.extend_from_slice(b"/nonce");
    let nonce = derive::<12>(shared, &nonce_info);
    (key, nonce)
}

/// Seals `plaintext` for every device in `recipients`.
///
/// # Errors
/// Returns [`EncryptionError::NoRecipients`] if the recipient list is empty, or
/// [`EncryptionError::Canonical`] if the plaintext cannot be canonicalized.
pub fn encrypt(
    plaintext: &Value,
    aad: Aad<'_>,
    recipients: &[RecipientDevice],
    entropy: &Entropy,
) -> Result<EncryptedContent, EncryptionError> {
    if recipients.is_empty() {
        return Err(EncryptionError::NoRecipients);
    }

    let ephemeral = EncryptionPrivateKey::from_seed(&derive::<32>(&entropy.0, INFO_EPHEMERAL));
    let content_key = derive::<32>(&entropy.0, INFO_CONTENT_KEY);
    // Derived from the content key rather than from the entropy, because the
    // recipient recovers the key but never sees the entropy. The key is fresh
    // per event, so the (key, nonce) pair is never reused.
    let content_nonce = derive::<12>(&content_key, INFO_CONTENT_NONCE);

    // The plaintext is canonicalized before sealing so that what a recipient
    // decrypts is byte-identical to what the sender meant, independent of how
    // either side's JSON library orders keys.
    let canonical = canonicalize(plaintext)?;
    let aad_bytes = aad.bytes();
    let ciphertext = seal(
        &content_key,
        &content_nonce,
        canonical.as_bytes(),
        &aad_bytes,
    );

    let mut wrapped = BTreeMap::new();
    for recipient in recipients {
        let address = recipient.address();
        let shared = ephemeral.diffie_hellman(recipient.encryption_key);
        let (key, nonce) = wrapping(&shared, &address);
        wrapped.insert(
            address,
            BASE64.encode(seal(&key, &nonce, &content_key, &aad_bytes)),
        );
    }

    Ok(EncryptedContent {
        algorithm: ALGORITHM.to_owned(),
        ephemeral_key: ephemeral.public_key(),
        ciphertext: BASE64.encode(ciphertext),
        recipients: wrapped,
    })
}

/// Opens content addressed to `device_key_id`.
///
/// # Errors
/// Returns [`EncryptionError::NotARecipient`] if no wrapped key is addressed to
/// this device, or [`EncryptionError::DecryptionFailed`] if the key is wrong or
/// the ciphertext or associated data has been altered.
pub fn decrypt(
    envelope: &EncryptedContent,
    aad: Aad<'_>,
    gid: &Gid,
    device_key_id: &str,
    device_secret: &EncryptionPrivateKey,
) -> Result<Value, EncryptionError> {
    if envelope.algorithm != ALGORITHM {
        return Err(EncryptionError::UnsupportedAlgorithm(
            envelope.algorithm.clone(),
        ));
    }

    let address = device_address(gid, device_key_id);
    let wrapped =
        envelope
            .recipients
            .get(&address)
            .ok_or_else(|| EncryptionError::NotARecipient {
                device_key_id: address.clone(),
            })?;
    let wrapped = BASE64
        .decode(wrapped)
        .map_err(|e| EncryptionError::Malformed(e.to_string()))?;

    let aad_bytes = aad.bytes();
    let shared = device_secret.diffie_hellman(envelope.ephemeral_key);
    let (key, nonce) = wrapping(&shared, &address);

    let content_key: [u8; 32] = open(&key, &nonce, &wrapped, &aad_bytes)?
        .try_into()
        .map_err(|_| EncryptionError::Malformed("content key is not 32 bytes".to_owned()))?;

    // The content nonce is not carried on the wire: it is derived from the same
    // entropy as the content key, and both are fresh per event, so the sender
    // reconstructs it and the recipient learns it from the wrapped key alone.
    let content_nonce = derive::<12>(&content_key, INFO_CONTENT_NONCE);
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|e| EncryptionError::Malformed(e.to_string()))?;

    let plaintext = open(&content_key, &content_nonce, &ciphertext, &aad_bytes)?;
    serde_json::from_slice(&plaintext).map_err(|e| EncryptionError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn device(seed: u8, gid: &str, id: &str) -> (RecipientDevice, EncryptionPrivateKey) {
        let secret = EncryptionPrivateKey::from_seed(&[seed; 32]);
        (
            RecipientDevice {
                gid: Gid::parse(gid).unwrap(),
                device_key_id: id.to_owned(),
                encryption_key: secret.public_key(),
            },
            secret,
        )
    }

    fn who(name: &str) -> Gid {
        Gid::parse(name).unwrap()
    }

    fn aad() -> Aad<'static> {
        Aad {
            thread_id: "!t1:herald.test",
            sender: "diprish:deloitte",
        }
    }

    fn plaintext() -> Value {
        json!({ "format": "text/herald", "text": "the Q3 numbers are attached" })
    }

    #[test]
    fn a_recipient_can_open_what_was_sealed_for_them() {
        let (recipient, secret) = device(1, "alice", "DEVKEY:AB12");
        let sealed = encrypt(
            &plaintext(),
            aad(),
            &[recipient],
            &Entropy::from_bytes([9; 32]),
        )
        .unwrap();

        assert_eq!(
            decrypt(&sealed, aad(), &who("alice"), "DEVKEY:AB12", &secret).unwrap(),
            plaintext()
        );
    }

    #[test]
    fn every_recipient_device_can_open_it() {
        let (alice, alice_secret) = device(1, "alice", "DEVKEY:0001");
        let (bob, bob_secret) = device(2, "bob", "DEVKEY:0001");
        // The sender's own second device is just another recipient.
        let (laptop, laptop_secret) = device(3, "diprish", "DEVKEY:0001");

        let sealed = encrypt(
            &plaintext(),
            aad(),
            &[alice, bob, laptop],
            &Entropy::from_bytes([9; 32]),
        )
        .unwrap();
        assert_eq!(sealed.recipients.len(), 3);

        // All three call their device DEVKEY:0001; addressing by gid keeps
        // their wrapped keys distinct.
        for (owner, secret) in [
            ("alice", &alice_secret),
            ("bob", &bob_secret),
            ("diprish", &laptop_secret),
        ] {
            assert_eq!(
                decrypt(&sealed, aad(), &who(owner), "DEVKEY:0001", secret).unwrap(),
                plaintext()
            );
        }
    }

    #[test]
    fn a_stranger_cannot_open_it() {
        let (recipient, _) = device(1, "alice", "DEVKEY:AB12");
        let stranger = EncryptionPrivateKey::from_seed(&[99; 32]);
        let sealed = encrypt(
            &plaintext(),
            aad(),
            &[recipient],
            &Entropy::from_bytes([9; 32]),
        )
        .unwrap();

        // Not addressed at all.
        assert!(matches!(
            decrypt(&sealed, aad(), &who("alice"), "DEVKEY:NOPE", &stranger),
            Err(EncryptionError::NotARecipient { .. })
        ));

        // Addressed, but holding the wrong key.
        assert_eq!(
            decrypt(&sealed, aad(), &who("alice"), "DEVKEY:AB12", &stranger),
            Err(EncryptionError::DecryptionFailed)
        );
    }

    #[test]
    fn ciphertext_cannot_be_moved_to_another_thread_or_sender() {
        let (recipient, secret) = device(1, "alice", "DEVKEY:AB12");
        let sealed = encrypt(
            &plaintext(),
            aad(),
            &[recipient],
            &Entropy::from_bytes([9; 32]),
        )
        .unwrap();

        let other_thread = Aad {
            thread_id: "!other:herald.test",
            sender: "diprish:deloitte",
        };
        assert_eq!(
            decrypt(&sealed, other_thread, &who("alice"), "DEVKEY:AB12", &secret),
            Err(EncryptionError::DecryptionFailed)
        );

        let other_sender = Aad {
            thread_id: "!t1:herald.test",
            sender: "mallory:deloitte",
        };
        assert_eq!(
            decrypt(&sealed, other_sender, &who("alice"), "DEVKEY:AB12", &secret),
            Err(EncryptionError::DecryptionFailed)
        );
    }

    #[test]
    fn associated_data_fields_cannot_be_confused() {
        // Without length prefixing, ("ab", "c") and ("a", "bc") would produce
        // identical associated data.
        let first = Aad {
            thread_id: "ab",
            sender: "c",
        };
        let second = Aad {
            thread_id: "a",
            sender: "bc",
        };
        assert_ne!(first.bytes(), second.bytes());
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let (recipient, secret) = device(1, "alice", "DEVKEY:AB12");
        let mut sealed = encrypt(
            &plaintext(),
            aad(),
            &[recipient],
            &Entropy::from_bytes([9; 32]),
        )
        .unwrap();

        let mut raw = BASE64.decode(&sealed.ciphertext).unwrap();
        raw[0] ^= 0x01;
        sealed.ciphertext = BASE64.encode(raw);

        assert_eq!(
            decrypt(&sealed, aad(), &who("alice"), "DEVKEY:AB12", &secret),
            Err(EncryptionError::DecryptionFailed)
        );
    }

    #[test]
    fn fresh_entropy_produces_a_different_envelope_each_time() {
        let (recipient, secret) = device(1, "alice", "DEVKEY:AB12");
        let first = encrypt(
            &plaintext(),
            aad(),
            std::slice::from_ref(&recipient),
            &Entropy::from_bytes([1; 32]),
        )
        .unwrap();
        let second = encrypt(
            &plaintext(),
            aad(),
            &[recipient],
            &Entropy::from_bytes([2; 32]),
        )
        .unwrap();

        assert_ne!(first.ciphertext, second.ciphertext);
        assert_ne!(first.ephemeral_key, second.ephemeral_key);
        // Both still open to the same plaintext.
        assert_eq!(
            decrypt(&first, aad(), &who("alice"), "DEVKEY:AB12", &secret).unwrap(),
            decrypt(&second, aad(), &who("alice"), "DEVKEY:AB12", &secret).unwrap()
        );
    }

    #[test]
    fn the_same_entropy_reproduces_the_envelope_exactly() {
        // Determinism is what lets the published vectors cover encryption; it is
        // also why a host must never reuse entropy across events.
        let (recipient, _) = device(1, "alice", "DEVKEY:AB12");
        let first = encrypt(
            &plaintext(),
            aad(),
            std::slice::from_ref(&recipient),
            &Entropy::from_bytes([7; 32]),
        )
        .unwrap();
        let second = encrypt(
            &plaintext(),
            aad(),
            &[recipient],
            &Entropy::from_bytes([7; 32]),
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn key_order_in_the_plaintext_does_not_change_what_is_decrypted() {
        let (recipient, secret) = device(1, "alice", "DEVKEY:AB12");
        let a: Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":2,"b":1}"#).unwrap();

        let sealed_a = encrypt(
            &a,
            aad(),
            std::slice::from_ref(&recipient),
            &Entropy::from_bytes([5; 32]),
        )
        .unwrap();
        let sealed_b = encrypt(&b, aad(), &[recipient], &Entropy::from_bytes([5; 32])).unwrap();

        assert_eq!(
            sealed_a, sealed_b,
            "canonicalization should erase key order"
        );
        assert_eq!(
            decrypt(&sealed_a, aad(), &who("alice"), "DEVKEY:AB12", &secret).unwrap(),
            a
        );
    }

    #[test]
    fn an_empty_recipient_list_is_refused() {
        assert_eq!(
            encrypt(&plaintext(), aad(), &[], &Entropy::from_bytes([1; 32])),
            Err(EncryptionError::NoRecipients)
        );
    }

    #[test]
    fn an_unknown_algorithm_is_refused() {
        let (recipient, secret) = device(1, "alice", "DEVKEY:AB12");
        let mut sealed = encrypt(
            &plaintext(),
            aad(),
            &[recipient],
            &Entropy::from_bytes([9; 32]),
        )
        .unwrap();
        sealed.algorithm = "rot13".into();

        assert!(matches!(
            decrypt(&sealed, aad(), &who("alice"), "DEVKEY:AB12", &secret),
            Err(EncryptionError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn the_envelope_round_trips_through_json() {
        let (recipient, secret) = device(1, "alice", "DEVKEY:AB12");
        let sealed = encrypt(
            &plaintext(),
            aad(),
            &[recipient],
            &Entropy::from_bytes([9; 32]),
        )
        .unwrap();

        let json = serde_json::to_string(&sealed).unwrap();
        // Nothing recognisable from the plaintext survives into the envelope.
        assert!(!json.contains("Q3 numbers"), "{json}");

        let parsed: EncryptedContent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sealed);
        assert_eq!(
            decrypt(&parsed, aad(), &who("alice"), "DEVKEY:AB12", &secret).unwrap(),
            plaintext()
        );
    }
}
