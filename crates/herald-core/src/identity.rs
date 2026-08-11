//! Verification levels and the cross-signing key chain (§3.4, §3.6).
//!
//! The chain is `identity key -> self-signing key -> device key`. A counterparty
//! that has verified the identity key once accepts every device the user later
//! adds, because each device certificate is signed by the self-signing key,
//! which the identity key vouches for. That is what makes "verify once, chain
//! thereafter" possible (§3.6).

use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalize_to_string, CanonicalError};
use crate::crypto::{CryptoError, EncryptionPublicKey, PrivateKey, PublicKey, Signature};
use crate::encryption::RecipientDevice;
use crate::id::Gid;

/// A GID's verification level (§3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// Instant self-registration. May message mutual contacts only; cannot send
    /// Connection Requests; cannot receive organizational contexts.
    #[serde(rename = "0")]
    Unverified,
    /// Anchored by an external verification (org grant, national eID, bank KYC).
    #[serde(rename = "1")]
    Anchored,
    /// Registry-verified and deduplicated against the global registry.
    #[serde(rename = "2")]
    RegistryVerified,
    /// A bridge shadow identity (§14.1). Never sends Connection Requests and
    /// exists only inside threads a real user initiated or accepted.
    #[serde(rename = "B")]
    Bridged,
}

impl VerificationLevel {
    /// Whether this level may participate in the full trust tiers (§3.4).
    #[must_use]
    pub const fn can_send_connection_requests(self) -> bool {
        matches!(self, Self::Anchored | Self::RegistryVerified)
    }

    /// Whether this level may operate a Context Authority (§3.4, §3.9).
    #[must_use]
    pub const fn can_issue_context_grants(self) -> bool {
        matches!(self, Self::RegistryVerified)
    }
}

/// What a certified key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// The self-signing key, certified by the identity key.
    #[serde(rename = "self-signing")]
    SelfSigning,
    /// A device key, certified by the self-signing key.
    #[serde(rename = "device")]
    Device,
}

/// Errors produced while validating a cross-signing chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// A certificate's signature did not verify against its issuer.
    #[error("certificate {key_id} failed verification")]
    BadCertificate {
        /// The certified key's identifier.
        key_id: String,
    },
    /// A certificate bound a different GID than the bundle it appeared in.
    #[error("certificate {key_id} is bound to {found}, expected {expected}")]
    GidMismatch {
        /// The certified key's identifier.
        key_id: String,
        /// The GID named in the certificate.
        found: String,
        /// The GID of the bundle.
        expected: String,
    },
    /// A certificate declared the wrong purpose for its position in the chain.
    #[error("certificate {key_id} has the wrong purpose for its position")]
    WrongPurpose {
        /// The certified key's identifier.
        key_id: String,
    },
    /// A device certificate carried no encryption key, so nothing could be
    /// encrypted to that device.
    #[error("device certificate {key_id} has no encryption key")]
    MissingEncryptionKey {
        /// The device missing a key.
        key_id: String,
    },
    /// A non-device certificate carried an encryption key.
    #[error("certificate {key_id} carries an encryption key but is not a device")]
    UnexpectedEncryptionKey {
        /// The offending certificate.
        key_id: String,
    },
    /// Two device certificates claimed the same key id.
    #[error("duplicate device key id {key_id}")]
    DuplicateDevice {
        /// The repeated identifier.
        key_id: String,
    },
    /// The certificate could not be canonicalized for verification.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// A key or signature was malformed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The signed body of a key certificate. Signatures are computed over this
/// structure's canonical form, never over the enclosing certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CertificateBody {
    gid: Gid,
    key_id: String,
    purpose: KeyPurpose,
    subject_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption_key: Option<EncryptionPublicKey>,
}

/// A key certified by another key in the cross-signing chain (§3.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCertificate {
    /// The identity this key belongs to.
    pub gid: Gid,
    /// Stable identifier for the certified key, e.g. `DEVKEY:AB12`.
    pub key_id: String,
    /// What the certified key is used for.
    pub purpose: KeyPurpose,
    /// The certified Ed25519 key.
    pub subject_key: PublicKey,
    /// The device's X25519 encryption key (§9).
    ///
    /// Required on device certificates and absent everywhere else: certifying
    /// both keys together is what lets a counterparty who trusts a device to
    /// *sign* also know where to *encrypt* for it, with no extra verification
    /// step (§3.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<EncryptionPublicKey>,
    /// Signature by the issuing key over the certificate body.
    pub signature: Signature,
}

impl KeyCertificate {
    /// Issues a certificate, signing the body with `issuer`.
    pub fn issue(
        issuer: &PrivateKey,
        gid: Gid,
        key_id: impl Into<String>,
        purpose: KeyPurpose,
        subject_key: PublicKey,
    ) -> Result<Self, IdentityError> {
        Self::issue_with_encryption(issuer, gid, key_id, purpose, subject_key, None)
    }

    /// Issues a device certificate that also publishes an encryption key (§9).
    ///
    /// # Errors
    /// Propagates canonicalization failures.
    pub fn issue_device(
        issuer: &PrivateKey,
        gid: Gid,
        key_id: impl Into<String>,
        subject_key: PublicKey,
        encryption_key: EncryptionPublicKey,
    ) -> Result<Self, IdentityError> {
        Self::issue_with_encryption(
            issuer,
            gid,
            key_id,
            KeyPurpose::Device,
            subject_key,
            Some(encryption_key),
        )
    }

    fn issue_with_encryption(
        issuer: &PrivateKey,
        gid: Gid,
        key_id: impl Into<String>,
        purpose: KeyPurpose,
        subject_key: PublicKey,
        encryption_key: Option<EncryptionPublicKey>,
    ) -> Result<Self, IdentityError> {
        let key_id = key_id.into();
        let body = CertificateBody {
            gid: gid.clone(),
            key_id: key_id.clone(),
            purpose,
            subject_key,
            encryption_key,
        };
        let signature = issuer.sign(canonicalize_to_string(&body)?.as_bytes());
        Ok(Self {
            gid,
            key_id,
            purpose,
            subject_key,
            encryption_key,
            signature,
        })
    }

    /// Verifies this certificate against the key that should have issued it.
    pub fn verify(&self, issuer: PublicKey) -> Result<(), IdentityError> {
        let body = CertificateBody {
            gid: self.gid.clone(),
            key_id: self.key_id.clone(),
            purpose: self.purpose,
            subject_key: self.subject_key,
            encryption_key: self.encryption_key,
        };
        issuer
            .verify(canonicalize_to_string(&body)?.as_bytes(), &self.signature)
            .map_err(|_| IdentityError::BadCertificate {
                key_id: self.key_id.clone(),
            })
    }
}

/// A GID's published key material: the identity key, its self-signing key, and
/// every device certified under it (§3.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBundle {
    /// The identity this bundle describes.
    pub gid: Gid,
    /// The registry's recorded verification level (§3.4).
    pub level: VerificationLevel,
    /// The root identity key.
    pub identity_key: PublicKey,
    /// The self-signing key, certified by `identity_key`.
    pub self_signing: KeyCertificate,
    /// Device keys, each certified by the self-signing key.
    pub devices: Vec<KeyCertificate>,
}

impl IdentityBundle {
    /// Verifies the whole chain: the self-signing certificate against the
    /// identity key, and every device certificate against the self-signing key.
    pub fn verify(&self) -> Result<(), IdentityError> {
        if self.self_signing.purpose != KeyPurpose::SelfSigning {
            return Err(IdentityError::WrongPurpose {
                key_id: self.self_signing.key_id.clone(),
            });
        }
        if self.self_signing.encryption_key.is_some() {
            return Err(IdentityError::UnexpectedEncryptionKey {
                key_id: self.self_signing.key_id.clone(),
            });
        }
        self.check_gid(&self.self_signing)?;
        self.self_signing.verify(self.identity_key)?;

        let mut seen = std::collections::HashSet::new();
        for device in &self.devices {
            if device.purpose != KeyPurpose::Device {
                return Err(IdentityError::WrongPurpose {
                    key_id: device.key_id.clone(),
                });
            }
            if device.encryption_key.is_none() {
                return Err(IdentityError::MissingEncryptionKey {
                    key_id: device.key_id.clone(),
                });
            }
            self.check_gid(device)?;
            if !seen.insert(device.key_id.as_str()) {
                return Err(IdentityError::DuplicateDevice {
                    key_id: device.key_id.clone(),
                });
            }
            device.verify(self.self_signing.subject_key)?;
        }
        Ok(())
    }

    /// Resolves a device key id to its public key, verifying the chain first.
    ///
    /// Returns `Ok(None)` when the chain is sound but names no such device.
    pub fn device_key(&self, key_id: &str) -> Result<Option<PublicKey>, IdentityError> {
        self.verify()?;
        Ok(self
            .devices
            .iter()
            .find(|device| device.key_id == key_id)
            .map(|device| device.subject_key))
    }

    /// Every device that can receive encrypted content, after verifying the
    /// chain (§9).
    ///
    /// This is the "fanned out through the cross-signing chain" step: a sender
    /// asks a recipient's published bundle where to encrypt, and gets an answer
    /// only if the chain is sound.
    ///
    /// # Errors
    /// Returns an error if the cross-signing chain does not verify.
    pub fn recipient_devices(&self) -> Result<Vec<RecipientDevice>, IdentityError> {
        self.verify()?;
        self.devices
            .iter()
            .map(|device| {
                Ok(RecipientDevice {
                    gid: self.gid.clone(),
                    device_key_id: device.key_id.clone(),
                    encryption_key: device.encryption_key.ok_or_else(|| {
                        IdentityError::MissingEncryptionKey {
                            key_id: device.key_id.clone(),
                        }
                    })?,
                })
            })
            .collect()
    }

    fn check_gid(&self, certificate: &KeyCertificate) -> Result<(), IdentityError> {
        if certificate.gid == self.gid {
            Ok(())
        } else {
            Err(IdentityError::GidMismatch {
                key_id: certificate.key_id.clone(),
                found: certificate.gid.to_string(),
                expected: self.gid.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        bundle: IdentityBundle,
        device: PrivateKey,
    }

    fn fixture() -> Fixture {
        let gid = Gid::parse("diprish").unwrap();
        let identity = PrivateKey::from_seed(&[1; 32]);
        let self_signing = PrivateKey::from_seed(&[2; 32]);
        let device = PrivateKey::from_seed(&[3; 32]);
        let device_encryption = crate::crypto::EncryptionPrivateKey::from_seed(&[4; 32]);

        let self_signing_cert = KeyCertificate::issue(
            &identity,
            gid.clone(),
            "SSK:0001",
            KeyPurpose::SelfSigning,
            self_signing.public_key(),
        )
        .unwrap();
        let device_cert = KeyCertificate::issue_device(
            &self_signing,
            gid.clone(),
            "DEVKEY:AB12",
            device.public_key(),
            device_encryption.public_key(),
        )
        .unwrap();

        Fixture {
            bundle: IdentityBundle {
                gid,
                level: VerificationLevel::Anchored,
                identity_key: identity.public_key(),
                self_signing: self_signing_cert,
                devices: vec![device_cert],
            },
            device,
        }
    }

    #[test]
    fn verifies_a_sound_chain() {
        let fixture = fixture();
        assert!(fixture.bundle.verify().is_ok());
        assert_eq!(
            fixture.bundle.device_key("DEVKEY:AB12").unwrap(),
            Some(fixture.device.public_key())
        );
    }

    #[test]
    fn unknown_device_resolves_to_none() {
        assert_eq!(fixture().bundle.device_key("DEVKEY:NOPE").unwrap(), None);
    }

    #[test]
    fn rejects_device_signed_by_the_wrong_key() {
        let mut fixture = fixture();
        let impostor = PrivateKey::from_seed(&[9; 32]);
        fixture.bundle.devices[0] = KeyCertificate::issue_device(
            &impostor,
            fixture.bundle.gid.clone(),
            "DEVKEY:AB12",
            impostor.public_key(),
            crate::crypto::EncryptionPrivateKey::from_seed(&[11; 32]).public_key(),
        )
        .unwrap();
        assert!(matches!(
            fixture.bundle.verify(),
            Err(IdentityError::BadCertificate { .. })
        ));
    }

    #[test]
    fn rejects_self_signing_key_not_signed_by_identity() {
        let mut fixture = fixture();
        let impostor = PrivateKey::from_seed(&[10; 32]);
        fixture.bundle.self_signing = KeyCertificate::issue(
            &impostor,
            fixture.bundle.gid.clone(),
            "SSK:0001",
            KeyPurpose::SelfSigning,
            impostor.public_key(),
        )
        .unwrap();
        assert!(matches!(
            fixture.bundle.verify(),
            Err(IdentityError::BadCertificate { .. })
        ));
    }

    #[test]
    fn rejects_certificate_borrowed_from_another_identity() {
        // A certificate is bound to its GID, so it cannot be lifted into
        // another person's bundle even though its signature is genuine.
        let mut fixture = fixture();
        let other_gid = Gid::parse("mallory").unwrap();
        let self_signing = PrivateKey::from_seed(&[2; 32]);
        fixture.bundle.devices[0] = KeyCertificate::issue_device(
            &self_signing,
            other_gid,
            "DEVKEY:AB12",
            PrivateKey::from_seed(&[3; 32]).public_key(),
            crate::crypto::EncryptionPrivateKey::from_seed(&[4; 32]).public_key(),
        )
        .unwrap();
        assert!(matches!(
            fixture.bundle.verify(),
            Err(IdentityError::GidMismatch { .. })
        ));
    }

    #[test]
    fn rejects_purpose_confusion() {
        let mut fixture = fixture();
        let self_signing = PrivateKey::from_seed(&[2; 32]);
        fixture.bundle.devices[0] = KeyCertificate::issue(
            &self_signing,
            fixture.bundle.gid.clone(),
            "DEVKEY:AB12",
            KeyPurpose::SelfSigning,
            PrivateKey::from_seed(&[3; 32]).public_key(),
        )
        .unwrap();
        assert!(matches!(
            fixture.bundle.verify(),
            Err(IdentityError::WrongPurpose { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_device_ids() {
        let mut fixture = fixture();
        let duplicate = fixture.bundle.devices[0].clone();
        fixture.bundle.devices.push(duplicate);
        assert!(matches!(
            fixture.bundle.verify(),
            Err(IdentityError::DuplicateDevice { .. })
        ));
    }

    #[test]
    fn level_capabilities_follow_the_spec() {
        assert!(!VerificationLevel::Unverified.can_send_connection_requests());
        assert!(VerificationLevel::Anchored.can_send_connection_requests());
        assert!(!VerificationLevel::Anchored.can_issue_context_grants());
        assert!(VerificationLevel::RegistryVerified.can_issue_context_grants());
        assert!(!VerificationLevel::Bridged.can_send_connection_requests());
    }
}
