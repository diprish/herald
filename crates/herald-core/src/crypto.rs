//! Ed25519 signing primitives (specification §9).
//!
//! Keys are constructed from caller-supplied 32-byte seeds rather than an
//! operating-system RNG. That keeps this crate free of `getrandom`, which is
//! what allows the same code to compile to `wasm32-unknown-unknown` without a
//! JavaScript shim; key *generation* belongs to the host (server, client app,
//! or hardware-backed store per §12), not to the protocol core.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors produced by key handling and signature verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// Key or signature bytes were not valid hex, or not the expected length.
    #[error("malformed {kind}: {reason}")]
    Malformed {
        /// What was being decoded (`public key`, `signature`, ...).
        kind: &'static str,
        /// Why it failed.
        reason: String,
    },
    /// The signature did not verify against the key and message.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Decodes a key from its 32 raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|e| CryptoError::Malformed {
                kind: "public key",
                reason: e.to_string(),
            })
    }

    /// Decodes a key from lowercase hex.
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = decode_fixed::<32>(hex_str, "public key")?;
        Self::from_bytes(&bytes)
    }

    /// The key's raw bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The key as lowercase hex, which is its wire form.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0.to_bytes())
    }

    /// Verifies `signature` over `message`.
    pub fn verify(self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        self.0
            .verify(message, &signature.0)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// An Ed25519 private key.
///
/// Debug output is redacted so keys cannot leak through logs.
#[derive(Clone)]
pub struct PrivateKey(SigningKey);

impl PrivateKey {
    /// Builds a key from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Builds a key from a hex-encoded 32-byte seed.
    pub fn from_seed_hex(hex_str: &str) -> Result<Self, CryptoError> {
        Ok(Self::from_seed(&decode_fixed::<32>(
            hex_str,
            "private key",
        )?))
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey(<redacted> for {})", self.public_key())
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(ed25519_dalek::Signature);

impl Signature {
    /// Decodes a signature from its 64 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(ed25519_dalek::Signature::from_bytes(bytes))
    }

    /// Decodes a signature from lowercase hex.
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        Ok(Self::from_bytes(&decode_fixed::<64>(hex_str, "signature")?))
    }

    /// The signature's raw bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// The signature as lowercase hex, which is its wire form.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0.to_bytes())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// An X25519 public key, used to receive encrypted content (§9).
///
/// Separate from the Ed25519 signing key on purpose: one key, one primitive.
/// A device publishes both, and the cross-signing chain certifies them together
/// (§3.6), so a counterparty that trusts a device to *sign* also knows where to
/// *encrypt* for it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptionPublicKey(x25519_dalek::PublicKey);

impl EncryptionPublicKey {
    /// Builds a key from its 32 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(bytes))
    }

    /// Decodes a key from lowercase hex.
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        Ok(Self::from_bytes(decode_fixed::<32>(
            hex_str,
            "encryption key",
        )?))
    }

    /// The key's raw bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The key as lowercase hex, which is its wire form.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0.as_bytes())
    }

    pub(crate) fn inner(self) -> x25519_dalek::PublicKey {
        self.0
    }
}

impl fmt::Debug for EncryptionPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptionPublicKey({})", self.to_hex())
    }
}

impl fmt::Display for EncryptionPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// An X25519 private key.
///
/// Built from a caller-supplied seed for the same reason as [`PrivateKey`]:
/// this crate never reaches for operating-system randomness.
#[derive(Clone)]
pub struct EncryptionPrivateKey(x25519_dalek::StaticSecret);

impl EncryptionPrivateKey {
    /// Builds a key from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(*seed))
    }

    /// Builds a key from a hex-encoded 32-byte seed.
    pub fn from_seed_hex(hex_str: &str) -> Result<Self, CryptoError> {
        Ok(Self::from_seed(&decode_fixed::<32>(
            hex_str,
            "encryption key",
        )?))
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> EncryptionPublicKey {
        EncryptionPublicKey(x25519_dalek::PublicKey::from(&self.0))
    }

    /// Performs the X25519 exchange with `peer`, yielding a shared secret.
    ///
    /// The result must be run through a KDF before use as a key; see
    /// [`crate::encryption`].
    #[must_use]
    pub fn diffie_hellman(&self, peer: EncryptionPublicKey) -> [u8; 32] {
        self.0.diffie_hellman(&peer.inner()).to_bytes()
    }
}

impl fmt::Debug for EncryptionPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptionPrivateKey(<redacted> for {})",
            self.public_key()
        )
    }
}

fn decode_fixed<const N: usize>(hex_str: &str, kind: &'static str) -> Result<[u8; N], CryptoError> {
    let bytes = hex::decode(hex_str).map_err(|e| CryptoError::Malformed {
        kind,
        reason: e.to_string(),
    })?;
    bytes.try_into().map_err(|_| CryptoError::Malformed {
        kind,
        reason: format!("expected {N} bytes"),
    })
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

impl Serialize for EncryptionPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for EncryptionPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_seed(&[byte; 32])
    }

    #[test]
    fn signs_and_verifies() {
        let signer = key(1);
        let signature = signer.sign(b"herald");
        assert!(signer.public_key().verify(b"herald", &signature).is_ok());
    }

    #[test]
    fn rejects_tampered_message() {
        let signer = key(2);
        let signature = signer.sign(b"herald");
        assert_eq!(
            signer.public_key().verify(b"herald!", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_other_signer() {
        let signature = key(3).sign(b"herald");
        assert_eq!(
            key(4).public_key().verify(b"herald", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn seeds_are_deterministic() {
        assert_eq!(key(5).public_key(), key(5).public_key());
        assert_eq!(key(5).sign(b"x"), key(5).sign(b"x"));
        assert_ne!(key(5).public_key(), key(6).public_key());
    }

    #[test]
    fn hex_round_trips() {
        let public = key(7).public_key();
        assert_eq!(PublicKey::from_hex(&public.to_hex()).unwrap(), public);

        let signature = key(7).sign(b"x");
        assert_eq!(Signature::from_hex(&signature.to_hex()).unwrap(), signature);
    }

    #[test]
    fn rejects_wrong_length_hex() {
        assert!(matches!(
            PublicKey::from_hex("aabb"),
            Err(CryptoError::Malformed { .. })
        ));
    }

    #[test]
    fn x25519_agreement_is_symmetric() {
        let alice = EncryptionPrivateKey::from_seed(&[1; 32]);
        let bob = EncryptionPrivateKey::from_seed(&[2; 32]);
        assert_eq!(
            alice.diffie_hellman(bob.public_key()),
            bob.diffie_hellman(alice.public_key())
        );
    }

    #[test]
    fn x25519_agreement_differs_per_peer() {
        let alice = EncryptionPrivateKey::from_seed(&[1; 32]);
        let bob = EncryptionPrivateKey::from_seed(&[2; 32]);
        let eve = EncryptionPrivateKey::from_seed(&[3; 32]);
        assert_ne!(
            alice.diffie_hellman(bob.public_key()),
            alice.diffie_hellman(eve.public_key())
        );
    }

    #[test]
    fn encryption_keys_round_trip_through_hex() {
        let public = EncryptionPrivateKey::from_seed(&[4; 32]).public_key();
        assert_eq!(
            EncryptionPublicKey::from_hex(&public.to_hex()).unwrap(),
            public
        );
    }

    #[test]
    fn encryption_private_key_debug_is_redacted() {
        let rendered = format!("{:?}", EncryptionPrivateKey::from_seed(&[5; 32]));
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let rendered = format!("{:?}", key(8));
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains(&hex::encode([8u8; 32])), "{rendered}");
    }
}
