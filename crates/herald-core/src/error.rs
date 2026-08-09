//! Protocol error codes (specification Appendix A).

use core::fmt;

/// Wire-level error codes defined in specification Appendix A.
///
/// These are the codes a server returns to a peer or client. Library functions
/// return richer Rust errors; [`ErrorCode`] is what those map onto when a
/// rejection has to cross the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Sender not admitted by any trust tier.
    TrustDenied,
    /// Identity certificate expired or revoked.
    IdentityInvalid,
    /// Context grant revoked (post-grace).
    ContextRevoked,
    /// Grace-period redirect hint (§3.9).
    ContextMoved,
    /// Event signature verification failed.
    SignatureInvalid,
    /// Event log divergence detected; refetch canonical log.
    SeqConflict,
    /// Adaptive request cap exceeded.
    RateLimited,
    /// Link matched threat registry (neutralized, not bounced).
    LinkMalicious,
    /// Sandbox analysis flagged attachment.
    AttachmentRejected,
    /// Recipient retention window elapsed (§8.5).
    DeliveryExpired,
    /// Recipient GID not in registry.
    GidNotFound,
    /// Operation requires a higher verification level.
    LevelInsufficient,
}

impl ErrorCode {
    /// The code's wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustDenied => "TRUST_DENIED",
            Self::IdentityInvalid => "IDENTITY_INVALID",
            Self::ContextRevoked => "CONTEXT_REVOKED",
            Self::ContextMoved => "CONTEXT_MOVED",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::SeqConflict => "SEQ_CONFLICT",
            Self::RateLimited => "RATE_LIMITED",
            Self::LinkMalicious => "LINK_MALICIOUS",
            Self::AttachmentRejected => "ATTACHMENT_REJECTED",
            Self::DeliveryExpired => "DELIVERY_EXPIRED",
            Self::GidNotFound => "GID_NOT_FOUND",
            Self::LevelInsufficient => "LEVEL_INSUFFICIENT",
        }
    }
}

impl ErrorCode {
    /// Parses a code from its wire representation.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "TRUST_DENIED" => Self::TrustDenied,
            "IDENTITY_INVALID" => Self::IdentityInvalid,
            "CONTEXT_REVOKED" => Self::ContextRevoked,
            "CONTEXT_MOVED" => Self::ContextMoved,
            "SIGNATURE_INVALID" => Self::SignatureInvalid,
            "SEQ_CONFLICT" => Self::SeqConflict,
            "RATE_LIMITED" => Self::RateLimited,
            "LINK_MALICIOUS" => Self::LinkMalicious,
            "ATTACHMENT_REJECTED" => Self::AttachmentRejected,
            "DELIVERY_EXPIRED" => Self::DeliveryExpired,
            "GID_NOT_FOUND" => Self::GidNotFound,
            "LEVEL_INSUFFICIENT" => Self::LevelInsufficient,
            _ => return None,
        })
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown error code {raw}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_render_as_wire_strings() {
        assert_eq!(ErrorCode::TrustDenied.as_str(), "TRUST_DENIED");
        assert_eq!(ErrorCode::SeqConflict.to_string(), "SEQ_CONFLICT");
    }
}
