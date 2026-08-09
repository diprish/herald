//! Global identifiers, contexts, and addresses (specification §3.1–§3.3).
//!
//! ```text
//! GID            = [a-z0-9][a-z0-9_-]{2,31}
//! ContextName    = [a-z0-9][a-z0-9_-]{1,31}
//! ContextAddress = GID ":" ContextName
//! HeraldAddress  = ( GID | ContextAddress ) [ "@" Domain ]
//! ```
//!
//! A bare GID is equivalent to `gid:default` (§3.2). The distinction is
//! preserved on the wire — [`ContextAddress`] remembers whether the context was
//! written explicitly, so parsing and rendering round-trip exactly.

use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The context every bare GID resolves to (§3.2).
pub const DEFAULT_CONTEXT: &str = "default";

/// Errors produced while parsing identifiers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// A GID did not match the §3.1 grammar.
    #[error("invalid GID {0:?}: must be 3-32 chars of [a-z0-9_-] starting with [a-z0-9]")]
    InvalidGid(String),
    /// A context name did not match the §3.2 grammar.
    #[error("invalid context name {0:?}: must be 2-32 chars of [a-z0-9_-] starting with [a-z0-9]")]
    InvalidContext(String),
    /// A domain suffix was not a plausible DNS name.
    #[error("invalid domain {0:?}")]
    InvalidDomain(String),
    /// The address had more structure than the grammar allows.
    #[error("malformed address {0:?}")]
    Malformed(String),
}

/// A Global Identifier: one per physical person (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gid(String);

impl Gid {
    /// Parses and validates a GID against the §3.1 grammar.
    pub fn parse(input: &str) -> Result<Self, IdError> {
        if valid_token(input, 3, 32) {
            Ok(Self(input.to_owned()))
        } else {
            Err(IdError::InvalidGid(input.to_owned()))
        }
    }

    /// The GID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An organizational or personal context name (§3.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextName(String);

impl ContextName {
    /// Parses and validates a context name against the §3.2 grammar.
    pub fn parse(input: &str) -> Result<Self, IdError> {
        if valid_token(input, 2, 32) {
            Ok(Self(input.to_owned()))
        } else {
            Err(IdError::InvalidContext(input.to_owned()))
        }
    }

    /// The context name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A GID with a context, e.g. `diprish:deloitte` (§3.2).
///
/// `context` is `None` for a bare GID, which is semantically `:default` but
/// renders bare.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextAddress {
    gid: Gid,
    context: Option<ContextName>,
}

impl ContextAddress {
    /// Builds an address from parts.
    #[must_use]
    pub fn new(gid: Gid, context: Option<ContextName>) -> Self {
        Self { gid, context }
    }

    /// Parses `gid` or `gid:context`.
    pub fn parse(input: &str) -> Result<Self, IdError> {
        match input.split_once(':') {
            None => Ok(Self {
                gid: Gid::parse(input)?,
                context: None,
            }),
            Some((gid, context)) => {
                if context.contains(':') {
                    return Err(IdError::Malformed(input.to_owned()));
                }
                Ok(Self {
                    gid: Gid::parse(gid)?,
                    context: Some(ContextName::parse(context)?),
                })
            }
        }
    }

    /// The identity this address belongs to.
    #[must_use]
    pub fn gid(&self) -> &Gid {
        &self.gid
    }

    /// The explicitly written context, if any.
    #[must_use]
    pub fn context(&self) -> Option<&ContextName> {
        self.context.as_ref()
    }

    /// The context this address resolves to, defaulting to `default` (§3.2).
    pub fn effective_context(&self) -> &str {
        self.context
            .as_ref()
            .map_or(DEFAULT_CONTEXT, ContextName::as_str)
    }

    /// Whether two addresses denote the same person, regardless of context.
    #[must_use]
    pub fn same_identity(&self, other: &Self) -> bool {
        self.gid == other.gid
    }
}

impl fmt::Display for ContextAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.context {
            None => f.write_str(self.gid.as_str()),
            Some(context) => write!(f, "{}:{}", self.gid.as_str(), context.as_str()),
        }
    }
}

/// A full address including the optional federation-routing domain (§3.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeraldAddress {
    address: ContextAddress,
    domain: Option<String>,
}

impl HeraldAddress {
    /// Parses `gid[:context][@domain]`.
    pub fn parse(input: &str) -> Result<Self, IdError> {
        match input.split_once('@') {
            None => Ok(Self {
                address: ContextAddress::parse(input)?,
                domain: None,
            }),
            Some((left, domain)) => {
                if !valid_domain(domain) {
                    return Err(IdError::InvalidDomain(domain.to_owned()));
                }
                Ok(Self {
                    address: ContextAddress::parse(left)?,
                    domain: Some(domain.to_owned()),
                })
            }
        }
    }

    /// The context address portion.
    #[must_use]
    pub fn address(&self) -> &ContextAddress {
        &self.address
    }

    /// The routing domain, if present.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

impl fmt::Display for HeraldAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.domain {
            None => write!(f, "{}", self.address),
            Some(domain) => write!(f, "{}@{}", self.address, domain),
        }
    }
}

fn valid_token(input: &str, min: usize, max: usize) -> bool {
    let len = input.chars().count();
    if len < min || len > max {
        return false;
    }
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn valid_domain(input: &str) -> bool {
    if input.is_empty() || input.len() > 253 {
        return false;
    }
    input.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

macro_rules! string_serde {
    ($type:ty) => {
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::parse(&raw).map_err(serde::de::Error::custom)
            }
        }

        impl FromStr for $type {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }
    };
}

impl fmt::Display for Gid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for ContextName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

string_serde!(Gid);
string_serde!(ContextName);
string_serde!(ContextAddress);
string_serde!(HeraldAddress);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_gids() {
        for input in ["diprish", "alice", "bob99", "a1_", "a-b", "012"] {
            assert!(Gid::parse(input).is_ok(), "{input} should parse");
        }
    }

    #[test]
    fn rejects_invalid_gids() {
        for input in [
            "ab",
            "",
            "-abc",
            "_abc",
            "Alice",
            "a b",
            "a".repeat(33).as_str(),
        ] {
            assert!(Gid::parse(input).is_err(), "{input} should not parse");
        }
    }

    #[test]
    fn context_names_allow_two_characters() {
        assert!(ContextName::parse("hr").is_ok());
        assert!(ContextName::parse("h").is_err());
    }

    #[test]
    fn bare_gid_resolves_to_default_context() {
        let address = ContextAddress::parse("diprish").unwrap();
        assert_eq!(address.effective_context(), DEFAULT_CONTEXT);
        assert!(address.context().is_none());
        assert_eq!(address.to_string(), "diprish");
    }

    #[test]
    fn explicit_context_round_trips() {
        let address = ContextAddress::parse("diprish:deloitte").unwrap();
        assert_eq!(address.gid().as_str(), "diprish");
        assert_eq!(address.effective_context(), "deloitte");
        assert_eq!(address.to_string(), "diprish:deloitte");
    }

    #[test]
    fn rejects_double_context_separator() {
        assert!(ContextAddress::parse("diprish:a:b").is_err());
    }

    #[test]
    fn parses_federation_domain() {
        let address = HeraldAddress::parse("diprish:deloitte@herald.deloitte.com").unwrap();
        assert_eq!(address.domain(), Some("herald.deloitte.com"));
        assert_eq!(address.to_string(), "diprish:deloitte@herald.deloitte.com");
    }

    #[test]
    fn rejects_bad_domains() {
        for input in [
            "diprish@",
            "diprish@-bad.com",
            "diprish@bad-.com",
            "diprish@bad..com",
            "diprish@UPPER.com",
        ] {
            assert!(HeraldAddress::parse(input).is_err(), "{input} should fail");
        }
    }

    #[test]
    fn same_identity_ignores_context() {
        let work = ContextAddress::parse("diprish:deloitte").unwrap();
        let home = ContextAddress::parse("diprish:home").unwrap();
        let other = ContextAddress::parse("alice:deloitte").unwrap();
        assert!(work.same_identity(&home));
        assert!(!work.same_identity(&other));
    }

    #[test]
    fn serde_round_trips_through_strings() {
        let address = ContextAddress::parse("diprish:mit").unwrap();
        let json = serde_json::to_string(&address).unwrap();
        assert_eq!(json, "\"diprish:mit\"");
        let parsed: ContextAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, address);
    }
}
