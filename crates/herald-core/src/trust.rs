//! The trust chain: who is allowed to deliver to whom (§6).
//!
//! This is the protocol's central anti-abuse mechanism, and it is expressed
//! here as pure functions over explicit state so it can be exhaustively tested
//! and shared byte-for-byte between server and client. The decision procedure
//! is §6.3:
//!
//! ```text
//! ADMIT      if Tier 1 | Tier 2 | Tier 3 | valid Tier 4 grant
//! QUARANTINE if valid Connection Request (rate limit passed)
//! REJECT     otherwise -> generic TRUST_DENIED, no existence oracle
//! ```
//!
//! Timestamps are Unix seconds. Parsing RFC 3339 from the wire belongs to the
//! caller, which keeps this crate free of a date-time dependency.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::ErrorCode;
use crate::id::{ContextAddress, ContextName, Gid};
use crate::identity::VerificationLevel;

/// Unix seconds.
pub type Timestamp = i64;

/// The grace window after context revocation during which inbound events on
/// pre-existing threads get a `CONTEXT_MOVED` redirect (§3.9): 90 days.
pub const CONTEXT_GRACE_SECONDS: i64 = 90 * 24 * 60 * 60;

/// Minimum length of a Connection Request introduction (§6.6).
pub const INTRODUCTION_MIN_CHARS: usize = 20;
/// Maximum length of a Connection Request introduction (§6.6).
pub const INTRODUCTION_MAX_CHARS: usize = 300;

/// A context grant issued by a Context Authority, or a self-managed personal
/// context when `authority` is `None` (§3.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextGrant {
    /// The holder.
    pub gid: Gid,
    /// The context name granted.
    pub context: ContextName,
    /// The issuing Context Authority; `None` for a personal context.
    pub authority: Option<String>,
    /// When the grant lapses.
    pub valid_until: Timestamp,
    /// When the grant was revoked, if it has been (§3.9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Timestamp>,
}

/// The state of a context grant at a point in time (§3.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    /// Usable.
    Valid,
    /// Revoked within the last 90 days: pre-existing threads get a redirect.
    GraceRedirect,
    /// Revoked and past grace, or simply expired.
    Revoked,
}

impl ContextGrant {
    /// Evaluates the grant at `now`.
    #[must_use]
    pub fn status_at(&self, now: Timestamp) -> GrantStatus {
        if let Some(revoked_at) = self.revoked_at {
            return if now < revoked_at.saturating_add(CONTEXT_GRACE_SECONDS) {
                GrantStatus::GraceRedirect
            } else {
                GrantStatus::Revoked
            };
        }
        if now < self.valid_until {
            GrantStatus::Valid
        } else {
            GrantStatus::Revoked
        }
    }

    /// Whether the grant is usable at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        self.status_at(now) == GrantStatus::Valid
    }

    /// Whether this is an organizational grant (as opposed to personal).
    #[must_use]
    pub fn is_organizational(&self) -> bool {
        self.authority.is_some()
    }
}

/// The kinds of implicit trust grant defined in §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantType {
    /// Minted by the user's own client when handing over their address in an
    /// authenticated flow (checkout, booking, signup).
    Transactional,
    /// Provisional trust from being introduced into a thread.
    Introduction,
    /// Trust inherited from joining an organization.
    ContextInheritance,
}

/// A trust grant the recipient issued to some counterparty (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGrant {
    /// Which implicit-grant mechanism produced this.
    pub grant_type: GrantType,
    /// Who the grant admits.
    pub grantee: ContextAddress,
    /// What the grantee may do, e.g. `thread-initiate`.
    pub scope: String,
    /// Optional ceiling on threads the grantee may open under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_threads: Option<u32>,
    /// When the grant lapses.
    pub valid_until: Timestamp,
}

impl TrustGrant {
    /// Whether this grant admits `sender` at `now`, given how many threads the
    /// grantee has already opened under it.
    #[must_use]
    pub fn admits(&self, sender: &ContextAddress, now: Timestamp, threads_used: u32) -> bool {
        if now >= self.valid_until {
            return false;
        }
        if &self.grantee != sender {
            return false;
        }
        match self.max_threads {
            Some(max) => threads_used < max,
            None => true,
        }
    }
}

/// Everything about a sender the trust decision depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderInfo {
    /// The address the sender is sending as.
    pub address: ContextAddress,
    /// The sender's registry verification level (§3.4).
    pub level: VerificationLevel,
    /// The sender's context grants.
    ///
    /// A context the sender claims that is absent from this list is treated as
    /// a self-managed personal context (§3.9). Deciding which context *names*
    /// are CA-managed is the registry's job, not this function's; a server must
    /// populate this list from the registry before evaluating.
    #[serde(default)]
    pub contexts: Vec<ContextGrant>,
}

impl SenderInfo {
    fn claimed_grant(&self) -> Option<&ContextGrant> {
        let context = self.address.context()?;
        self.contexts
            .iter()
            .find(|grant| &grant.context == context && grant.gid == *self.address.gid())
    }
}

/// Everything about a recipient the trust decision depends on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientPolicy {
    /// Identities the recipient has as contacts (Tier 1).
    #[serde(default)]
    pub contacts: BTreeSet<Gid>,
    /// The recipient's own context grants (Tier 2).
    #[serde(default)]
    pub contexts: Vec<ContextGrant>,
    /// Identities whose Connection Requests the recipient accepted (Tier 3).
    #[serde(default)]
    pub accepted_requests: BTreeSet<Gid>,
    /// Trust grants the recipient has issued (Tier 4).
    #[serde(default)]
    pub trust_grants: Vec<TrustGrant>,
    /// Threads already opened per grantee, keyed by rendered address.
    #[serde(default)]
    pub grant_thread_usage: BTreeMap<String, u32>,
    /// Identities the recipient has blocked. Blocks win over every tier.
    #[serde(default)]
    pub blocked: BTreeSet<Gid>,
}

/// A Connection Request accompanying a delivery attempt (§6.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionRequest {
    /// Mandatory 20-300 character introduction.
    pub introduction: String,
    /// How many requests the sender has already sent in the current window.
    pub sent_today: u32,
    /// The sender's rolling acceptance rate, 0.0-1.0.
    pub acceptance_rate: f64,
    /// Age of the sender's account in days.
    pub account_age_days: u32,
}

/// Which tier admitted a delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Tier 1: the parties are mutual contacts.
    MutualContact,
    /// Tier 2: both hold valid grants from the same Context Authority.
    SharedContext,
    /// Tier 3: the recipient accepted a Connection Request.
    AcceptedRequest,
    /// Tier 4: an implicit grant admits the sender.
    ImplicitGrant(GrantType),
}

/// The outcome of a trust evaluation (§6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "kebab-case")]
pub enum Decision {
    /// Deliver, admitted by `tier`.
    Admit {
        /// The tier that admitted the delivery.
        tier: TrustTier,
    },
    /// Hold in the quarantine surface as a Connection Request.
    Quarantine,
    /// Refuse, reporting `code`.
    Reject {
        /// The wire error code to return.
        code: ErrorCode,
    },
}

impl Decision {
    fn admit(tier: TrustTier) -> Self {
        Self::Admit { tier }
    }

    fn reject(code: ErrorCode) -> Self {
        Self::Reject { code }
    }

    /// Whether this decision delivers the event.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admit { .. })
    }
}

/// Evaluates a delivery against the recipient's trust chain (§6.3).
///
/// `request` carries a Connection Request when the sender is attempting cold
/// contact; pass `None` for an ordinary delivery.
#[must_use]
pub fn evaluate(
    sender: &SenderInfo,
    recipient: &RecipientPolicy,
    request: Option<&ConnectionRequest>,
    now: Timestamp,
) -> Decision {
    // A block is absolute; it is checked before anything can admit.
    if recipient.blocked.contains(sender.address.gid()) {
        return Decision::reject(ErrorCode::TrustDenied);
    }

    // Sending *as* an organizational context requires that grant to be live.
    if let Some(grant) = sender.claimed_grant() {
        match grant.status_at(now) {
            GrantStatus::Valid => {}
            GrantStatus::GraceRedirect => return Decision::reject(ErrorCode::ContextMoved),
            GrantStatus::Revoked => return Decision::reject(ErrorCode::ContextRevoked),
        }
    }

    if let Some(tier) = admitting_tier(sender, recipient, now) {
        return Decision::admit(tier);
    }

    match request {
        Some(request) => evaluate_connection_request(sender, request),
        None => Decision::reject(ErrorCode::TrustDenied),
    }
}

fn admitting_tier(
    sender: &SenderInfo,
    recipient: &RecipientPolicy,
    now: Timestamp,
) -> Option<TrustTier> {
    let gid = sender.address.gid();

    // Tier 1 - mutual contact.
    if recipient.contacts.contains(gid) {
        return Some(TrustTier::MutualContact);
    }

    // Tier 2 - a currently valid grant from the same Context Authority.
    let shared = sender.contexts.iter().any(|sender_grant| {
        sender_grant.is_organizational()
            && sender_grant.is_valid_at(now)
            && recipient.contexts.iter().any(|recipient_grant| {
                recipient_grant.is_organizational()
                    && recipient_grant.is_valid_at(now)
                    && recipient_grant.authority == sender_grant.authority
                    && recipient_grant.context == sender_grant.context
            })
    });
    if shared {
        return Some(TrustTier::SharedContext);
    }

    // Tier 3 - previously accepted Connection Request.
    if recipient.accepted_requests.contains(gid) {
        return Some(TrustTier::AcceptedRequest);
    }

    // Tier 4 - implicit grants.
    let used = recipient
        .grant_thread_usage
        .get(&sender.address.to_string())
        .copied()
        .unwrap_or(0);
    recipient
        .trust_grants
        .iter()
        .find(|grant| grant.admits(&sender.address, now, used))
        .map(|grant| TrustTier::ImplicitGrant(grant.grant_type))
}

fn evaluate_connection_request(sender: &SenderInfo, request: &ConnectionRequest) -> Decision {
    if !sender.level.can_send_connection_requests() {
        return Decision::reject(ErrorCode::LevelInsufficient);
    }

    let length = request.introduction.chars().count();
    if !(INTRODUCTION_MIN_CHARS..=INTRODUCTION_MAX_CHARS).contains(&length) {
        return Decision::reject(ErrorCode::TrustDenied);
    }

    let cap = daily_connection_request_cap(
        sender.level,
        request.acceptance_rate,
        request.account_age_days,
    );
    if request.sent_today >= cap {
        return Decision::reject(ErrorCode::RateLimited);
    }

    Decision::Quarantine
}

/// The adaptive Connection Request cap (§6.5).
///
/// Replaces v1.0's flat 10/day with a reputation function requiring zero
/// configuration: legitimate networkers earn headroom automatically, while
/// purchased identities burn out on rejection.
///
/// * Level 0 and bridged identities cannot send requests at all.
/// * Level 1 starts at 5/day and scales to 50 at a sustained 60% acceptance.
/// * Level 2 starts at 10/day and scales to 100.
/// * Sustained acceptance below 10% decays the cap to 1.
/// * Accounts younger than 30 days are held at their base rate.
#[must_use]
pub fn daily_connection_request_cap(
    level: VerificationLevel,
    acceptance_rate: f64,
    account_age_days: u32,
) -> u32 {
    const SUSTAINED_ACCEPTANCE: f64 = 0.60;
    const DECAY_THRESHOLD: f64 = 0.10;
    const NEW_ACCOUNT_DAYS: u32 = 30;

    let (base, ceiling) = match level {
        VerificationLevel::Unverified | VerificationLevel::Bridged => return 0,
        VerificationLevel::Anchored => (5u32, 50u32),
        VerificationLevel::RegistryVerified => (10u32, 100u32),
    };

    // A brand-new account has no track record to reward; it gets the base rate
    // regardless of how flattering its early ratio looks.
    if account_age_days < NEW_ACCOUNT_DAYS {
        return base;
    }

    let rate = acceptance_rate.clamp(0.0, 1.0);
    if rate < DECAY_THRESHOLD {
        return 1;
    }

    let scale =
        ((rate - DECAY_THRESHOLD) / (SUSTAINED_ACCEPTANCE - DECAY_THRESHOLD)).clamp(0.0, 1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "scale is clamped to 0.0..=1.0, so the product is within 0..=(ceiling - base)"
    )]
    let headroom = (f64::from(ceiling - base) * scale).round() as u32;
    base + headroom
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Timestamp = 1_800_000_000;
    const LATER: Timestamp = NOW + 1_000;

    fn gid(name: &str) -> Gid {
        Gid::parse(name).unwrap()
    }

    fn address(raw: &str) -> ContextAddress {
        ContextAddress::parse(raw).unwrap()
    }

    fn org_grant(who: &str, context: &str, authority: &str) -> ContextGrant {
        ContextGrant {
            gid: gid(who),
            context: ContextName::parse(context).unwrap(),
            authority: Some(authority.to_owned()),
            valid_until: LATER,
            revoked_at: None,
        }
    }

    fn sender(raw: &str) -> SenderInfo {
        SenderInfo {
            address: address(raw),
            level: VerificationLevel::Anchored,
            contexts: Vec::new(),
        }
    }

    fn request() -> ConnectionRequest {
        ConnectionRequest {
            introduction: "Hello, we met at the conference last week in Lisbon.".into(),
            sent_today: 0,
            acceptance_rate: 0.5,
            account_age_days: 365,
        }
    }

    #[test]
    fn cold_delivery_is_denied_by_default() {
        let decision = evaluate(&sender("alice"), &RecipientPolicy::default(), None, NOW);
        assert_eq!(decision, Decision::reject(ErrorCode::TrustDenied));
    }

    #[test]
    fn tier1_admits_a_contact() {
        let recipient = RecipientPolicy {
            contacts: BTreeSet::from([gid("alice")]),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&sender("alice:home"), &recipient, None, NOW),
            Decision::admit(TrustTier::MutualContact)
        );
    }

    #[test]
    fn tier2_admits_a_shared_organizational_context() {
        let mut source = sender("alice:deloitte");
        source.contexts = vec![org_grant("alice", "deloitte", "deloitte")];
        let recipient = RecipientPolicy {
            contexts: vec![org_grant("diprish", "deloitte", "deloitte")],
            ..Default::default()
        };
        assert_eq!(
            evaluate(&source, &recipient, None, NOW),
            Decision::admit(TrustTier::SharedContext)
        );
    }

    #[test]
    fn tier2_requires_the_same_authority() {
        let mut source = sender("alice:deloitte");
        source.contexts = vec![org_grant("alice", "deloitte", "impostor-ca")];
        let recipient = RecipientPolicy {
            contexts: vec![org_grant("diprish", "deloitte", "deloitte")],
            ..Default::default()
        };
        assert_eq!(
            evaluate(&source, &recipient, None, NOW),
            Decision::reject(ErrorCode::TrustDenied)
        );
    }

    #[test]
    fn tier2_ignores_personal_contexts() {
        // Anyone may name a personal context; only CA-issued grants build trust.
        let mut source = sender("alice:deloitte");
        source.contexts = vec![ContextGrant {
            authority: None,
            ..org_grant("alice", "deloitte", "deloitte")
        }];
        let recipient = RecipientPolicy {
            contexts: vec![ContextGrant {
                authority: None,
                ..org_grant("diprish", "deloitte", "deloitte")
            }],
            ..Default::default()
        };
        assert_eq!(
            evaluate(&source, &recipient, None, NOW),
            Decision::reject(ErrorCode::TrustDenied)
        );
    }

    #[test]
    fn tier3_admits_an_accepted_request() {
        let recipient = RecipientPolicy {
            accepted_requests: BTreeSet::from([gid("alice")]),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&sender("alice"), &recipient, None, NOW),
            Decision::admit(TrustTier::AcceptedRequest)
        );
    }

    #[test]
    fn tier4_admits_a_transactional_grant() {
        let recipient = RecipientPolicy {
            trust_grants: vec![TrustGrant {
                grant_type: GrantType::Transactional,
                grantee: address("receipts:acmeair"),
                scope: "thread-initiate".into(),
                max_threads: Some(5),
                valid_until: LATER,
            }],
            ..Default::default()
        };
        assert_eq!(
            evaluate(&sender("receipts:acmeair"), &recipient, None, NOW),
            Decision::admit(TrustTier::ImplicitGrant(GrantType::Transactional))
        );
    }

    #[test]
    fn tier4_grant_expires() {
        let recipient = RecipientPolicy {
            trust_grants: vec![TrustGrant {
                grant_type: GrantType::Transactional,
                grantee: address("receipts:acmeair"),
                scope: "thread-initiate".into(),
                max_threads: None,
                valid_until: NOW,
            }],
            ..Default::default()
        };
        assert_eq!(
            evaluate(&sender("receipts:acmeair"), &recipient, None, NOW),
            Decision::reject(ErrorCode::TrustDenied)
        );
    }

    #[test]
    fn tier4_grant_respects_the_thread_ceiling() {
        let recipient = RecipientPolicy {
            trust_grants: vec![TrustGrant {
                grant_type: GrantType::Transactional,
                grantee: address("receipts:acmeair"),
                scope: "thread-initiate".into(),
                max_threads: Some(5),
                valid_until: LATER,
            }],
            grant_thread_usage: BTreeMap::from([("receipts:acmeair".to_owned(), 5)]),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&sender("receipts:acmeair"), &recipient, None, NOW),
            Decision::reject(ErrorCode::TrustDenied)
        );
    }

    #[test]
    fn tier4_grant_is_bound_to_the_exact_grantee_context() {
        let recipient = RecipientPolicy {
            trust_grants: vec![TrustGrant {
                grant_type: GrantType::Transactional,
                grantee: address("receipts:acmeair"),
                scope: "thread-initiate".into(),
                max_threads: None,
                valid_until: LATER,
            }],
            ..Default::default()
        };
        // The marketing context of the same organization is not the grantee.
        assert_eq!(
            evaluate(&sender("promos:acmeair"), &recipient, None, NOW),
            Decision::reject(ErrorCode::TrustDenied)
        );
    }

    #[test]
    fn blocks_override_every_tier() {
        let recipient = RecipientPolicy {
            contacts: BTreeSet::from([gid("alice")]),
            accepted_requests: BTreeSet::from([gid("alice")]),
            blocked: BTreeSet::from([gid("alice")]),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&sender("alice"), &recipient, None, NOW),
            Decision::reject(ErrorCode::TrustDenied)
        );
    }

    #[test]
    fn revoked_context_in_grace_redirects() {
        let mut source = sender("alice:deloitte");
        source.contexts = vec![ContextGrant {
            revoked_at: Some(NOW - 10),
            ..org_grant("alice", "deloitte", "deloitte")
        }];
        let recipient = RecipientPolicy {
            contacts: BTreeSet::from([gid("alice")]),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&source, &recipient, None, NOW),
            Decision::reject(ErrorCode::ContextMoved)
        );
    }

    #[test]
    fn revoked_context_past_grace_is_rejected() {
        let mut source = sender("alice:deloitte");
        source.contexts = vec![ContextGrant {
            revoked_at: Some(NOW - CONTEXT_GRACE_SECONDS - 1),
            ..org_grant("alice", "deloitte", "deloitte")
        }];
        let recipient = RecipientPolicy {
            contacts: BTreeSet::from([gid("alice")]),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&source, &recipient, None, NOW),
            Decision::reject(ErrorCode::ContextRevoked)
        );
    }

    #[test]
    fn grace_boundary_is_exclusive_at_ninety_days() {
        let grant = ContextGrant {
            revoked_at: Some(NOW),
            ..org_grant("alice", "deloitte", "deloitte")
        };
        assert_eq!(
            grant.status_at(NOW + CONTEXT_GRACE_SECONDS - 1),
            GrantStatus::GraceRedirect
        );
        assert_eq!(
            grant.status_at(NOW + CONTEXT_GRACE_SECONDS),
            GrantStatus::Revoked
        );
    }

    #[test]
    fn connection_request_quarantines() {
        assert_eq!(
            evaluate(
                &sender("alice"),
                &RecipientPolicy::default(),
                Some(&request()),
                NOW
            ),
            Decision::Quarantine
        );
    }

    #[test]
    fn level_zero_cannot_send_connection_requests() {
        let mut source = sender("alice");
        source.level = VerificationLevel::Unverified;
        assert_eq!(
            evaluate(&source, &RecipientPolicy::default(), Some(&request()), NOW),
            Decision::reject(ErrorCode::LevelInsufficient)
        );
    }

    #[test]
    fn level_zero_can_still_reach_a_mutual_contact() {
        // Level 0 may message mutual contacts (spec section 3.4); only cold
        // requests are barred.
        let mut source = sender("alice");
        source.level = VerificationLevel::Unverified;
        let recipient = RecipientPolicy {
            contacts: BTreeSet::from([gid("alice")]),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&source, &recipient, None, NOW),
            Decision::admit(TrustTier::MutualContact)
        );
    }

    #[test]
    fn introduction_length_is_enforced() {
        let mut short = request();
        short.introduction = "hi".into();
        assert_eq!(
            evaluate(
                &sender("alice"),
                &RecipientPolicy::default(),
                Some(&short),
                NOW
            ),
            Decision::reject(ErrorCode::TrustDenied)
        );

        let mut long = request();
        long.introduction = "x".repeat(INTRODUCTION_MAX_CHARS + 1);
        assert_eq!(
            evaluate(
                &sender("alice"),
                &RecipientPolicy::default(),
                Some(&long),
                NOW
            ),
            Decision::reject(ErrorCode::TrustDenied)
        );
    }

    #[test]
    fn rate_limit_rejects_over_cap() {
        let mut over = request();
        over.sent_today = 999;
        assert_eq!(
            evaluate(
                &sender("alice"),
                &RecipientPolicy::default(),
                Some(&over),
                NOW
            ),
            Decision::reject(ErrorCode::RateLimited)
        );
    }

    #[test]
    fn adaptive_cap_follows_the_spec_bands() {
        use VerificationLevel::{Anchored, Bridged, RegistryVerified, Unverified};

        assert_eq!(daily_connection_request_cap(Unverified, 1.0, 3650), 0);
        assert_eq!(daily_connection_request_cap(Bridged, 1.0, 3650), 0);

        // Base rates for established accounts with middling reputation.
        assert_eq!(daily_connection_request_cap(Anchored, 0.10, 365), 5);
        assert_eq!(
            daily_connection_request_cap(RegistryVerified, 0.10, 365),
            10
        );

        // Sustained 60% acceptance reaches the ceiling.
        assert_eq!(daily_connection_request_cap(Anchored, 0.60, 365), 50);
        assert_eq!(
            daily_connection_request_cap(RegistryVerified, 0.60, 365),
            100
        );
        assert_eq!(daily_connection_request_cap(Anchored, 0.95, 365), 50);

        // Below 10% acceptance the cap decays to 1.
        assert_eq!(daily_connection_request_cap(Anchored, 0.05, 365), 1);
        assert_eq!(daily_connection_request_cap(RegistryVerified, 0.0, 365), 1);

        // New accounts are held at base regardless of a flattering ratio.
        assert_eq!(daily_connection_request_cap(Anchored, 1.0, 29), 5);
        assert_eq!(daily_connection_request_cap(RegistryVerified, 1.0, 0), 10);
    }

    #[test]
    fn adaptive_cap_is_monotonic_in_acceptance_rate() {
        let mut previous = 0;
        for step in 0..=100 {
            let cap = daily_connection_request_cap(
                VerificationLevel::RegistryVerified,
                f64::from(step) / 100.0,
                365,
            );
            if step > 10 {
                assert!(
                    cap >= previous,
                    "cap dropped at {step}%: {previous} -> {cap}"
                );
            }
            previous = cap;
        }
    }

    #[test]
    fn decisions_serialize_for_test_vectors() {
        let json = serde_json::to_value(Decision::admit(TrustTier::ImplicitGrant(
            GrantType::Transactional,
        )))
        .unwrap();
        assert_eq!(json["decision"], "admit");

        let rejected = serde_json::to_value(Decision::reject(ErrorCode::TrustDenied)).unwrap();
        assert_eq!(rejected["code"], "TRUST_DENIED");

        let parsed: Decision = serde_json::from_value(rejected).unwrap();
        assert_eq!(parsed, Decision::reject(ErrorCode::TrustDenied));
    }
}
