//! Regenerates the protocol test vectors in `vectors/`.
//!
//! Run with `cargo run -p herald-core --example gen_vectors`. The committed
//! vectors are checked against the current implementation by
//! `tests/vectors.rs`, so regenerating them is a deliberate act: if a change
//! makes this example produce different output, the wire format changed and
//! the diff should say so.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use herald_core::canonical::{canonical_hash, canonicalize};
use herald_core::crypto::{EncryptionPrivateKey, PrivateKey};
use herald_core::encryption::{encrypt, Aad, Entropy, RecipientDevice};
use herald_core::error::ErrorCode;
use herald_core::event::{EventDraft, EventType};
use herald_core::id::{ContextAddress, ContextName, Gid};
use herald_core::identity::{IdentityBundle, KeyCertificate, KeyPurpose, VerificationLevel};
use herald_core::trust::{
    ConnectionRequest, ContextGrant, Decision, GrantType, RecipientPolicy, SenderInfo, Timestamp,
    TrustGrant, TrustTier,
};
use serde_json::{json, Value};

const NOW: Timestamp = 1_800_000_000;
const LATER: Timestamp = NOW + 86_400;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors");
    std::fs::create_dir_all(&root)?;

    write(&root.join("canonical.json"), canonical_vectors()?)?;
    write(&root.join("identity.json"), identity_vectors()?)?;
    write(&root.join("events.json"), event_vectors()?)?;
    write(&root.join("trust.json"), trust_vectors()?)?;
    write(&root.join("encryption.json"), encryption_vectors()?)?;

    println!("wrote vectors to {}", root.display());
    Ok(())
}

fn write(path: &std::path::Path, value: Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut text = serde_json::to_string_pretty(&value)?;
    text.push('\n');
    std::fs::write(path, text)?;
    Ok(())
}

fn seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// How seeds are published.
///
/// Vectors name a seed by the single byte it repeats rather than by 64 hex
/// characters. The material is identical, but a repeated-byte marker is not
/// mistakable for real key material — by a reader or by a secret scanner —
/// and a published reference implementation should not be teaching either one
/// to expect key-shaped blobs in its fixtures.
const SEED_ENCODING: &str = "each seed is the given byte repeated 32 times";

fn canonical_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let cases = [
        ("empty object", json!({})),
        ("empty array", json!([])),
        ("key ordering", json!({ "b": 1, "a": 2, "C": 3, "_": 4 })),
        (
            "nested ordering",
            json!({ "z": { "y": 1, "x": 2 }, "a": [{ "d": 1, "c": 2 }] }),
        ),
        ("array order preserved", json!([3, 1, 2])),
        (
            "integer bounds",
            json!({ "min": i64::MIN, "max": u64::MAX }),
        ),
        ("literals", json!({ "t": true, "f": false, "n": null })),
        (
            "string escapes",
            json!({ "k": "quote:\" backslash:\\ newline:\n tab:\t control:\u{0001}" }),
        ),
        (
            "non-ascii is literal",
            json!({ "greeting": "héllo wörld", "emoji": "🛰" }),
        ),
        (
            "utf16 key ordering",
            json!({ "\u{10000}": "astral", "\u{ff3a}": "fullwidth", "a": "ascii" }),
        ),
        (
            "realistic event content",
            json!({
                "format": "text/herald",
                "text": "Hi, please find the Q3 numbers attached.",
                "mentions": ["boss:deloitte"],
            }),
        ),
    ];

    let mut vectors = Vec::new();
    for (name, input) in cases {
        vectors.push(json!({
            "name": name,
            "input": input,
            "canonical": canonicalize(&input)?,
            "sha512": hex::encode(canonical_hash(&input)?),
        }));
    }

    Ok(json!({
        "description": "Canonical JSON (JCS / RFC 8785 profile) as used for every HERALD signature.",
        "note": "Floating-point numbers are rejected outright; see `rejected` for inputs an \
                 implementation must refuse rather than canonicalize.",
        "vectors": vectors,
        "rejected": [
            { "name": "float", "input": { "k": 1.5 }, "reason": "floating-point not permitted" },
            { "name": "exponent", "input": { "k": 1.0e10 }, "reason": "floating-point not permitted" }
        ]
    }))
}

fn sample_bundle() -> Result<(IdentityBundle, PrivateKey), Box<dyn std::error::Error>> {
    let gid = Gid::parse("diprish")?;
    let identity = PrivateKey::from_seed(&seed(1));
    let self_signing = PrivateKey::from_seed(&seed(2));
    let device = PrivateKey::from_seed(&seed(3));
    let device_encryption = EncryptionPrivateKey::from_seed(&seed(4));

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
        )?,
        devices: vec![KeyCertificate::issue_device(
            &self_signing,
            gid,
            "DEVKEY:AB12",
            device.public_key(),
            device_encryption.public_key(),
        )?],
    };
    Ok((bundle, device))
}

fn identity_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let (bundle, _) = sample_bundle()?;

    // A device certificate signed by a key that is not the self-signing key.
    let mut forged_signer = bundle.clone();
    let impostor = PrivateKey::from_seed(&seed(9));
    forged_signer.devices = vec![KeyCertificate::issue_device(
        &impostor,
        Gid::parse("diprish")?,
        "DEVKEY:AB12",
        impostor.public_key(),
        EncryptionPrivateKey::from_seed(&seed(11)).public_key(),
    )?];

    // A genuine certificate lifted from another identity.
    let mut borrowed = bundle.clone();
    borrowed.devices = vec![KeyCertificate::issue_device(
        &PrivateKey::from_seed(&seed(2)),
        Gid::parse("mallory")?,
        "DEVKEY:AB12",
        PrivateKey::from_seed(&seed(3)).public_key(),
        EncryptionPrivateKey::from_seed(&seed(4)).public_key(),
    )?];

    Ok(json!({
        "description": "Cross-signing chains: identity key -> self-signing key -> device key (spec 3.6).",
        "seed_encoding": SEED_ENCODING,
        "seed_bytes": {
            "identity": 1,
            "self_signing": 2,
            "device": 3,
            "device_encryption": 4,
            "impostor": 9
        },
        "vectors": [
            {
                "name": "sound chain",
                "bundle": bundle,
                "verifies": true,
                "resolves": { "DEVKEY:AB12": bundle.devices[0].subject_key.to_hex() }
            },
            {
                "name": "device signed by an uncertified key",
                "bundle": forged_signer,
                "verifies": false,
                "reason": "BadCertificate"
            },
            {
                "name": "certificate borrowed from another identity",
                "bundle": borrowed,
                "verifies": false,
                "reason": "GidMismatch"
            }
        ]
    }))
}

fn event_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let (bundle, device) = sample_bundle()?;

    let drafts = vec![
        (
            "first event in a thread",
            EventDraft {
                thread_id: "!01J8X2M0AB:herald.deloitte.com".into(),
                seq: 1,
                prev_event: None,
                event_type: EventType::Message,
                sender: ContextAddress::parse("diprish:deloitte")?,
                origin_server: "herald.deloitte.com".into(),
                created_at: "2026-07-21T09:32:00.000Z".into(),
                content: json!({
                    "format": "text/herald",
                    "text": "Hi, please find the Q3 numbers attached."
                }),
                device_key_id: "DEVKEY:AB12".into(),
            },
        ),
        (
            "linked second event",
            EventDraft {
                thread_id: "!01J8X2M0AB:herald.deloitte.com".into(),
                seq: 2,
                prev_event: Some("$0000000000000000000000000000000f:herald.deloitte.com".into()),
                event_type: EventType::React,
                sender: ContextAddress::parse("diprish:deloitte")?,
                origin_server: "herald.deloitte.com".into(),
                created_at: "2026-07-21T09:33:00.000Z".into(),
                content: json!({ "key": "+1" }),
                device_key_id: "DEVKEY:AB12".into(),
            },
        ),
        (
            "bare gid sender",
            EventDraft {
                thread_id: "!01J8X2M0AC:herald.example.com".into(),
                seq: 1,
                prev_event: None,
                event_type: EventType::Member,
                sender: ContextAddress::parse("diprish")?,
                origin_server: "herald.example.com".into(),
                created_at: "2026-07-21T10:00:00.000Z".into(),
                content: json!({ "membership": "join" }),
                device_key_id: "DEVKEY:AB12".into(),
            },
        ),
        (
            "unknown event type relays unchanged",
            EventDraft {
                thread_id: "!01J8X2M0AD:herald.example.com".into(),
                seq: 1,
                prev_event: None,
                event_type: EventType::from("h.offer"),
                sender: ContextAddress::parse("diprish:deloitte")?,
                origin_server: "herald.example.com".into(),
                created_at: "2026-07-21T11:00:00.000Z".into(),
                content: json!({ "title": "20% off", "valid_until": "2026-08-15T00:00:00Z" }),
                device_key_id: "DEVKEY:AB12".into(),
            },
        ),
    ];

    let mut vectors = Vec::new();
    for (name, draft) in drafts {
        let signing_payload = draft.signing_payload()?;
        let expected_event_id = draft.event_id()?;
        let event = draft.sign(&device)?;
        vectors.push(json!({
            "name": name,
            "signing_payload": signing_payload,
            "expected_event_id": expected_event_id,
            "event": event,
        }));
    }

    Ok(json!({
        "description": "Signed events (spec 4.1). The signature covers the canonical form of every \
                        field except `event_id` and `signature`; `event_id` is SHA-512 of that same \
                        payload, truncated to 32 hex characters, prefixed with `$` and suffixed with \
                        `:<origin_server>`.",
        "seed_encoding": SEED_ENCODING,
        "device_seed_byte": 3,
        "verification_bundle": bundle,
        "vectors": vectors
    }))
}

fn org_grant(who: &str, context: &str, authority: &str) -> ContextGrant {
    ContextGrant {
        gid: Gid::parse(who).expect("valid gid"),
        context: ContextName::parse(context).expect("valid context"),
        authority: Some(authority.to_owned()),
        valid_until: LATER,
        revoked_at: None,
    }
}

fn trust_case(
    name: &str,
    sender: SenderInfo,
    recipient: RecipientPolicy,
    request: Option<ConnectionRequest>,
    expected: Decision,
) -> Value {
    json!({
        "name": name,
        "now": NOW,
        "sender": sender,
        "recipient": recipient,
        "request": request,
        "expected": expected
    })
}

fn plain_sender(address: &str, level: VerificationLevel) -> SenderInfo {
    SenderInfo {
        address: ContextAddress::parse(address).expect("valid address"),
        level,
        contexts: Vec::new(),
    }
}

fn trust_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let intro = "Hello, we met at the conference last week in Lisbon.";
    let request = ConnectionRequest {
        introduction: intro.into(),
        sent_today: 0,
        acceptance_rate: 0.5,
        account_age_days: 365,
    };

    let mut org_sender = plain_sender("alice:deloitte", VerificationLevel::Anchored);
    org_sender.contexts = vec![org_grant("alice", "deloitte", "deloitte")];

    let mut revoked_sender = plain_sender("alice:deloitte", VerificationLevel::Anchored);
    revoked_sender.contexts = vec![ContextGrant {
        revoked_at: Some(NOW - 10),
        ..org_grant("alice", "deloitte", "deloitte")
    }];

    let contact_policy = RecipientPolicy {
        contacts: BTreeSet::from([Gid::parse("alice")?]),
        ..Default::default()
    };

    let vectors = vec![
        trust_case(
            "cold delivery is denied",
            plain_sender("alice", VerificationLevel::Anchored),
            RecipientPolicy::default(),
            None,
            Decision::Reject {
                code: ErrorCode::TrustDenied,
            },
        ),
        trust_case(
            "tier 1 mutual contact",
            plain_sender("alice:home", VerificationLevel::Anchored),
            contact_policy.clone(),
            None,
            Decision::Admit {
                tier: TrustTier::MutualContact,
            },
        ),
        trust_case(
            "tier 2 shared organizational context",
            org_sender.clone(),
            RecipientPolicy {
                contexts: vec![org_grant("diprish", "deloitte", "deloitte")],
                ..Default::default()
            },
            None,
            Decision::Admit {
                tier: TrustTier::SharedContext,
            },
        ),
        trust_case(
            "tier 2 requires the same authority",
            {
                let mut sender = plain_sender("alice:deloitte", VerificationLevel::Anchored);
                sender.contexts = vec![org_grant("alice", "deloitte", "impostor-ca")];
                sender
            },
            RecipientPolicy {
                contexts: vec![org_grant("diprish", "deloitte", "deloitte")],
                ..Default::default()
            },
            None,
            Decision::Reject {
                code: ErrorCode::TrustDenied,
            },
        ),
        trust_case(
            "tier 3 accepted connection request",
            plain_sender("alice", VerificationLevel::Anchored),
            RecipientPolicy {
                accepted_requests: BTreeSet::from([Gid::parse("alice")?]),
                ..Default::default()
            },
            None,
            Decision::Admit {
                tier: TrustTier::AcceptedRequest,
            },
        ),
        trust_case(
            "tier 4 transactional grant",
            plain_sender("receipts:acmeair", VerificationLevel::Anchored),
            RecipientPolicy {
                trust_grants: vec![TrustGrant {
                    grant_type: GrantType::Transactional,
                    grantee: ContextAddress::parse("receipts:acmeair")?,
                    scope: "thread-initiate".into(),
                    max_threads: Some(5),
                    valid_until: LATER,
                }],
                ..Default::default()
            },
            None,
            Decision::Admit {
                tier: TrustTier::ImplicitGrant(GrantType::Transactional),
            },
        ),
        trust_case(
            "tier 4 grant exhausted by thread ceiling",
            plain_sender("receipts:acmeair", VerificationLevel::Anchored),
            RecipientPolicy {
                trust_grants: vec![TrustGrant {
                    grant_type: GrantType::Transactional,
                    grantee: ContextAddress::parse("receipts:acmeair")?,
                    scope: "thread-initiate".into(),
                    max_threads: Some(5),
                    valid_until: LATER,
                }],
                grant_thread_usage: BTreeMap::from([("receipts:acmeair".to_owned(), 5)]),
                ..Default::default()
            },
            None,
            Decision::Reject {
                code: ErrorCode::TrustDenied,
            },
        ),
        trust_case(
            "block overrides every tier",
            plain_sender("alice", VerificationLevel::Anchored),
            RecipientPolicy {
                contacts: BTreeSet::from([Gid::parse("alice")?]),
                blocked: BTreeSet::from([Gid::parse("alice")?]),
                ..Default::default()
            },
            None,
            Decision::Reject {
                code: ErrorCode::TrustDenied,
            },
        ),
        trust_case(
            "revoked context within grace redirects",
            revoked_sender,
            contact_policy.clone(),
            None,
            Decision::Reject {
                code: ErrorCode::ContextMoved,
            },
        ),
        trust_case(
            "connection request quarantines",
            plain_sender("alice", VerificationLevel::Anchored),
            RecipientPolicy::default(),
            Some(request.clone()),
            Decision::Quarantine,
        ),
        trust_case(
            "level 0 cannot send connection requests",
            plain_sender("alice", VerificationLevel::Unverified),
            RecipientPolicy::default(),
            Some(request.clone()),
            Decision::Reject {
                code: ErrorCode::LevelInsufficient,
            },
        ),
        trust_case(
            "level 0 still reaches a mutual contact",
            plain_sender("alice", VerificationLevel::Unverified),
            contact_policy,
            None,
            Decision::Admit {
                tier: TrustTier::MutualContact,
            },
        ),
        trust_case(
            "connection request over the adaptive cap",
            plain_sender("alice", VerificationLevel::Anchored),
            RecipientPolicy::default(),
            Some(ConnectionRequest {
                sent_today: 999,
                ..request
            }),
            Decision::Reject {
                code: ErrorCode::RateLimited,
            },
        ),
    ];

    Ok(json!({
        "description": "Trust-chain decisions (spec 6.3). Timestamps are Unix seconds.",
        "caps": {
            "description": "Adaptive Connection Request caps (spec 6.5): \
                            [level, acceptance_rate, account_age_days, expected_cap].",
            "cases": [
                ["0", 1.0, 3650, 0],
                ["B", 1.0, 3650, 0],
                ["1", 0.10, 365, 5],
                ["1", 0.60, 365, 50],
                ["1", 0.95, 365, 50],
                ["1", 0.05, 365, 1],
                ["1", 1.0, 29, 5],
                ["2", 0.10, 365, 10],
                ["2", 0.60, 365, 100],
                ["2", 0.0, 365, 1],
                ["2", 1.0, 0, 10]
            ]
        },
        "vectors": vectors
    }))
}

fn encryption_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    // Recipient device secrets are published here so an implementation can
    // decrypt the vectors; they exist only for this file.
    // All three call their device DEVKEY:0001: wrapped keys are addressed by
    // gid/device_key_id, so identical device ids across identities are fine.
    let devices = [("alice", 20u8), ("bob", 21u8), ("diprish", 22u8)];

    let recipients: Vec<RecipientDevice> = devices
        .iter()
        .map(|(owner, seed_byte)| {
            Ok(RecipientDevice {
                gid: Gid::parse(owner)?,
                device_key_id: "DEVKEY:0001".to_owned(),
                encryption_key: EncryptionPrivateKey::from_seed(&seed(*seed_byte)).public_key(),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

    let cases: Vec<(&str, Value, Vec<RecipientDevice>, u8)> = vec![
        (
            "single recipient",
            json!({ "format": "text/herald", "text": "Hi, please find the Q3 numbers attached." }),
            vec![recipients[0].clone()],
            30,
        ),
        (
            "three recipient devices",
            json!({ "format": "text/herald", "text": "standup at 10" }),
            recipients.clone(),
            31,
        ),
        (
            "structured blocks",
            json!({
                "format": "text/herald",
                "blocks": [
                    { "kind": "paragraph", "text": "Q3 revenue" },
                    { "kind": "table", "header": ["Region", "Revenue"], "rows": [["EMEA", "4.2M"]] }
                ]
            }),
            vec![recipients[0].clone()],
            32,
        ),
    ];

    let aad = Aad {
        thread_id: "!01J8X2M0AB:herald.deloitte.com",
        sender: "diprish:deloitte",
    };

    let mut vectors = Vec::new();
    for (name, plaintext, to, entropy_byte) in cases {
        let envelope = encrypt(
            &plaintext,
            aad,
            &to,
            &Entropy::from_bytes(seed(entropy_byte)),
        )?;
        vectors.push(json!({
            "name": name,
            "entropy_byte": entropy_byte,
            "aad": { "thread_id": aad.thread_id, "sender": aad.sender },
            "recipients": to
                .iter()
                .map(|device| json!({
                    "gid": device.gid.as_str(),
                    "device_key_id": device.device_key_id,
                    "encryption_key": device.encryption_key.to_hex(),
                }))
                .collect::<Vec<_>>(),
            "plaintext": plaintext,
            "envelope": envelope,
        }));
    }

    Ok(json!({
        "description": "End-to-end encrypted content (spec 9). Encryption is deterministic given \
                        the entropy, which is what allows it to be covered by vectors; a real host \
                        MUST draw fresh entropy per event.",
        "algorithm": herald_core::encryption::ALGORITHM,
        "seed_encoding": SEED_ENCODING,
        "device_seed_bytes": devices
            .iter()
            .map(|(owner, seed_byte)| (format!("{owner}/DEVKEY:0001"), u64::from(*seed_byte)))
            .collect::<BTreeMap<String, u64>>(),
        "vectors": vectors
    }))
}
