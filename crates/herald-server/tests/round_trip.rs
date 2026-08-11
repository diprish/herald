//! End-to-end: two identities register, form trust, and exchange signed
//! messages through a server that verifies every step.
//!
//! This is the Phase 2 milestone from `docs/architecture/implementation-roadmap.md` —
//! the first real HERALD conversation.

use herald_core::crypto::{EncryptionPrivateKey, PrivateKey};
use herald_core::error::ErrorCode;
use herald_core::event::{Event, EventDraft, EventType};
use herald_core::id::{ContextAddress, Gid};
use herald_core::identity::{IdentityBundle, KeyCertificate, KeyPurpose, VerificationLevel};
use herald_core::log::validate_chain;
use herald_server::{
    Hhs, ListRequest, MemoryStore, ServerError, Subscription, SyncRequest, SyncResponse,
};
use serde_json::json;

const SERVER: &str = "herald.example.com";
const NOW: i64 = 1_800_000_000;

/// A registered person: their keys, address, and published bundle.
struct Person {
    gid: Gid,
    address: ContextAddress,
    device: PrivateKey,
    device_encryption: EncryptionPrivateKey,
    bundle: IdentityBundle,
}

/// Builds a Level 0 identity with a sound cross-signing chain (§3.5, §3.6).
fn person(name: &str, seed: u8) -> Person {
    let gid = Gid::parse(name).expect("valid gid");
    let identity = PrivateKey::from_seed(&[seed; 32]);
    let self_signing = PrivateKey::from_seed(&[seed + 1; 32]);
    let device = PrivateKey::from_seed(&[seed + 2; 32]);
    let device_encryption = EncryptionPrivateKey::from_seed(&[seed + 3; 32]);

    let bundle = IdentityBundle {
        gid: gid.clone(),
        level: VerificationLevel::Unverified,
        identity_key: identity.public_key(),
        self_signing: KeyCertificate::issue(
            &identity,
            gid.clone(),
            "SSK:0001",
            KeyPurpose::SelfSigning,
            self_signing.public_key(),
        )
        .expect("self-signing certificate"),
        devices: vec![KeyCertificate::issue_device(
            &self_signing,
            gid.clone(),
            "DEVKEY:0001",
            device.public_key(),
            device_encryption.public_key(),
        )
        .expect("device certificate")],
    };

    Person {
        address: ContextAddress::parse(name).expect("valid address"),
        gid,
        device,
        device_encryption,
        bundle,
    }
}

/// Composes, signs, and submits a message, the way a client would: read the
/// head, claim that position, sign, send.
fn send(
    hhs: &mut Hhs<MemoryStore>,
    from: &Person,
    thread_id: &str,
    text: &str,
    at: &str,
) -> Result<Event, ServerError> {
    let head = hhs.head(thread_id)?;
    let event = EventDraft {
        thread_id: thread_id.to_owned(),
        seq: head.seq,
        prev_event: head.prev_event,
        event_type: EventType::Message,
        sender: from.address.clone(),
        origin_server: SERVER.to_owned(),
        created_at: at.to_owned(),
        content: json!({ "format": "text/herald", "text": text }),
        device_key_id: "DEVKEY:0001".to_owned(),
    }
    .sign(&from.device)?;

    hhs.submit(event.clone())?;
    Ok(event)
}

fn subscribe(thread_id: &str, limit: usize) -> SyncRequest {
    SyncRequest {
        lists: vec![ListRequest {
            name: "inbox".into(),
            range: [0, 30],
        }],
        thread_subscriptions: [(
            thread_id.to_owned(),
            Subscription {
                timeline_limit: limit,
            },
        )]
        .into_iter()
        .collect(),
    }
}

fn texts(sync: &SyncResponse, thread_id: &str) -> Vec<String> {
    sync.threads[thread_id]
        .events
        .iter()
        .map(|event| event.draft.content["text"].as_str().unwrap().to_owned())
        .collect()
}

/// Two people register, become contacts, and hold a conversation. Every event
/// is signature-verified by the server on the way in and by the recipient on
/// the way out.
#[test]
fn two_identities_exchange_messages() {
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    hhs.register(diprish.bundle.clone()).expect("register");
    hhs.register(alice.bundle.clone()).expect("register");

    // Cold contact does not exist: with no trust, the thread cannot be opened.
    let refused = hhs
        .create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW)
        .unwrap_err();
    assert_eq!(refused.error_code(), ErrorCode::TrustDenied);

    // Tier 1 trust: alice has diprish as a contact.
    hhs.add_contact(&alice.gid, &diprish.gid).expect("contact");

    let thread = hhs
        .create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW)
        .expect("thread opens once trust exists");

    send(
        &mut hhs,
        &diprish,
        &thread,
        "Hello Alice",
        "2026-08-09T10:00:00.000Z",
    )
    .expect("first message");

    // Alice syncs and sees it.
    let sync = hhs.sync(&alice.gid, &subscribe(&thread, 50)).expect("sync");
    assert_eq!(sync.lists[0].count, 1);
    assert_eq!(sync.lists[0].threads[0].thread_id, thread);
    assert_eq!(texts(&sync, &thread), ["Hello Alice"]);

    // She verifies the signature herself rather than trusting the server (§12).
    sync.threads[&thread].events[0]
        .verify(&diprish.bundle)
        .expect("recipient verifies the sender's signature");

    send(
        &mut hhs,
        &alice,
        &thread,
        "Hi Diprish",
        "2026-08-09T10:01:00.000Z",
    )
    .expect("reply");
    send(
        &mut hhs,
        &diprish,
        &thread,
        "How did the demo go?",
        "2026-08-09T10:02:00.000Z",
    )
    .expect("third message");

    let sync = hhs
        .sync(&diprish.gid, &subscribe(&thread, 50))
        .expect("sync");
    assert_eq!(
        texts(&sync, &thread),
        ["Hello Alice", "Hi Diprish", "How did the demo go?"]
    );

    // The log is a sound hash chain end to end.
    validate_chain(&sync.threads[&thread].events).expect("chain intact");
}

#[test]
fn sliding_sync_window_returns_only_the_tail() {
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    hhs.register(diprish.bundle.clone()).unwrap();
    hhs.register(alice.bundle.clone()).unwrap();
    hhs.add_contact(&alice.gid, &diprish.gid).unwrap();
    let thread = hhs
        .create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW)
        .unwrap();

    for i in 1..=10 {
        send(
            &mut hhs,
            &diprish,
            &thread,
            &format!("message {i}"),
            &format!("2026-08-09T10:{i:02}:00.000Z"),
        )
        .unwrap();
    }

    let sync = hhs.sync(&alice.gid, &subscribe(&thread, 3)).unwrap();
    assert_eq!(sync.threads[&thread].from_seq, 8);
    assert_eq!(
        texts(&sync, &thread),
        ["message 8", "message 9", "message 10"]
    );

    // A window that starts past the end is empty, not an error.
    let past_end = hhs
        .sync(
            &alice.gid,
            &SyncRequest {
                lists: vec![ListRequest {
                    name: "inbox".into(),
                    range: [5, 10],
                }],
                thread_subscriptions: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();
    assert!(past_end.lists[0].threads.is_empty());
    assert_eq!(past_end.lists[0].count, 1);
}

#[test]
fn non_members_cannot_post_or_read() {
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);
    let mallory = person("mallory", 20);

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    for who in [&diprish, &alice, &mallory] {
        hhs.register(who.bundle.clone()).unwrap();
    }
    hhs.add_contact(&alice.gid, &diprish.gid).unwrap();
    let thread = hhs
        .create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW)
        .unwrap();
    send(
        &mut hhs,
        &diprish,
        &thread,
        "private",
        "2026-08-09T10:00:00.000Z",
    )
    .unwrap();

    let posted = send(
        &mut hhs,
        &mallory,
        &thread,
        "let me in",
        "2026-08-09T10:05:00.000Z",
    )
    .unwrap_err();
    assert!(matches!(posted, ServerError::NotAMember { .. }));
    assert_eq!(posted.error_code(), ErrorCode::TrustDenied);

    // Subscribing to a thread she is not in reveals nothing at all - not even
    // that it exists (spec 6.3: no existence oracle).
    let sync = hhs.sync(&mallory.gid, &subscribe(&thread, 50)).unwrap();
    assert!(sync.threads.is_empty());
    assert_eq!(sync.lists[0].count, 0);
}

#[test]
fn a_stale_position_is_refused_and_the_retry_succeeds() {
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    hhs.register(diprish.bundle.clone()).unwrap();
    hhs.register(alice.bundle.clone()).unwrap();
    hhs.add_contact(&alice.gid, &diprish.gid).unwrap();
    hhs.add_contact(&diprish.gid, &alice.gid).unwrap();
    let thread = hhs
        .create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW)
        .unwrap();

    // Both clients read the same head, then alice lands first.
    let head = hhs.head(&thread).unwrap();
    let stale = EventDraft {
        thread_id: thread.clone(),
        seq: head.seq,
        prev_event: head.prev_event.clone(),
        event_type: EventType::Message,
        sender: diprish.address.clone(),
        origin_server: SERVER.into(),
        created_at: "2026-08-09T10:00:00.000Z".into(),
        content: json!({ "format": "text/herald", "text": "race" }),
        device_key_id: "DEVKEY:0001".into(),
    }
    .sign(&diprish.device)
    .unwrap();

    send(
        &mut hhs,
        &alice,
        &thread,
        "first",
        "2026-08-09T10:00:01.000Z",
    )
    .unwrap();

    let conflict = hhs.submit(stale).unwrap_err();
    assert!(matches!(conflict, ServerError::SeqConflict { .. }));
    assert_eq!(conflict.error_code(), ErrorCode::SeqConflict);

    // Re-reading the head and re-signing is the whole remedy.
    send(
        &mut hhs,
        &diprish,
        &thread,
        "race",
        "2026-08-09T10:00:02.000Z",
    )
    .expect("retry against the new head");

    let sync = hhs.sync(&alice.gid, &subscribe(&thread, 50)).unwrap();
    assert_eq!(texts(&sync, &thread), ["first", "race"]);
}

#[test]
fn a_tampered_event_is_rejected_at_submission() {
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    hhs.register(diprish.bundle.clone()).unwrap();
    hhs.register(alice.bundle.clone()).unwrap();
    hhs.add_contact(&alice.gid, &diprish.gid).unwrap();
    let thread = hhs
        .create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW)
        .unwrap();

    let head = hhs.head(&thread).unwrap();
    let mut event = EventDraft {
        thread_id: thread.clone(),
        seq: head.seq,
        prev_event: head.prev_event,
        event_type: EventType::Message,
        sender: diprish.address.clone(),
        origin_server: SERVER.into(),
        created_at: "2026-08-09T10:00:00.000Z".into(),
        content: json!({ "format": "text/herald", "text": "transfer 100" }),
        device_key_id: "DEVKEY:0001".into(),
    }
    .sign(&diprish.device)
    .unwrap();

    // Rewrite the content and repair the id so only the signature betrays it.
    event.draft.content = json!({ "format": "text/herald", "text": "transfer 100000" });
    event.event_id = event.draft.event_id().unwrap();

    let rejected = hhs.submit(event).unwrap_err();
    assert!(matches!(rejected, ServerError::Event(_)));
    assert_eq!(rejected.error_code(), ErrorCode::SignatureInvalid);
}

#[test]
fn an_unsound_identity_chain_cannot_register() {
    let mut victim = person("diprish", 1);
    let impostor = PrivateKey::from_seed(&[99; 32]);
    victim.bundle.devices = vec![KeyCertificate::issue(
        &impostor,
        victim.gid.clone(),
        "DEVKEY:0001",
        KeyPurpose::Device,
        impostor.public_key(),
    )
    .unwrap()];

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    let rejected = hhs.register(victim.bundle).unwrap_err();
    assert!(matches!(rejected, ServerError::Identity(_)));
    assert_eq!(rejected.error_code(), ErrorCode::IdentityInvalid);
}

#[test]
fn group_threads_are_the_same_object_as_pairs() {
    // Spec 4.3: a thread with N members is the same object as a thread with 2.
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);
    let bob = person("bob", 20);

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    for who in [&diprish, &alice, &bob] {
        hhs.register(who.bundle.clone()).unwrap();
    }
    hhs.add_contact(&alice.gid, &diprish.gid).unwrap();
    hhs.add_contact(&bob.gid, &diprish.gid).unwrap();

    let thread = hhs
        .create_thread(&diprish.address, &[alice.gid.clone(), bob.gid.clone()], NOW)
        .unwrap();

    send(
        &mut hhs,
        &diprish,
        &thread,
        "standup at 10",
        "2026-08-09T09:00:00.000Z",
    )
    .unwrap();
    send(&mut hhs, &bob, &thread, "ack", "2026-08-09T09:01:00.000Z").unwrap();

    for who in [&alice, &bob, &diprish] {
        let sync = hhs.sync(&who.gid, &subscribe(&thread, 50)).unwrap();
        assert_eq!(texts(&sync, &thread), ["standup at 10", "ack"]);
    }
}

#[test]
fn one_untrusting_invitee_blocks_the_whole_thread() {
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);
    let bob = person("bob", 20);

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    for who in [&diprish, &alice, &bob] {
        hhs.register(who.bundle.clone()).unwrap();
    }
    // Alice trusts diprish; bob does not.
    hhs.add_contact(&alice.gid, &diprish.gid).unwrap();

    let refused = hhs
        .create_thread(&diprish.address, &[alice.gid.clone(), bob.gid.clone()], NOW)
        .unwrap_err();
    assert!(matches!(refused, ServerError::TrustDenied { .. }));
}

/// Specification §9: "servers relay and store ciphertext plus unencrypted
/// routing/trust metadata only." This is that claim, checked against what the
/// store actually holds.
#[test]
fn the_server_stores_ciphertext_and_never_the_plaintext() {
    use herald_core::encryption::{decrypt, encrypt, Aad, Entropy};
    use herald_server::store::Store;

    const SECRET: &str = "the acquisition closes on Tuesday";

    let diprish = person("diprish", 1);
    let alice = person("alice", 10);

    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);
    hhs.register(diprish.bundle.clone()).unwrap();
    hhs.register(alice.bundle.clone()).unwrap();
    hhs.add_contact(&alice.gid, &diprish.gid).unwrap();
    let thread = hhs
        .create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW)
        .unwrap();

    // Seal for every device in both parties' published bundles: the recipient's
    // devices, and the sender's own so their other devices can read it too.
    let mut recipients = alice.bundle.recipient_devices().unwrap();
    recipients.extend(diprish.bundle.recipient_devices().unwrap());

    let sender = diprish.address.to_string();
    let aad = Aad {
        thread_id: &thread,
        sender: &sender,
    };
    let sealed = encrypt(
        &json!({ "format": "text/herald", "text": SECRET }),
        aad,
        &recipients,
        &Entropy::from_bytes([77; 32]),
    )
    .unwrap();

    let head = hhs.head(&thread).unwrap();
    let event = EventDraft {
        thread_id: thread.clone(),
        seq: head.seq,
        prev_event: head.prev_event,
        event_type: EventType::Message,
        sender: diprish.address.clone(),
        origin_server: SERVER.into(),
        created_at: "2026-08-09T10:00:00.000Z".into(),
        content: serde_json::to_value(&sealed).unwrap(),
        device_key_id: "DEVKEY:0001".into(),
    }
    .sign(&diprish.device)
    .unwrap();

    hhs.submit(event).unwrap();

    // What the server holds: no plaintext anywhere in the stored event...
    let stored = hhs.store().events(&thread, 1, 10).unwrap();
    let raw = serde_json::to_string(&stored).unwrap();
    assert!(!raw.contains(SECRET), "plaintext reached storage");

    // ...but the routing and trust metadata it needs is still in the clear.
    assert_eq!(stored[0].draft.sender, diprish.address);
    assert_eq!(stored[0].draft.thread_id, thread);
    assert_eq!(stored[0].draft.seq, 1);

    // And the recipient can read it.
    let envelope: herald_core::encryption::EncryptedContent =
        serde_json::from_value(stored[0].draft.content.clone()).unwrap();
    let opened = decrypt(
        &envelope,
        aad,
        &alice.gid,
        "DEVKEY:0001",
        &alice.device_encryption,
    )
    .unwrap();
    assert_eq!(opened["text"], SECRET);

    // A third party who is somehow handed the event still cannot read it.
    let mallory = person("mallory", 20);
    assert!(decrypt(
        &envelope,
        aad,
        &mallory.gid,
        "DEVKEY:0001",
        &mallory.device_encryption
    )
    .is_err());
}
