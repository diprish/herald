//! One behavioural contract, two backends.
//!
//! Every case here runs against both [`MemoryStore`] and [`SqliteStore`], so a
//! deployment that swaps its storage does not quietly change what the protocol
//! does. A durable backend additionally has to survive a restart, which the
//! in-memory one cannot be asked about — those cases are at the end.

use herald_core::crypto::PrivateKey;
use herald_core::event::{Event, EventDraft, EventType};
use herald_core::id::{ContextAddress, Gid};
use herald_core::identity::{IdentityBundle, KeyCertificate, KeyPurpose, VerificationLevel};
use herald_core::trust::{ContextGrant, Timestamp};
use herald_server::store::{Account, SqliteStore, Store, Thread};
use herald_server::{Hhs, ListRequest, MemoryStore, Subscription, SyncRequest};
use serde_json::json;

const SERVER: &str = "herald.test";
const NOW: Timestamp = 1_800_000_000;

fn gid(name: &str) -> Gid {
    Gid::parse(name).unwrap()
}

fn bundle(name: &str, seed: u8) -> (IdentityBundle, PrivateKey) {
    let gid = gid(name);
    let identity = PrivateKey::from_seed(&[seed; 32]);
    let self_signing = PrivateKey::from_seed(&[seed + 1; 32]);
    let device = PrivateKey::from_seed(&[seed + 2; 32]);

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
            "DEVKEY:0001",
            KeyPurpose::Device,
            device.public_key(),
        )
        .unwrap()],
    };
    (bundle, device)
}

fn event(thread_id: &str, seq: u64, prev: Option<String>, at: &str, device: &PrivateKey) -> Event {
    EventDraft {
        thread_id: thread_id.to_owned(),
        seq,
        prev_event: prev,
        event_type: EventType::Message,
        sender: ContextAddress::parse("diprish").unwrap(),
        origin_server: SERVER.to_owned(),
        created_at: at.to_owned(),
        content: json!({ "text": format!("message {seq}") }),
        device_key_id: "DEVKEY:0001".to_owned(),
    }
    .sign(device)
    .unwrap()
}

/// Runs one case against both backends.
fn for_each_store(case: impl Fn(&mut dyn Store, &str)) {
    case(&mut MemoryStore::new(), "MemoryStore");
    case(&mut SqliteStore::open_in_memory().unwrap(), "SqliteStore");
}

#[test]
fn identities_round_trip() {
    for_each_store(|store, name| {
        let (bundle, _) = bundle("diprish", 1);
        assert_eq!(store.identity(&gid("diprish")).unwrap(), None, "{name}");

        store.put_identity(bundle.clone()).unwrap();
        assert_eq!(
            store.identity(&gid("diprish")).unwrap(),
            Some(bundle),
            "{name}: bundle did not round-trip"
        );
    });
}

#[test]
fn republishing_an_identity_replaces_it() {
    for_each_store(|store, name| {
        let (first, _) = bundle("diprish", 1);
        let (second, _) = bundle("diprish", 40);
        store.put_identity(first).unwrap();
        store.put_identity(second.clone()).unwrap();
        assert_eq!(
            store.identity(&gid("diprish")).unwrap(),
            Some(second),
            "{name}"
        );
    });
}

#[test]
fn a_missing_account_reads_as_the_closed_default() {
    for_each_store(|store, name| {
        let account = store.account(&gid("nobody")).unwrap();
        assert_eq!(account, Account::default(), "{name}");
        assert!(account.policy.contacts.is_empty(), "{name}");
    });
}

#[test]
fn accounts_round_trip_with_contexts_and_policy() {
    for_each_store(|store, name| {
        let mut account = Account::default();
        account.policy.contacts.insert(gid("alice"));
        account.contexts.push(ContextGrant {
            gid: gid("diprish"),
            context: herald_core::id::ContextName::parse("deloitte").unwrap(),
            authority: Some("deloitte".into()),
            valid_until: NOW + 1000,
            revoked_at: None,
        });

        store.put_account(&gid("diprish"), account.clone()).unwrap();
        assert_eq!(store.account(&gid("diprish")).unwrap(), account, "{name}");
    });
}

#[test]
fn threads_round_trip_with_ordered_membership() {
    for_each_store(|store, name| {
        let thread = Thread {
            thread_id: "!t1:herald.test".into(),
            creator: ContextAddress::parse("diprish:deloitte").unwrap(),
            members: vec![gid("diprish"), gid("alice"), gid("bob")],
            sequencing_server: SERVER.into(),
        };
        store.put_thread(thread.clone()).unwrap();

        let loaded = store.thread("!t1:herald.test").unwrap().unwrap();
        assert_eq!(loaded, thread, "{name}: membership order must be preserved");
        assert!(loaded.has_member(&gid("bob")), "{name}");
        assert!(!loaded.has_member(&gid("mallory")), "{name}");
        assert_eq!(
            store.thread("!missing:herald.test").unwrap(),
            None,
            "{name}"
        );
    });
}

#[test]
fn an_empty_thread_starts_at_the_first_sequence_number() {
    for_each_store(|store, name| {
        let head = store.head("!t1:herald.test").unwrap();
        assert_eq!(head.seq, herald_core::log::FIRST_SEQ, "{name}");
        assert_eq!(head.prev_event, None, "{name}");
    });
}

#[test]
fn appending_advances_the_head() {
    for_each_store(|store, name| {
        let (_, device) = bundle("diprish", 1);
        let first = event(
            "!t1:herald.test",
            1,
            None,
            "2026-08-09T10:00:00.000Z",
            &device,
        );
        store.append_event(first.clone()).unwrap();

        let head = store.head("!t1:herald.test").unwrap();
        assert_eq!(head.seq, 2, "{name}");
        assert_eq!(head.prev_event, Some(first.event_id.clone()), "{name}");

        let second = event(
            "!t1:herald.test",
            2,
            Some(first.event_id.clone()),
            "2026-08-09T10:01:00.000Z",
            &device,
        );
        store.append_event(second.clone()).unwrap();
        assert_eq!(store.head("!t1:herald.test").unwrap().seq, 3, "{name}");

        // Stored events must come back byte-identical, signatures included.
        let events = store.events("!t1:herald.test", 1, 100).unwrap();
        assert_eq!(events, vec![first, second], "{name}");
    });
}

#[test]
fn event_windows_respect_offset_and_limit() {
    for_each_store(|store, name| {
        let (_, device) = bundle("diprish", 1);
        let mut prev = None;
        for seq in 1..=10 {
            let e = event(
                "!t1:herald.test",
                seq,
                prev,
                &format!("2026-08-09T10:{seq:02}:00.000Z"),
                &device,
            );
            prev = Some(e.event_id.clone());
            store.append_event(e).unwrap();
        }

        let window = store.events("!t1:herald.test", 8, 3).unwrap();
        assert_eq!(window.len(), 3, "{name}");
        assert_eq!(window[0].draft.seq, 8, "{name}");
        assert_eq!(window[2].draft.seq, 10, "{name}");

        assert!(
            store.events("!t1:herald.test", 99, 10).unwrap().is_empty(),
            "{name}"
        );
        assert!(
            store
                .events("!missing:herald.test", 1, 10)
                .unwrap()
                .is_empty(),
            "{name}"
        );
    });
}

#[test]
fn thread_lists_are_scoped_to_members_and_ordered_by_recency() {
    for_each_store(|store, name| {
        let (_, device) = bundle("diprish", 1);

        for (thread_id, at) in [
            ("!old:herald.test", "2026-08-01T00:00:00.000Z"),
            ("!new:herald.test", "2026-08-09T00:00:00.000Z"),
        ] {
            store
                .put_thread(Thread {
                    thread_id: thread_id.into(),
                    creator: ContextAddress::parse("diprish").unwrap(),
                    members: vec![gid("diprish"), gid("alice")],
                    sequencing_server: SERVER.into(),
                })
                .unwrap();
            store
                .append_event(event(thread_id, 1, None, at, &device))
                .unwrap();
        }

        // A thread alice is not in must not appear in her list.
        store
            .put_thread(Thread {
                thread_id: "!private:herald.test".into(),
                creator: ContextAddress::parse("diprish").unwrap(),
                members: vec![gid("diprish")],
                sequencing_server: SERVER.into(),
            })
            .unwrap();
        store
            .append_event(event(
                "!private:herald.test",
                1,
                None,
                "2026-08-10T00:00:00.000Z",
                &device,
            ))
            .unwrap();

        let alice: Vec<String> = store
            .threads_for(&gid("alice"))
            .unwrap()
            .into_iter()
            .map(|summary| summary.thread_id)
            .collect();
        assert_eq!(alice, ["!new:herald.test", "!old:herald.test"], "{name}");

        assert_eq!(
            store.threads_for(&gid("diprish")).unwrap().len(),
            3,
            "{name}"
        );
        assert!(
            store.threads_for(&gid("mallory")).unwrap().is_empty(),
            "{name}"
        );
    });
}

#[test]
fn a_thread_with_no_events_is_not_listed() {
    for_each_store(|store, name| {
        store
            .put_thread(Thread {
                thread_id: "!silent:herald.test".into(),
                creator: ContextAddress::parse("diprish").unwrap(),
                members: vec![gid("diprish")],
                sequencing_server: SERVER.into(),
            })
            .unwrap();
        assert!(
            store.threads_for(&gid("diprish")).unwrap().is_empty(),
            "{name}"
        );
    });
}

#[test]
fn thread_numbers_are_never_reused() {
    for_each_store(|store, name| {
        let allocated: Vec<u64> = (0..5)
            .map(|_| store.allocate_thread_number().unwrap())
            .collect();
        let mut sorted = allocated.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), allocated.len(), "{name}: numbers repeated");
    });
}

/// The whole point of a durable store: state outlives the process.
#[test]
fn sqlite_state_survives_a_restart() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let (bundle_value, device) = bundle("diprish", 1);

    {
        let mut store = SqliteStore::open(file.path()).unwrap();
        store.put_identity(bundle_value.clone()).unwrap();

        let mut account = Account::default();
        account.policy.contacts.insert(gid("alice"));
        store.put_account(&gid("diprish"), account).unwrap();

        store
            .put_thread(Thread {
                thread_id: "!t1:herald.test".into(),
                creator: ContextAddress::parse("diprish").unwrap(),
                members: vec![gid("diprish"), gid("alice")],
                sequencing_server: SERVER.into(),
            })
            .unwrap();
        store
            .append_event(event(
                "!t1:herald.test",
                1,
                None,
                "2026-08-09T10:00:00.000Z",
                &device,
            ))
            .unwrap();
    }

    let reopened = SqliteStore::open(file.path()).unwrap();
    assert_eq!(
        reopened.identity(&gid("diprish")).unwrap(),
        Some(bundle_value)
    );
    assert!(reopened
        .account(&gid("diprish"))
        .unwrap()
        .policy
        .contacts
        .contains(&gid("alice")));
    assert_eq!(reopened.head("!t1:herald.test").unwrap().seq, 2);

    let events = reopened.events("!t1:herald.test", 1, 10).unwrap();
    assert_eq!(events.len(), 1);
    // A recovered event must still verify: storage round-tripped the exact bytes.
    let (published, _) = bundle("diprish", 1);
    events[0]
        .verify(&published)
        .expect("signature survives storage");
}

/// A whole conversation, conducted against a file-backed server, then re-read
/// by a server that starts fresh from the same file.
#[test]
fn a_conversation_survives_a_server_restart() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let (diprish, diprish_device) = bundle("diprish", 1);
    let (alice, _) = bundle("alice", 10);
    let thread_id;

    {
        let mut hhs = Hhs::new(SqliteStore::open(file.path()).unwrap(), SERVER);
        hhs.register(diprish.clone()).unwrap();
        hhs.register(alice.clone()).unwrap();
        hhs.add_contact(&gid("alice"), &gid("diprish")).unwrap();

        thread_id = hhs
            .create_thread(
                &ContextAddress::parse("diprish").unwrap(),
                &[gid("alice")],
                NOW,
            )
            .unwrap();

        let head = hhs.head(&thread_id).unwrap();
        hhs.submit(event(
            &thread_id,
            head.seq,
            head.prev_event,
            "2026-08-09T10:00:00.000Z",
            &diprish_device,
        ))
        .unwrap();
    }

    let hhs = Hhs::new(SqliteStore::open(file.path()).unwrap(), SERVER);
    let sync = hhs
        .sync(
            &gid("alice"),
            &SyncRequest {
                lists: vec![ListRequest {
                    name: "inbox".into(),
                    range: [0, 30],
                }],
                thread_subscriptions: [(thread_id.clone(), Subscription { timeline_limit: 50 })]
                    .into_iter()
                    .collect(),
            },
        )
        .unwrap();

    assert_eq!(sync.lists[0].count, 1);
    assert_eq!(sync.threads[&thread_id].events.len(), 1);
    sync.threads[&thread_id].events[0]
        .verify(&diprish)
        .expect("event recovered from disk still verifies");
}

/// A restarted server must not mint a thread id that already exists.
#[test]
fn thread_ids_do_not_collide_across_a_restart() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let (diprish, _) = bundle("diprish", 1);
    let (alice, _) = bundle("alice", 10);
    let creator = ContextAddress::parse("diprish").unwrap();

    let first = {
        let mut hhs = Hhs::new(SqliteStore::open(file.path()).unwrap(), SERVER);
        hhs.register(diprish.clone()).unwrap();
        hhs.register(alice.clone()).unwrap();
        hhs.add_contact(&gid("alice"), &gid("diprish")).unwrap();
        hhs.create_thread(&creator, &[gid("alice")], NOW).unwrap()
    };

    let second = {
        let mut hhs = Hhs::new(SqliteStore::open(file.path()).unwrap(), SERVER);
        hhs.create_thread(&creator, &[gid("alice")], NOW).unwrap()
    };

    assert_ne!(first, second, "a restart reissued a thread id");
}
