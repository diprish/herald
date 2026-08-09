//! A narrated HERALD conversation, run against an in-process home server.
//!
//! Everything printed here is the real protocol: cross-signed identities,
//! trust-chain admission, device-signed events, server-side verification, and
//! a sliding-sync read-back that the recipient verifies for itself.
//!
//! ```sh
//! cargo run -p herald-cli
//! ```

use std::collections::BTreeMap;

use herald_core::crypto::PrivateKey;
use herald_core::event::{EventDraft, EventType};
use herald_core::id::{ContextAddress, Gid};
use herald_core::identity::{IdentityBundle, KeyCertificate, KeyPurpose, VerificationLevel};
use herald_server::{Hhs, ListRequest, MemoryStore, ServerError, Subscription, SyncRequest};
use serde_json::json;

const SERVER: &str = "herald.example.com";
const NOW: i64 = 1_800_000_000;

struct Person {
    gid: Gid,
    address: ContextAddress,
    device: PrivateKey,
    bundle: IdentityBundle,
}

fn person(name: &str, seed: u8) -> Result<Person, Box<dyn std::error::Error>> {
    let gid = Gid::parse(name)?;
    let identity = PrivateKey::from_seed(&[seed; 32]);
    let self_signing = PrivateKey::from_seed(&[seed + 1; 32]);
    let device = PrivateKey::from_seed(&[seed + 2; 32]);

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
        )?,
        devices: vec![KeyCertificate::issue(
            &self_signing,
            gid.clone(),
            "DEVKEY:0001",
            KeyPurpose::Device,
            device.public_key(),
        )?],
    };

    Ok(Person {
        address: ContextAddress::parse(name)?,
        gid,
        device,
        bundle,
    })
}

fn send(
    hhs: &mut Hhs<MemoryStore>,
    from: &Person,
    thread_id: &str,
    text: &str,
    at: &str,
) -> Result<String, ServerError> {
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

    let event_id = event.event_id.clone();
    hhs.submit(event)?;
    Ok(event_id)
}

fn step(n: u8, title: &str) {
    println!("\n[{n}] {title}");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("HERALD demo - two identities, one server, every event signed.");

    let diprish = person("diprish", 1)?;
    let alice = person("alice", 10)?;
    let mut hhs = Hhs::new(MemoryStore::new(), SERVER);

    step(1, "Register identities (Level 0: instant, no user effort)");
    for who in [&diprish, &alice] {
        hhs.register(who.bundle.clone())?;
        println!(
            "    {:<10} identity key {}...  device DEVKEY:0001",
            who.gid.as_str(),
            &who.bundle.identity_key.to_hex()[..16]
        );
    }
    println!("    the server verified each cross-signing chain before accepting it");

    step(2, "Try to open a thread with no trust (cold contact)");
    match hhs.create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW) {
        Ok(_) => println!("    unexpectedly admitted"),
        Err(error) => println!("    refused: {} - {error}", error.error_code()),
    }

    step(3, "Alice adds diprish as a contact (Tier 1 trust)");
    hhs.add_contact(&alice.gid, &diprish.gid)?;
    println!("    alice's trust chain now admits diprish");

    step(4, "Open the thread");
    let thread = hhs.create_thread(&diprish.address, std::slice::from_ref(&alice.gid), NOW)?;
    println!("    {thread}");

    step(5, "Exchange messages");
    for (who, text, at) in [
        (
            &diprish,
            "Hello Alice - first message on HERALD.",
            "2026-08-09T10:00:00.000Z",
        ),
        (
            &alice,
            "Hi Diprish. No spam filter involved.",
            "2026-08-09T10:01:00.000Z",
        ),
        (
            &diprish,
            "None needed - you admitted me first.",
            "2026-08-09T10:02:00.000Z",
        ),
    ] {
        let event_id = send(&mut hhs, who, &thread, text, at)?;
        println!("    {:<10} -> {}", who.gid.as_str(), &event_id[..24]);
    }

    step(6, "Alice syncs (sliding window, last 2 events)");
    let request = SyncRequest {
        lists: vec![ListRequest {
            name: "inbox".into(),
            range: [0, 30],
        }],
        thread_subscriptions: BTreeMap::from([(
            thread.clone(),
            Subscription { timeline_limit: 2 },
        )]),
    };
    let sync = hhs.sync(&alice.gid, &request)?;
    println!(
        "    inbox: {} thread(s); window starts at seq {}",
        sync.lists[0].count, sync.threads[&thread].from_seq
    );

    step(
        7,
        "Alice verifies each event herself, not trusting the server",
    );
    for event in &sync.threads[&thread].events {
        let sender = if event.draft.sender.gid() == &diprish.gid {
            &diprish
        } else {
            &alice
        };
        event.verify(&sender.bundle)?;
        println!(
            "    seq {}  {:<10} verified  {}",
            event.draft.seq,
            event.draft.sender.to_string(),
            event.draft.content["text"].as_str().unwrap_or_default()
        );
    }

    step(8, "An outsider tries to post");
    let mallory = person("mallory", 20)?;
    hhs.register(mallory.bundle.clone())?;
    match send(
        &mut hhs,
        &mallory,
        &thread,
        "let me in",
        "2026-08-09T10:03:00.000Z",
    ) {
        Ok(_) => println!("    unexpectedly accepted"),
        Err(error) => println!("    refused: {} - {error}", error.error_code()),
    }

    println!("\nDone. Cold sending never happened; every delivered event was signed and verified.");
    Ok(())
}
