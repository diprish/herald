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

use herald_core::crypto::{EncryptionPrivateKey, PrivateKey};
use herald_core::encryption::{decrypt, encrypt, Aad, EncryptedContent, Entropy};
use herald_core::event::{EventDraft, EventType};
use herald_core::id::{ContextAddress, Gid};
use herald_core::identity::{IdentityBundle, KeyCertificate, KeyPurpose, VerificationLevel};
use herald_server::{Hhs, ListRequest, MemoryStore, Subscription, SyncRequest};
use serde_json::json;

const SERVER: &str = "herald.example.com";
const NOW: i64 = 1_800_000_000;

struct Person {
    gid: Gid,
    address: ContextAddress,
    device: PrivateKey,
    device_encryption: EncryptionPrivateKey,
    bundle: IdentityBundle,
}

fn person(name: &str, seed: u8) -> Result<Person, Box<dyn std::error::Error>> {
    let gid = Gid::parse(name)?;
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
        )?,
        devices: vec![KeyCertificate::issue_device(
            &self_signing,
            gid.clone(),
            "DEVKEY:0001",
            device.public_key(),
            device_encryption.public_key(),
        )?],
    };

    Ok(Person {
        address: ContextAddress::parse(name)?,
        gid,
        device,
        device_encryption,
        bundle,
    })
}

/// Seals the message for every device in the thread's members, signs it, and
/// submits. `entropy` stands in for a fresh draw from the host's RNG.
fn send(
    hhs: &mut Hhs<MemoryStore>,
    from: &Person,
    to: &[&Person],
    thread_id: &str,
    text: &str,
    at: &str,
    entropy: u8,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut recipients = from.bundle.recipient_devices()?;
    for person in to {
        recipients.extend(person.bundle.recipient_devices()?);
    }

    let sender = from.address.to_string();
    let sealed = encrypt(
        &json!({ "format": "text/herald", "text": text }),
        Aad {
            thread_id,
            sender: &sender,
        },
        &recipients,
        &Entropy::from_bytes([entropy; 32]),
    )?;

    let head = hhs.head(thread_id)?;
    let event = EventDraft {
        thread_id: thread_id.to_owned(),
        seq: head.seq,
        prev_event: head.prev_event,
        event_type: EventType::Message,
        sender: from.address.clone(),
        origin_server: SERVER.to_owned(),
        created_at: at.to_owned(),
        content: serde_json::to_value(&sealed)?,
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

    step(5, "Exchange messages, end-to-end encrypted");
    for (who, other, text, at, entropy) in [
        (
            &diprish,
            &alice,
            "Hello Alice - first message on HERALD.",
            "2026-08-09T10:00:00.000Z",
            60u8,
        ),
        (
            &alice,
            &diprish,
            "Hi Diprish. No spam filter involved.",
            "2026-08-09T10:01:00.000Z",
            61,
        ),
        (
            &diprish,
            &alice,
            "None needed - you admitted me first.",
            "2026-08-09T10:02:00.000Z",
            62,
        ),
    ] {
        let event_id = send(&mut hhs, who, &[other], &thread, text, at, entropy)?;
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

    step(7, "What the server holds is ciphertext (spec 9)");
    let stored = &sync.threads[&thread].events[0];
    let envelope: EncryptedContent = serde_json::from_value(stored.draft.content.clone())?;
    println!("    algorithm    {}", envelope.algorithm);
    println!("    sealed for   {} device(s)", envelope.recipients.len());
    println!(
        "    ciphertext   {}...",
        &envelope.ciphertext[..envelope.ciphertext.len().min(40)]
    );
    println!(
        "    in the clear only: sender={} thread={}... seq={}",
        stored.draft.sender,
        &stored.draft.thread_id[..8],
        stored.draft.seq
    );

    step(8, "Alice verifies and decrypts each event herself");
    for event in &sync.threads[&thread].events {
        let sender = if event.draft.sender.gid() == &diprish.gid {
            &diprish
        } else {
            &alice
        };
        event.verify(&sender.bundle)?;

        let envelope: EncryptedContent = serde_json::from_value(event.draft.content.clone())?;
        let opened = decrypt(
            &envelope,
            Aad {
                thread_id: &thread,
                sender: &event.draft.sender.to_string(),
            },
            &alice.gid,
            "DEVKEY:0001",
            &alice.device_encryption,
        )?;
        println!(
            "    seq {}  {:<10} verified + decrypted  {}",
            event.draft.seq,
            event.draft.sender.to_string(),
            opened["text"].as_str().unwrap_or_default()
        );
    }

    step(9, "An outsider tries to post");
    let mallory = person("mallory", 20)?;
    hhs.register(mallory.bundle.clone())?;
    match send(
        &mut hhs,
        &mallory,
        &[],
        &thread,
        "let me in",
        "2026-08-09T10:03:00.000Z",
        63,
    ) {
        Ok(_) => println!("    unexpectedly accepted"),
        Err(error) => println!("    refused: {error}"),
    }

    println!();
    println!("Done. Cold sending never happened, every delivered event was signed and");
    println!("verified, and the server never held the plaintext.");
    Ok(())
}
