//! Checks the implementation against the published vectors in `vectors/`.
//!
//! These files are the contract a second implementation builds against, so a
//! change here is a wire-format change. Regenerate deliberately with
//! `cargo run -p herald-core --example gen_vectors`.

use std::path::PathBuf;

use herald_core::canonical::{canonical_hash, canonicalize};
use herald_core::crypto::PrivateKey;
use herald_core::event::{Event, EventDraft};
use herald_core::identity::{IdentityBundle, VerificationLevel};
use herald_core::trust::{
    daily_connection_request_cap, evaluate, ConnectionRequest, Decision, RecipientPolicy,
    SenderInfo, Timestamp,
};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn vectors(file: &Value) -> &Vec<Value> {
    file["vectors"].as_array().expect("vectors array")
}

#[test]
fn canonical_vectors_match() {
    let file = load("canonical.json");
    assert!(!vectors(&file).is_empty());

    for case in vectors(&file) {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];

        let canonical = canonicalize(input).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            canonical,
            case["canonical"].as_str().unwrap(),
            "canonical form changed for {name}"
        );
        assert_eq!(
            hex::encode(canonical_hash(input).unwrap()),
            case["sha512"].as_str().unwrap(),
            "hash changed for {name}"
        );
    }
}

#[test]
fn canonical_rejections_are_refused() {
    let file = load("canonical.json");
    let rejected = file["rejected"].as_array().expect("rejected array");
    assert!(!rejected.is_empty());

    for case in rejected {
        let name = case["name"].as_str().unwrap();
        assert!(
            canonicalize(&case["input"]).is_err(),
            "{name} should have been rejected"
        );
    }
}

#[test]
fn identity_vectors_match() {
    let file = load("identity.json");
    assert!(!vectors(&file).is_empty());

    for case in vectors(&file) {
        let name = case["name"].as_str().unwrap();
        let bundle: IdentityBundle = serde_json::from_value(case["bundle"].clone())
            .unwrap_or_else(|e| panic!("{name}: cannot parse bundle: {e}"));

        let expected = case["verifies"].as_bool().unwrap();
        assert_eq!(
            bundle.verify().is_ok(),
            expected,
            "{name}: verification outcome changed ({:?})",
            bundle.verify()
        );

        if let Some(resolves) = case.get("resolves").and_then(Value::as_object) {
            for (key_id, expected_key) in resolves {
                let resolved = bundle
                    .device_key(key_id)
                    .unwrap_or_else(|e| panic!("{name}: {e}"))
                    .unwrap_or_else(|| panic!("{name}: {key_id} did not resolve"));
                assert_eq!(
                    resolved.to_hex(),
                    expected_key.as_str().unwrap(),
                    "{name}: {key_id} resolved to a different key"
                );
            }
        }
    }
}

#[test]
fn event_vectors_match() {
    let file = load("events.json");
    assert!(!vectors(&file).is_empty());

    let bundle: IdentityBundle =
        serde_json::from_value(file["verification_bundle"].clone()).expect("bundle");
    let device = PrivateKey::from_seed_hex(file["device_seed"].as_str().unwrap()).expect("seed");

    for case in vectors(&file) {
        let name = case["name"].as_str().unwrap();
        let event: Event = serde_json::from_value(case["event"].clone())
            .unwrap_or_else(|e| panic!("{name}: cannot parse event: {e}"));

        assert_eq!(
            event.draft.signing_payload().unwrap(),
            case["signing_payload"].as_str().unwrap(),
            "{name}: signing payload changed"
        );
        assert_eq!(
            event.event_id,
            case["expected_event_id"].as_str().unwrap(),
            "{name}: event id changed"
        );

        event
            .verify(&bundle)
            .unwrap_or_else(|e| panic!("{name}: vector event failed verification: {e}"));

        // Re-signing the same draft must reproduce the committed bytes exactly.
        let draft: EventDraft = serde_json::from_value(case["event"].clone())
            .unwrap_or_else(|e| panic!("{name}: cannot parse draft: {e}"));
        let resigned = draft.sign(&device).unwrap();
        assert_eq!(
            resigned, event,
            "{name}: re-signing produced a different event"
        );
    }
}

#[test]
fn trust_vectors_match() {
    let file = load("trust.json");
    assert!(!vectors(&file).is_empty());

    for case in vectors(&file) {
        let name = case["name"].as_str().unwrap();
        let sender: SenderInfo = serde_json::from_value(case["sender"].clone())
            .unwrap_or_else(|e| panic!("{name}: sender: {e}"));
        let recipient: RecipientPolicy = serde_json::from_value(case["recipient"].clone())
            .unwrap_or_else(|e| panic!("{name}: recipient: {e}"));
        let request: Option<ConnectionRequest> = serde_json::from_value(case["request"].clone())
            .unwrap_or_else(|e| panic!("{name}: request: {e}"));
        let now: Timestamp = case["now"].as_i64().unwrap();
        let expected: Decision = serde_json::from_value(case["expected"].clone())
            .unwrap_or_else(|e| panic!("{name}: expected: {e}"));

        assert_eq!(
            evaluate(&sender, &recipient, request.as_ref(), now),
            expected,
            "{name}: trust decision changed"
        );
    }
}

#[test]
fn adaptive_cap_vectors_match() {
    let file = load("trust.json");
    let cases = file["caps"]["cases"].as_array().expect("cap cases");
    assert!(!cases.is_empty());

    for case in cases {
        let row = case.as_array().expect("cap row");
        let level: VerificationLevel = serde_json::from_value(row[0].clone()).expect("level");
        let rate = row[1].as_f64().expect("rate");
        let age = u32::try_from(row[2].as_u64().expect("age")).expect("age fits");
        let expected = u32::try_from(row[3].as_u64().expect("cap")).expect("cap fits");

        assert_eq!(
            daily_connection_request_cap(level, rate, age),
            expected,
            "cap changed for {level:?} at {rate} over {age} days"
        );
    }
}
