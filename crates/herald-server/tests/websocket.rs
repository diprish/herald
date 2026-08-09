//! End-to-end over a real WebSocket: two clients connect to a listening
//! server, negotiate a version, register, form trust, and exchange messages —
//! with the second client receiving the first's message as a *push*, not a poll.

use std::collections::BTreeMap;

use futures_util::{SinkExt, StreamExt};
use herald_core::crypto::PrivateKey;
use herald_core::event::{EventDraft, EventType};
use herald_core::id::{ContextAddress, Gid};
use herald_core::identity::{IdentityBundle, KeyCertificate, KeyPurpose, VerificationLevel};
use herald_server::store::Store;
use herald_server::{
    router, AppState, ClientFrame, Hhs, ListRequest, MemoryStore, ServerFrame, SqliteStore,
    Subscription, SyncRequest,
};
use serde_json::json;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

const SERVER: &str = "herald.test";

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Person {
    address: ContextAddress,
    device: PrivateKey,
    bundle: IdentityBundle,
}

fn person(name: &str, seed: u8) -> Person {
    let gid = Gid::parse(name).unwrap();
    let identity = PrivateKey::from_seed(&[seed; 32]);
    let self_signing = PrivateKey::from_seed(&[seed + 1; 32]);
    let device = PrivateKey::from_seed(&[seed + 2; 32]);

    Person {
        address: ContextAddress::parse(name).unwrap(),
        device: device.clone(),
        bundle: IdentityBundle {
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
            .unwrap(),
            devices: vec![KeyCertificate::issue(
                &self_signing,
                gid.clone(),
                "DEVKEY:0001",
                KeyPurpose::Device,
                device.public_key(),
            )
            .unwrap()],
        },
    }
}

/// Starts a server on an ephemeral port and returns its WebSocket URL.
async fn serve(dev_auth: bool) -> String {
    serve_with(MemoryStore::new(), dev_auth).await.0
}

/// Starts a server backed by `store`, returning its URL and a handle so the
/// caller can stop it.
async fn serve_with<S: Store + Send + 'static>(
    store: S,
    dev_auth: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    let state = AppState::new(Hhs::new(store, SERVER), dev_auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    (format!("ws://{addr}/hcs/v1/ws"), handle)
}

async fn send(socket: &mut Socket, frame: &ClientFrame) {
    socket
        .send(Message::Text(serde_json::to_string(frame).unwrap().into()))
        .await
        .unwrap();
}

async fn recv(socket: &mut Socket) -> ServerFrame {
    loop {
        let message = socket.next().await.expect("stream open").expect("no error");
        if let Message::Text(text) = message {
            return serde_json::from_str(&text).expect("server frame");
        }
    }
}

/// Connects, reads `hello`, negotiates, and returns the ready socket.
async fn connect(url: &str, as_identity: &str) -> Socket {
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();

    match recv(&mut socket).await {
        ServerFrame::Hello {
            server_name,
            supported_versions,
        } => {
            assert_eq!(server_name, SERVER);
            assert!(supported_versions.contains(&"1.1".to_owned()));
        }
        other => panic!("expected hello, got {other:?}"),
    }

    send(
        &mut socket,
        &ClientFrame::SelectVersion {
            versions: vec!["1.0".into(), "1.1".into()],
            identity: as_identity.to_owned(),
        },
    )
    .await;

    match recv(&mut socket).await {
        ServerFrame::Ready { version, identity } => {
            assert_eq!(version, "1.1");
            assert_eq!(identity, as_identity);
        }
        other => panic!("expected ready, got {other:?}"),
    }
    socket
}

async fn expect_ack(socket: &mut Socket, expected_id: u64) {
    match recv(socket).await {
        ServerFrame::Ack { id } => assert_eq!(id, expected_id),
        other => panic!("expected ack {expected_id}, got {other:?}"),
    }
}

/// Reads the head, signs an event claiming that position, and submits it.
async fn post(socket: &mut Socket, from: &Person, thread_id: &str, text: &str, id: u64) {
    send(
        socket,
        &ClientFrame::Head {
            id,
            thread_id: thread_id.to_owned(),
        },
    )
    .await;

    let (seq, prev_event) = match recv(socket).await {
        ServerFrame::Head {
            seq, prev_event, ..
        } => (seq, prev_event),
        other => panic!("expected head, got {other:?}"),
    };

    let event = EventDraft {
        thread_id: thread_id.to_owned(),
        seq,
        prev_event,
        event_type: EventType::Message,
        sender: from.address.clone(),
        origin_server: SERVER.to_owned(),
        created_at: format!("2026-08-09T10:{id:02}:00.000Z"),
        content: json!({ "format": "text/herald", "text": text }),
        device_key_id: "DEVKEY:0001".to_owned(),
    }
    .sign(&from.device)
    .unwrap();

    send(
        socket,
        &ClientFrame::Submit {
            id: id + 1,
            event: Box::new(event),
        },
    )
    .await;
    expect_ack(socket, id + 1).await;
}

#[tokio::test]
async fn two_clients_converse_over_websockets_with_push_delivery() {
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);
    let url = serve(true).await;

    let mut d = connect(&url, "diprish").await;
    let mut a = connect(&url, "alice").await;

    // Both publish their key bundles.
    send(
        &mut d,
        &ClientFrame::Register {
            id: 1,
            bundle: Box::new(diprish.bundle.clone()),
        },
    )
    .await;
    expect_ack(&mut d, 1).await;

    send(
        &mut a,
        &ClientFrame::Register {
            id: 1,
            bundle: Box::new(alice.bundle.clone()),
        },
    )
    .await;
    expect_ack(&mut a, 1).await;

    // With no trust, opening a thread is refused.
    send(
        &mut d,
        &ClientFrame::CreateThread {
            id: 2,
            invitees: vec!["alice".into()],
        },
    )
    .await;
    match recv(&mut d).await {
        ServerFrame::Error { id, code, .. } => {
            assert_eq!(id, Some(2));
            assert_eq!(code, "TRUST_DENIED");
        }
        other => panic!("expected refusal, got {other:?}"),
    }

    // Alice adds diprish as a contact, then the thread opens.
    send(
        &mut a,
        &ClientFrame::AddContact {
            id: 2,
            contact: "diprish".into(),
        },
    )
    .await;
    expect_ack(&mut a, 2).await;

    send(
        &mut d,
        &ClientFrame::CreateThread {
            id: 3,
            invitees: vec!["alice".into()],
        },
    )
    .await;
    let thread = match recv(&mut d).await {
        ServerFrame::Thread { id, thread_id } => {
            assert_eq!(id, 3);
            thread_id
        }
        other => panic!("expected thread, got {other:?}"),
    };

    post(&mut d, &diprish, &thread, "Hello over a socket", 10).await;

    // Alice receives it as a push, without having asked.
    match recv(&mut a).await {
        ServerFrame::Event { event } => {
            assert_eq!(event.draft.content["text"], "Hello over a socket");
            event
                .verify(&diprish.bundle)
                .expect("recipient verifies the sender's signature");
        }
        other => panic!("expected pushed event, got {other:?}"),
    }

    // She replies, and diprish is pushed her reply in turn.
    post(&mut a, &alice, &thread, "Received, verified", 20).await;
    match recv(&mut d).await {
        ServerFrame::Event { event } => {
            assert_eq!(event.draft.content["text"], "Received, verified");
        }
        other => panic!("expected pushed event, got {other:?}"),
    }

    // Sync agrees with what was pushed.
    send(
        &mut a,
        &ClientFrame::Sync {
            id: 30,
            request: Box::new(SyncRequest {
                lists: vec![ListRequest {
                    name: "inbox".into(),
                    range: [0, 30],
                }],
                thread_subscriptions: BTreeMap::from([(
                    thread.clone(),
                    Subscription { timeline_limit: 50 },
                )]),
            }),
        },
    )
    .await;

    match recv(&mut a).await {
        ServerFrame::Sync { id, response } => {
            assert_eq!(id, 30);
            assert_eq!(response.lists[0].count, 1);
            let texts: Vec<&str> = response.threads[&thread]
                .events
                .iter()
                .map(|event| event.draft.content["text"].as_str().unwrap())
                .collect();
            assert_eq!(texts, ["Hello over a socket", "Received, verified"]);
        }
        other => panic!("expected sync, got {other:?}"),
    }
}

#[tokio::test]
async fn a_client_with_no_mutual_version_is_refused() {
    let url = serve(true).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let _hello = recv(&mut socket).await;

    send(
        &mut socket,
        &ClientFrame::SelectVersion {
            versions: vec!["0.9".into()],
            identity: "diprish".into(),
        },
    )
    .await;

    match recv(&mut socket).await {
        ServerFrame::Error { code, .. } => assert_eq!(code, "VERSION_UNSUPPORTED"),
        other => panic!("expected version refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn requests_before_negotiation_are_refused() {
    let url = serve(true).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let _hello = recv(&mut socket).await;

    send(
        &mut socket,
        &ClientFrame::Head {
            id: 1,
            thread_id: "!nope:herald.test".into(),
        },
    )
    .await;

    match recv(&mut socket).await {
        ServerFrame::Error { code, .. } => assert_eq!(code, "NOT_READY"),
        other => panic!("expected not-ready, got {other:?}"),
    }
}

#[tokio::test]
async fn a_server_without_dev_auth_refuses_every_connection() {
    let url = serve(false).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let _hello = recv(&mut socket).await;

    send(
        &mut socket,
        &ClientFrame::SelectVersion {
            versions: vec!["1.1".into()],
            identity: "diprish".into(),
        },
    )
    .await;

    match recv(&mut socket).await {
        ServerFrame::Error { code, .. } => assert_eq!(code, "UNAUTHORIZED"),
        other => panic!("expected unauthorized, got {other:?}"),
    }
}

#[tokio::test]
async fn pushes_do_not_leak_to_non_members() {
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);
    let mallory = person("mallory", 20);
    let url = serve(true).await;

    let mut d = connect(&url, "diprish").await;
    let mut a = connect(&url, "alice").await;
    let mut m = connect(&url, "mallory").await;

    for (socket, who) in [(&mut d, &diprish), (&mut a, &alice), (&mut m, &mallory)] {
        send(
            socket,
            &ClientFrame::Register {
                id: 1,
                bundle: Box::new(who.bundle.clone()),
            },
        )
        .await;
        expect_ack(socket, 1).await;
    }

    send(
        &mut a,
        &ClientFrame::AddContact {
            id: 2,
            contact: "diprish".into(),
        },
    )
    .await;
    expect_ack(&mut a, 2).await;

    send(
        &mut d,
        &ClientFrame::CreateThread {
            id: 3,
            invitees: vec!["alice".into()],
        },
    )
    .await;
    let thread = match recv(&mut d).await {
        ServerFrame::Thread { thread_id, .. } => thread_id,
        other => panic!("expected thread, got {other:?}"),
    };

    post(&mut d, &diprish, &thread, "members only", 10).await;

    // Alice is pushed the event.
    match recv(&mut a).await {
        ServerFrame::Event { event } => {
            assert_eq!(event.draft.content["text"], "members only");
        }
        other => panic!("expected pushed event, got {other:?}"),
    }

    // Mallory is not. Her own request round-trips first, proving her socket is
    // live and simply was not sent the event rather than merely being slow.
    send(
        &mut m,
        &ClientFrame::Sync {
            id: 99,
            request: Box::new(SyncRequest::default()),
        },
    )
    .await;
    match recv(&mut m).await {
        ServerFrame::Sync { id, response } => {
            assert_eq!(id, 99);
            assert!(response.threads.is_empty());
        }
        other => panic!("expected only her own sync, got {other:?}"),
    }
}

/// A conversation held over a socket against a file-backed server is still
/// there after that server is stopped and a new one starts on the same file.
#[tokio::test]
async fn state_survives_a_server_restart() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let diprish = person("diprish", 1);
    let alice = person("alice", 10);

    let thread = {
        let (url, server) = serve_with(SqliteStore::open(file.path()).unwrap(), true).await;
        let mut d = connect(&url, "diprish").await;
        let mut a = connect(&url, "alice").await;

        for (socket, who) in [(&mut d, &diprish), (&mut a, &alice)] {
            send(
                socket,
                &ClientFrame::Register {
                    id: 1,
                    bundle: Box::new(who.bundle.clone()),
                },
            )
            .await;
            expect_ack(socket, 1).await;
        }

        send(
            &mut a,
            &ClientFrame::AddContact {
                id: 2,
                contact: "diprish".into(),
            },
        )
        .await;
        expect_ack(&mut a, 2).await;

        send(
            &mut d,
            &ClientFrame::CreateThread {
                id: 3,
                invitees: vec!["alice".into()],
            },
        )
        .await;
        let thread = match recv(&mut d).await {
            ServerFrame::Thread { thread_id, .. } => thread_id,
            other => panic!("expected thread, got {other:?}"),
        };

        post(&mut d, &diprish, &thread, "written to disk", 10).await;
        server.abort();
        thread
    };

    // A brand-new server process, same database file.
    let (url, _server) = serve_with(SqliteStore::open(file.path()).unwrap(), true).await;
    let mut a = connect(&url, "alice").await;

    send(
        &mut a,
        &ClientFrame::Sync {
            id: 50,
            request: Box::new(SyncRequest {
                lists: vec![ListRequest {
                    name: "inbox".into(),
                    range: [0, 30],
                }],
                thread_subscriptions: BTreeMap::from([(
                    thread.clone(),
                    Subscription { timeline_limit: 50 },
                )]),
            }),
        },
    )
    .await;

    match recv(&mut a).await {
        ServerFrame::Sync { response, .. } => {
            assert_eq!(response.lists[0].count, 1, "thread lost across restart");
            let events = &response.threads[&thread].events;
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].draft.content["text"], "written to disk");
            events[0]
                .verify(&diprish.bundle)
                .expect("signature survives a restart");
        }
        other => panic!("expected sync, got {other:?}"),
    }
}
