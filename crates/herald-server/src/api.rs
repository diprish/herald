//! The HERALD Client-Server API (HCS) over WebSocket (§7.1, §8.2, §8.3).
//!
//! A connection opens with the server's `HELLO` announcing its supported
//! protocol versions; the client answers with its own list and the server
//! selects the highest mutual one (Appendix B). After that the socket carries
//! request/response frames correlated by a client-chosen `id`, plus
//! server-pushed `event` frames — the persistent real-time channel §8.3 calls
//! for, rather than polling.
//!
//! Everything here is a shell over [`Hhs`]: the transport parses frames,
//! delegates, and serializes the answer. Protocol rules live in the engine.
//!
//! # Authentication is not implemented
//!
//! §8.1 specifies OIDC/OAuth 2.0 with DPoP-bound device keys, which this phase
//! does not provide. The `select_version` frame simply asserts an identity, so
//! a connection can read any account's sync. Events remain signature-verified,
//! so nothing can be *forged* — but reads are unprotected. The server therefore
//! refuses to start unless `--insecure-dev-auth` is passed explicitly.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use herald_core::event::Event;
use herald_core::id::Gid;
use herald_core::identity::IdentityBundle;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::engine::{Hhs, ServerError, SyncRequest, SyncResponse};
use crate::store::Store;

/// Protocol versions this build speaks, newest last.
pub const SUPPORTED_VERSIONS: &[&str] = &["1.1"];

/// How many pushed events may queue for a slow connection before it is dropped.
const PUSH_BUFFER: usize = 256;

/// A frame sent by a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    /// Answer to `hello`: the client's versions and the identity it acts as.
    SelectVersion {
        /// Versions the client speaks.
        versions: Vec<String>,
        /// The identity to act as. See the module note on authentication.
        #[serde(rename = "as")]
        identity: String,
    },
    /// Publish an identity bundle (§3.5).
    Register {
        /// Correlation id.
        id: u64,
        /// The bundle to publish.
        bundle: Box<IdentityBundle>,
    },
    /// Add a contact, forming Tier 1 trust (§6.1).
    AddContact {
        /// Correlation id.
        id: u64,
        /// The identity to trust.
        contact: String,
    },
    /// Open a thread, trust-checked against every invitee (§6.3).
    CreateThread {
        /// Correlation id.
        id: u64,
        /// Identities to invite.
        invitees: Vec<String>,
    },
    /// Read the position a new event must claim.
    Head {
        /// Correlation id.
        id: u64,
        /// The thread to extend.
        thread_id: String,
    },
    /// Submit a signed event.
    Submit {
        /// Correlation id.
        id: u64,
        /// The event.
        event: Box<Event>,
    },
    /// Request a sliding-sync window (§8.4).
    Sync {
        /// Correlation id.
        id: u64,
        /// The window specification.
        request: Box<SyncRequest>,
    },
}

/// A frame sent by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    /// Sent immediately on connect (§8.2).
    Hello {
        /// The server's federation name.
        server_name: String,
        /// Versions the server speaks.
        supported_versions: Vec<String>,
    },
    /// Version negotiation succeeded.
    Ready {
        /// The selected version.
        version: String,
        /// The identity this connection acts as.
        identity: String,
    },
    /// A request succeeded with no payload.
    Ack {
        /// Correlation id of the request.
        id: u64,
    },
    /// A thread was created.
    Thread {
        /// Correlation id of the request.
        id: u64,
        /// The new thread.
        thread_id: String,
    },
    /// The current head of a thread.
    Head {
        /// Correlation id of the request.
        id: u64,
        /// The `seq` a new event must carry.
        seq: u64,
        /// The `prev_event` a new event must link to.
        prev_event: Option<String>,
    },
    /// A sliding-sync response.
    Sync {
        /// Correlation id of the request.
        id: u64,
        /// The window.
        response: Box<SyncResponse>,
    },
    /// An event delivered in real time (§8.3).
    Event {
        /// The event.
        event: Box<Event>,
    },
    /// A request failed.
    Error {
        /// Correlation id, absent for connection-level failures.
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<u64>,
        /// Appendix A error code, or a transport-level code.
        code: String,
        /// Human-readable detail.
        message: String,
    },
}

/// An event fanned out to connections, tagged with the connection that
/// submitted it.
///
/// The submitter is not pushed its own event — it already holds the event and
/// received an `ack`. Every *other* connection is, including other connections
/// of the same identity, which is what keeps a user's second device current
/// (§4.3, multi-device consistency).
#[derive(Debug, Clone)]
struct Push {
    origin: u64,
    event: Event,
}

/// Shared server state, generic over the storage backend so a deployment can
/// pick one at runtime.
pub struct AppState<S: Store> {
    hhs: Arc<Mutex<Hhs<S>>>,
    events: broadcast::Sender<Push>,
    dev_auth: bool,
    next_connection: Arc<AtomicU64>,
}

// Derived Clone would demand `S: Clone`, which the store is not and need not
// be: every field is shared, so cloning is a handful of refcount bumps.
impl<S: Store> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            hhs: Arc::clone(&self.hhs),
            events: self.events.clone(),
            dev_auth: self.dev_auth,
            next_connection: Arc::clone(&self.next_connection),
        }
    }
}

impl<S: Store> AppState<S> {
    /// Wraps an engine for serving.
    ///
    /// `dev_auth` enables the unauthenticated identity assertion described in
    /// the module note; it must never be set in a real deployment.
    #[must_use]
    pub fn new(hhs: Hhs<S>, dev_auth: bool) -> Self {
        let (events, _) = broadcast::channel(PUSH_BUFFER);
        Self {
            hhs: Arc::new(Mutex::new(hhs)),
            events,
            dev_auth,
            next_connection: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Locks the engine, recovering from a poisoned mutex: a panic in one
    /// connection must not take the whole server down with it.
    fn engine(&self) -> MutexGuard<'_, Hhs<S>> {
        self.hhs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn next_connection_id(&self) -> u64 {
        self.next_connection.fetch_add(1, Ordering::Relaxed)
    }
}

/// Builds the HCS router.
pub fn router<S: Store + Send + 'static>(state: AppState<S>) -> Router {
    Router::new()
        .route("/hcs/v1/version", get(version))
        .route("/hcs/v1/ws", get(upgrade))
        .with_state(state)
}

async fn version<S: Store + Send + 'static>(State(state): State<AppState<S>>) -> impl IntoResponse {
    Json(ServerFrame::Hello {
        server_name: state.engine().server_name().to_owned(),
        supported_versions: SUPPORTED_VERSIONS.iter().map(|&v| v.to_owned()).collect(),
    })
}

async fn upgrade<S: Store + Send + 'static>(
    ws: WebSocketUpgrade,
    State(state): State<AppState<S>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| connection(socket, state))
}

/// Selects the highest version both sides speak (Appendix B).
fn negotiate(client_versions: &[String]) -> Option<String> {
    SUPPORTED_VERSIONS
        .iter()
        .rev()
        .find(|supported| client_versions.iter().any(|v| v == *supported))
        .map(|selected| (*selected).to_owned())
}

fn now_secs() -> i64 {
    // The server supplies its own clock for trust evaluation: grant validity
    // must not be decided by a timestamp the caller chose.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

fn error(id: Option<u64>, code: &str, message: impl Into<String>) -> ServerFrame {
    ServerFrame::Error {
        id,
        code: code.to_owned(),
        message: message.into(),
    }
}

fn from_server_error(id: u64, error: &ServerError) -> ServerFrame {
    ServerFrame::Error {
        id: Some(id),
        code: error.error_code().as_str().to_owned(),
        message: error.to_string(),
    }
}

fn encode(frame: &ServerFrame) -> Message {
    // Serializing our own frames cannot fail; a serializer error would be a bug
    // rather than a runtime condition, so fall back to a transport error frame.
    Message::Text(
        serde_json::to_string(frame)
            .unwrap_or_else(|_| {
                r#"{"type":"error","code":"SERVER_ERROR","message":"frame encoding failed"}"#
                    .to_owned()
            })
            .into(),
    )
}

async fn connection<S: Store + Send>(socket: WebSocket, state: AppState<S>) {
    let connection_id = state.next_connection_id();
    let (mut sink, mut stream) = socket.split();

    let hello = ServerFrame::Hello {
        server_name: state.engine().server_name().to_owned(),
        supported_versions: SUPPORTED_VERSIONS.iter().map(|&v| v.to_owned()).collect(),
    };
    if sink.send(encode(&hello)).await.is_err() {
        return;
    }

    // Version negotiation must complete before anything else is accepted.
    let Some(identity) = handshake(&mut sink, &mut stream, &state).await else {
        return;
    };

    let mut fanout = state.events.subscribe();
    loop {
        tokio::select! {
            incoming = stream.next() => {
                let Some(Ok(message)) = incoming else { break };
                let Message::Text(text) = message else {
                    // Ping/pong/binary need no application handling.
                    continue;
                };
                let reply = match serde_json::from_str::<ClientFrame>(text.as_str()) {
                    Ok(frame) => handle(frame, &identity, connection_id, &state),
                    Err(e) => error(None, "BAD_FRAME", e.to_string()),
                };
                if sink.send(encode(&reply)).await.is_err() {
                    break;
                }
            }
            delivery = fanout.recv() => {
                match delivery {
                    Ok(Push { origin, event }) => {
                        if origin == connection_id || !visible_to(&state, &identity, &event) {
                            continue;
                        }
                        let frame = ServerFrame::Event { event: Box::new(event) };
                        if sink.send(encode(&frame)).await.is_err() {
                            break;
                        }
                    }
                    // Lagged: the client fell behind the push buffer and must
                    // resynchronise; sync is authoritative, so this is safe.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn handshake<S: Store + Send>(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    state: &AppState<S>,
) -> Option<Gid> {
    while let Some(Ok(message)) = stream.next().await {
        let Message::Text(text) = message else {
            continue;
        };

        let frame = match serde_json::from_str::<ClientFrame>(text.as_str()) {
            Ok(frame) => frame,
            Err(e) => {
                let _ = sink
                    .send(encode(&error(None, "BAD_FRAME", e.to_string())))
                    .await;
                continue;
            }
        };

        let ClientFrame::SelectVersion { versions, identity } = frame else {
            let _ = sink
                .send(encode(&error(
                    None,
                    "NOT_READY",
                    "select_version must be the first frame",
                )))
                .await;
            continue;
        };

        if !state.dev_auth {
            let _ = sink
                .send(encode(&error(
                    None,
                    "UNAUTHORIZED",
                    "this server has no authentication configured (spec 8.1)",
                )))
                .await;
            return None;
        }

        let Some(version) = negotiate(&versions) else {
            let _ = sink
                .send(encode(&error(
                    None,
                    "VERSION_UNSUPPORTED",
                    format!("no mutual version; server speaks {SUPPORTED_VERSIONS:?}"),
                )))
                .await;
            return None;
        };

        let Ok(gid) = Gid::parse(&identity) else {
            let _ = sink
                .send(encode(&error(None, "BAD_FRAME", "malformed identity")))
                .await;
            return None;
        };

        let ready = ServerFrame::Ready {
            version,
            identity: gid.to_string(),
        };
        return sink.send(encode(&ready)).await.ok().map(|()| gid);
    }
    None
}

fn visible_to<S: Store + Send>(state: &AppState<S>, identity: &Gid, event: &Event) -> bool {
    state
        .engine()
        .store()
        .thread(&event.draft.thread_id)
        .ok()
        .flatten()
        .is_some_and(|thread| thread.has_member(identity))
}

fn handle<S: Store + Send>(
    frame: ClientFrame,
    identity: &Gid,
    connection_id: u64,
    state: &AppState<S>,
) -> ServerFrame {
    match frame {
        // A second negotiation on an established connection is a client bug.
        ClientFrame::SelectVersion { .. } => error(
            None,
            "ALREADY_READY",
            "version already negotiated for this connection",
        ),

        ClientFrame::Register { id, bundle } => match state.engine().register(*bundle) {
            Ok(()) => ServerFrame::Ack { id },
            Err(e) => from_server_error(id, &e),
        },

        ClientFrame::AddContact { id, contact } => {
            let Ok(contact) = Gid::parse(&contact) else {
                return error(Some(id), "BAD_FRAME", "malformed contact");
            };
            match state.engine().add_contact(identity, &contact) {
                Ok(()) => ServerFrame::Ack { id },
                Err(e) => from_server_error(id, &e),
            }
        }

        ClientFrame::CreateThread { id, invitees } => {
            let mut parsed = Vec::with_capacity(invitees.len());
            for invitee in &invitees {
                let Ok(gid) = Gid::parse(invitee) else {
                    return error(Some(id), "BAD_FRAME", "malformed invitee");
                };
                parsed.push(gid);
            }
            let creator = herald_core::id::ContextAddress::new(identity.clone(), None);
            match state.engine().create_thread(&creator, &parsed, now_secs()) {
                Ok(thread_id) => ServerFrame::Thread { id, thread_id },
                Err(e) => from_server_error(id, &e),
            }
        }

        ClientFrame::Head { id, thread_id } => match state.engine().head(&thread_id) {
            Ok(head) => ServerFrame::Head {
                id,
                seq: head.seq,
                prev_event: head.prev_event,
            },
            Err(e) => from_server_error(id, &e),
        },

        ClientFrame::Submit { id, event } => {
            let event = *event;
            let accepted = state.engine().submit(event.clone());
            match accepted {
                Ok(()) => {
                    // Fan out to connected members. An error here means nobody
                    // is listening, which is not a submission failure.
                    let _ = state.events.send(Push {
                        origin: connection_id,
                        event,
                    });
                    ServerFrame::Ack { id }
                }
                Err(e) => from_server_error(id, &e),
            }
        }

        ClientFrame::Sync { id, request } => match state.engine().sync(identity, &request) {
            Ok(response) => ServerFrame::Sync {
                id,
                response: Box::new(response),
            },
            Err(e) => from_server_error(id, &e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_picks_the_highest_mutual_version() {
        assert_eq!(negotiate(&["1.1".into()]), Some("1.1".into()));
        assert_eq!(
            negotiate(&["1.0".into(), "1.1".into(), "9.9".into()]),
            Some("1.1".into())
        );
        assert_eq!(negotiate(&["1.0".into()]), None);
        assert_eq!(negotiate(&[]), None);
    }
}
