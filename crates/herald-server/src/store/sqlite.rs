//! A durable [`Store`](super::Store) backed by `SQLite`.
//!
//! This is the backend that makes §11.3 self-hosting real: a single file, no
//! service to operate, and the same behaviour as [`MemoryStore`](super::MemoryStore)
//! — both are held to `tests/store_conformance.rs`.
//!
//! Records that the protocol already defines as signed, canonical structures
//! (identity bundles, accounts, events) are stored as their JSON form rather
//! than shredded into columns: re-encoding a signed event through a column
//! mapping is a chance to change bytes that a signature depends on. The columns
//! that do exist alongside the JSON — `seq`, `event_id`, `created_at`,
//! membership — are the ones the engine queries and orders by.
//!
//! `SQLite` is compiled in (`bundled`), so a deployment needs no system library.

use std::path::Path;

use herald_core::event::Event;
use herald_core::id::Gid;
use herald_core::identity::IdentityBundle;
use rusqlite::{params, Connection, OptionalExtension};

use super::{Account, Store, StoreError, Thread, ThreadHead, ThreadSummary};

/// Schema applied on open. Idempotent, so opening an existing database is safe.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS identities (
    gid    TEXT PRIMARY KEY,
    bundle TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    gid     TEXT PRIMARY KEY,
    account TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threads (
    thread_id         TEXT PRIMARY KEY,
    creator           TEXT NOT NULL,
    sequencing_server TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS thread_members (
    thread_id TEXT    NOT NULL,
    gid       TEXT    NOT NULL,
    position  INTEGER NOT NULL,
    PRIMARY KEY (thread_id, gid)
);
CREATE TABLE IF NOT EXISTS events (
    thread_id  TEXT    NOT NULL,
    seq        INTEGER NOT NULL,
    event_id   TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    event      TEXT    NOT NULL,
    PRIMARY KEY (thread_id, seq)
);
CREATE INDEX IF NOT EXISTS events_by_thread ON events (thread_id, seq);
CREATE INDEX IF NOT EXISTS members_by_gid ON thread_members (gid);
CREATE TABLE IF NOT EXISTS counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
";

/// The counter that hands out thread numbers.
const THREAD_COUNTER: &str = "thread";

fn backend(error: &impl std::fmt::Display) -> StoreError {
    StoreError::Backend(error.to_string())
}

fn encode<T: serde::Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|e| backend(&e))
}

fn decode<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, StoreError> {
    serde_json::from_str(raw).map_err(|e| backend(&e))
}

/// A SQLite-backed store.
#[derive(Debug)]
pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    /// Opens (or creates) a database at `path`.
    ///
    /// # Errors
    /// Returns [`StoreError::Backend`] if the file cannot be opened or the
    /// schema cannot be applied.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path).map_err(|e| backend(&e))?;
        Self::prepare(connection)
    }

    /// Opens a private in-memory database. Useful for tests that want the
    /// `SQLite` code path without a file.
    ///
    /// # Errors
    /// Returns [`StoreError::Backend`] if the schema cannot be applied.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory().map_err(|e| backend(&e))?;
        Self::prepare(connection)
    }

    fn prepare(connection: Connection) -> Result<Self, StoreError> {
        // WAL keeps readers from blocking the writer; FULL synchronous is the
        // right default for correspondence nobody wants to lose to a power cut.
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| backend(&e))?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|e| backend(&e))?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| backend(&e))?;
        connection.execute_batch(SCHEMA).map_err(|e| backend(&e))?;
        Ok(Self { connection })
    }
}

impl Store for SqliteStore {
    fn put_identity(&mut self, bundle: IdentityBundle) -> Result<(), StoreError> {
        self.connection
            .execute(
                "INSERT INTO identities (gid, bundle) VALUES (?1, ?2)
                 ON CONFLICT (gid) DO UPDATE SET bundle = excluded.bundle",
                params![bundle.gid.as_str(), encode(&bundle)?],
            )
            .map_err(|e| backend(&e))?;
        Ok(())
    }

    fn identity(&self, gid: &Gid) -> Result<Option<IdentityBundle>, StoreError> {
        let raw: Option<String> = self
            .connection
            .query_row(
                "SELECT bundle FROM identities WHERE gid = ?1",
                params![gid.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| backend(&e))?;
        raw.as_deref().map(decode).transpose()
    }

    fn put_account(&mut self, gid: &Gid, account: Account) -> Result<(), StoreError> {
        self.connection
            .execute(
                "INSERT INTO accounts (gid, account) VALUES (?1, ?2)
                 ON CONFLICT (gid) DO UPDATE SET account = excluded.account",
                params![gid.as_str(), encode(&account)?],
            )
            .map_err(|e| backend(&e))?;
        Ok(())
    }

    fn account(&self, gid: &Gid) -> Result<Account, StoreError> {
        let raw: Option<String> = self
            .connection
            .query_row(
                "SELECT account FROM accounts WHERE gid = ?1",
                params![gid.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| backend(&e))?;
        match raw {
            None => Ok(Account::default()),
            Some(raw) => decode(&raw),
        }
    }

    fn allocate_thread_number(&mut self) -> Result<u64, StoreError> {
        // RETURNING makes the read-modify-write a single atomic statement, so
        // two concurrent callers cannot be handed the same number.
        let next: i64 = self
            .connection
            .query_row(
                "INSERT INTO counters (name, value) VALUES (?1, 1)
                 ON CONFLICT (name) DO UPDATE SET value = value + 1
                 RETURNING value",
                params![THREAD_COUNTER],
                |row| row.get(0),
            )
            .map_err(|e| backend(&e))?;
        u64::try_from(next).map_err(|e| backend(&e))
    }

    fn put_thread(&mut self, thread: Thread) -> Result<(), StoreError> {
        let transaction = self.connection.transaction().map_err(|e| backend(&e))?;
        transaction
            .execute(
                "INSERT INTO threads (thread_id, creator, sequencing_server) VALUES (?1, ?2, ?3)
                 ON CONFLICT (thread_id) DO UPDATE SET
                     creator = excluded.creator,
                     sequencing_server = excluded.sequencing_server",
                params![
                    thread.thread_id,
                    thread.creator.to_string(),
                    thread.sequencing_server
                ],
            )
            .map_err(|e| backend(&e))?;
        transaction
            .execute(
                "DELETE FROM thread_members WHERE thread_id = ?1",
                params![thread.thread_id],
            )
            .map_err(|e| backend(&e))?;
        for (position, member) in thread.members.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO thread_members (thread_id, gid, position) VALUES (?1, ?2, ?3)",
                    params![
                        thread.thread_id,
                        member.as_str(),
                        i64::try_from(position).map_err(|e| backend(&e))?
                    ],
                )
                .map_err(|e| backend(&e))?;
        }
        transaction.commit().map_err(|e| backend(&e))?;
        Ok(())
    }

    fn thread(&self, thread_id: &str) -> Result<Option<Thread>, StoreError> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT creator, sequencing_server FROM threads WHERE thread_id = ?1",
                params![thread_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| backend(&e))?;

        let Some((creator, sequencing_server)) = row else {
            return Ok(None);
        };

        let mut statement = self
            .connection
            .prepare("SELECT gid FROM thread_members WHERE thread_id = ?1 ORDER BY position")
            .map_err(|e| backend(&e))?;
        let members = statement
            .query_map(params![thread_id], |row| row.get::<_, String>(0))
            .map_err(|e| backend(&e))?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| backend(&e))?
            .into_iter()
            .map(|gid| Gid::parse(&gid).map_err(|e| backend(&e)))
            .collect::<Result<Vec<Gid>, StoreError>>()?;

        Ok(Some(Thread {
            thread_id: thread_id.to_owned(),
            creator: herald_core::id::ContextAddress::parse(&creator).map_err(|e| backend(&e))?,
            members,
            sequencing_server,
        }))
    }

    fn append_event(&mut self, event: Event) -> Result<(), StoreError> {
        self.connection
            .execute(
                "INSERT INTO events (thread_id, seq, event_id, created_at, event)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    event.draft.thread_id,
                    i64::try_from(event.draft.seq).map_err(|e| backend(&e))?,
                    event.event_id,
                    event.draft.created_at,
                    encode(&event)?
                ],
            )
            .map_err(|e| backend(&e))?;
        Ok(())
    }

    fn events(
        &self,
        thread_id: &str,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<Event>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT event FROM events
                 WHERE thread_id = ?1 AND seq >= ?2
                 ORDER BY seq LIMIT ?3",
            )
            .map_err(|e| backend(&e))?;
        let rows = statement
            .query_map(
                params![
                    thread_id,
                    i64::try_from(from_seq).map_err(|e| backend(&e))?,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(|e| backend(&e))?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| backend(&e))?;

        rows.iter().map(|raw| decode(raw)).collect()
    }

    fn head(&self, thread_id: &str) -> Result<ThreadHead, StoreError> {
        let row: Option<(i64, String)> = self
            .connection
            .query_row(
                "SELECT seq, event_id FROM events WHERE thread_id = ?1 ORDER BY seq DESC LIMIT 1",
                params![thread_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| backend(&e))?;

        Ok(match row {
            None => ThreadHead {
                seq: herald_core::log::FIRST_SEQ,
                prev_event: None,
            },
            Some((seq, event_id)) => ThreadHead {
                seq: u64::try_from(seq).map_err(|e| backend(&e))? + 1,
                prev_event: Some(event_id),
            },
        })
    }

    fn threads_for(&self, gid: &Gid) -> Result<Vec<ThreadSummary>, StoreError> {
        // Threads with no events yet are omitted, matching the in-memory store:
        // a thread only appears in a sync list once it has activity to show.
        let mut statement = self
            .connection
            .prepare(
                "SELECT e.thread_id, e.seq, e.created_at
                 FROM events e
                 JOIN thread_members m ON m.thread_id = e.thread_id
                 WHERE m.gid = ?1
                   AND e.seq = (SELECT MAX(seq) FROM events WHERE thread_id = e.thread_id)
                 ORDER BY e.created_at DESC, e.thread_id ASC",
            )
            .map_err(|e| backend(&e))?;

        let summaries = statement
            .query_map(params![gid.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| backend(&e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| backend(&e))?;

        summaries
            .into_iter()
            .map(|(thread_id, last_seq, last_activity)| {
                Ok(ThreadSummary {
                    thread_id,
                    last_seq: u64::try_from(last_seq).map_err(|e| backend(&e))?,
                    last_activity,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use herald_core::crypto::PrivateKey;
    use herald_core::event::{EventDraft, EventType};
    use herald_core::id::ContextAddress;

    use super::*;

    fn sample_event(seq: u64) -> Event {
        EventDraft {
            thread_id: "!thread:herald.test".into(),
            seq,
            prev_event: None,
            event_type: EventType::Message,
            sender: ContextAddress::parse("diprish").unwrap(),
            origin_server: "herald.test".into(),
            created_at: "2026-08-09T10:00:00.000Z".into(),
            content: serde_json::json!({ "text": "hello" }),
            device_key_id: "DEVKEY:0001".into(),
        }
        .sign(&PrivateKey::from_seed(&[7; 32]))
        .unwrap()
    }

    #[test]
    fn thread_numbers_are_unique_and_survive_reopen() {
        let file = tempfile::NamedTempFile::new().unwrap();

        let mut store = SqliteStore::open(file.path()).unwrap();
        assert_eq!(store.allocate_thread_number().unwrap(), 1);
        assert_eq!(store.allocate_thread_number().unwrap(), 2);
        drop(store);

        // Reopening must not hand out a number that was already used, or a
        // restarted server would mint thread ids that already exist.
        let mut reopened = SqliteStore::open(file.path()).unwrap();
        assert_eq!(reopened.allocate_thread_number().unwrap(), 3);
    }

    #[test]
    fn opening_an_existing_database_is_idempotent() {
        let file = tempfile::NamedTempFile::new().unwrap();
        drop(SqliteStore::open(file.path()).unwrap());
        assert!(SqliteStore::open(file.path()).is_ok());
    }

    #[test]
    fn a_duplicate_sequence_number_is_refused_by_the_schema() {
        // The engine checks the head before appending, but the primary key is
        // the backstop: a thread must never hold two events at one position.
        let mut store = SqliteStore::open_in_memory().unwrap();
        let event = sample_event(1);
        store.append_event(event.clone()).unwrap();
        assert!(store.append_event(event).is_err());
    }
}
