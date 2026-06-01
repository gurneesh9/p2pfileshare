use rusqlite::{params, Connection};
use std::path::PathBuf;
use uuid::Uuid;

use crate::identity::storage::config_dir;
use crate::{Error, Result};

use super::model::Contact;

fn db_path() -> PathBuf {
    config_dir().join("contacts.db")
}

pub struct ContactStore {
    conn: Connection,
}

impl ContactStore {
    pub fn open() -> Result<Self> {
        let dir = config_dir();
        std::fs::create_dir_all(&dir)?;
        let conn = Connection::open(db_path())?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contacts (
                id              TEXT PRIMARY KEY,
                display_name    TEXT NOT NULL,
                public_key      TEXT NOT NULL,
                fingerprint     TEXT NOT NULL,
                last_known_addr TEXT,
                added_at        INTEGER NOT NULL,
                last_seen       INTEGER
            );",
        )?;
        Ok(())
    }

    pub fn add(&self, contact: &Contact) -> Result<()> {
        self.conn.execute(
            "INSERT INTO contacts
             (id, display_name, public_key, fingerprint, last_known_addr, added_at, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                contact.id.to_string(),
                contact.display_name,
                contact.public_key,
                contact.fingerprint,
                contact.last_known_addr,
                contact.added_at as i64,
                contact.last_seen.map(|t| t as i64),
            ],
        )?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, display_name, public_key, fingerprint, last_known_addr, added_at, last_seen
             FROM contacts ORDER BY display_name",
        )?;
        let contacts = stmt
            .query_map([], |row| {
                let id_str: String = row.get(0)?;
                let added_at: i64 = row.get(5)?;
                let last_seen: Option<i64> = row.get(6)?;
                Ok(Contact {
                    id: Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4()),
                    display_name: row.get(1)?,
                    public_key: row.get(2)?,
                    fingerprint: row.get(3)?,
                    last_known_addr: row.get(4)?,
                    added_at: added_at as u64,
                    last_seen: last_seen.map(|t| t as u64),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(contacts)
    }

    pub fn find_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, display_name, public_key, fingerprint, last_known_addr, added_at, last_seen
             FROM contacts WHERE fingerprint = ?1",
        )?;
        let mut rows = stmt.query(params![fingerprint])?;
        if let Some(row) = rows.next()? {
            let id_str: String = row.get(0)?;
            let added_at: i64 = row.get(5)?;
            let last_seen: Option<i64> = row.get(6)?;
            Ok(Some(Contact {
                id: Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4()),
                display_name: row.get(1)?,
                public_key: row.get(2)?,
                fingerprint: row.get(3)?,
                last_known_addr: row.get(4)?,
                added_at: added_at as u64,
                last_seen: last_seen.map(|t| t as u64),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn update_last_seen(&self, id: Uuid, addr: Option<&str>) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.conn.execute(
            "UPDATE contacts SET last_seen = ?1, last_known_addr = ?2 WHERE id = ?3",
            params![now, addr, id.to_string()],
        )?;
        Ok(())
    }

    pub fn remove(&self, id: Uuid) -> Result<()> {
        let changed = self.conn.execute(
            "DELETE FROM contacts WHERE id = ?1",
            params![id.to_string()],
        )?;
        if changed == 0 {
            return Err(Error::ContactNotFound(id.to_string()));
        }
        Ok(())
    }
}
