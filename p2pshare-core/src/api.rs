/// Phase 6 — Flutter FFI surface via flutter_rust_bridge v2.
///
/// All public types and functions in this module are exposed to Dart.
/// Rules:
/// - No lifetimes, no Arc/Mutex in return types.
/// - Sessions are stored in a global registry keyed by a u64 handle.
/// - Long-running operations stream events via StreamSink<ApiEvent>.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use flutter_rust_bridge::frb;

use crate::{
    contacts::{model::Contact, store::ContactStore},
    discovery::{
        dht::DhtLayer,
        presence::{check_presence, PresenceStatus},
        share_code::generate_share_code,
    },
    identity::storage::{load, reset, save},
    session::{
        coordinator::{
            announce_and_connect, announce_and_connect_with_code, announce_mdns_only_with_code,
            announce_via_relay_only, announce_via_relay_only_with_code, connect_to_contact,
            connect_via_relay_only, lookup_and_connect, lookup_mdns_only,
        },
        Session,
    },
    transfer::{receiver::receive_file, sender::send_file},
};

// ── Global session registry ───────────────────────────────────────────────────

static SESSION_REGISTRY: OnceLock<Mutex<HashMap<u64, Session>>> = OnceLock::new();
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static DHT_LAYER: OnceLock<Mutex<Option<DhtLayer>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<u64, Session>> {
    SESSION_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn store_session(session: Session) -> u64 {
    let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    sessions().lock().unwrap().insert(id, session);
    id
}

fn take_session(id: u64) -> Option<Session> {
    sessions().lock().unwrap().remove(&id)
}

// ── API types ─────────────────────────────────────────────────────────────────

pub struct ApiIdentity {
    pub display_name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub created_at: u64,
}

pub struct ApiContact {
    pub id: String,
    pub display_name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub is_online: bool,
    pub last_known_addr: Option<String>,
    pub last_seen: Option<u64>,
}

pub struct ApiTransferResult {
    pub file_name: String,
    pub file_path: String,
    pub bytes_transferred: u64,
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

/// Set the directory where Xend stores identity.json and contacts.db.
/// Must be called once before any identity/contact/session API.
/// Flutter passes getApplicationSupportDirectory().path here.
#[frb(sync)]
pub fn api_set_data_dir(path: String) {
    crate::identity::storage::set_data_dir(std::path::PathBuf::from(path));
}

// ── Identity ──────────────────────────────────────────────────────────────────

/// Load the stored identity, or None if none exists yet.
#[frb(sync)]
pub fn api_get_identity() -> Option<ApiIdentity> {
    match load() {
        Ok(Some(id)) => Some(ApiIdentity {
            display_name: id.display_name,
            fingerprint: id.fingerprint,
            public_key: id.public_key,
            created_at: id.created_at,
        }),
        _ => None,
    }
}

/// Regenerate the keypair (destructive — old identity is lost).
#[frb(sync)]
pub fn api_reset_identity(display_name: String) -> Result<ApiIdentity, String> {
    let mut id = reset().map_err(|e| e.to_string())?;
    id.display_name = display_name.clone();
    save(&id).map_err(|e| e.to_string())?;
    Ok(ApiIdentity {
        display_name,
        fingerprint: id.fingerprint,
        public_key: id.public_key,
        created_at: id.created_at,
    })
}

/// Update the display name of the current identity.
#[frb(sync)]
pub fn api_set_display_name(name: String) -> Result<(), String> {
    match load().map_err(|e| e.to_string())? {
        Some(mut id) => {
            id.display_name = name;
            save(&id).map_err(|e| e.to_string())
        }
        None => Err("no identity found".into()),
    }
}

// ── Contacts ──────────────────────────────────────────────────────────────────

/// List all contacts sorted by name.
#[frb(sync)]
pub fn api_list_contacts() -> Vec<ApiContact> {
    ContactStore::open()
        .ok()
        .and_then(|s| s.list().ok())
        .unwrap_or_default()
        .into_iter()
        .map(contact_to_api)
        .collect()
}

/// Add a contact by fingerprint + display name.
/// Returns the newly created contact.
#[frb(sync)]
pub fn api_add_contact(fingerprint: String, display_name: String) -> Result<ApiContact, String> {
    let store = ContactStore::open().map_err(|e| e.to_string())?;

    if store
        .find_by_fingerprint(&fingerprint)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err(format!("contact {} already exists", fingerprint));
    }

    let contact = Contact::new(display_name, String::new(), fingerprint);
    store.add(&contact).map_err(|e| e.to_string())?;
    Ok(contact_to_api(contact))
}

/// Remove a contact by id (UUID string).
#[frb(sync)]
pub fn api_remove_contact(id: String) -> Result<(), String> {
    let uuid = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let store = ContactStore::open().map_err(|e| e.to_string())?;
    store.remove(uuid).map_err(|e| e.to_string())
}

/// Check online/offline status of all contacts via DHT.
/// Kicks off a tokio runtime for each call since this is async.
pub async fn api_check_presence() -> Vec<ApiContact> {
    let store = match ContactStore::open() {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let contacts = store.list().unwrap_or_default();
    if contacts.is_empty() {
        return vec![];
    }

    let dht = match DhtLayer::new() {
        Ok(d) => d,
        Err(_) => {
            return contacts.into_iter().map(contact_to_api).collect();
        }
    };

    let statuses = check_presence(&contacts, &dht).await;

    contacts
        .into_iter()
        .map(|c| {
            let is_online = matches!(statuses.get(&c.id), Some(PresenceStatus::Online { .. }));
            let last_addr = match statuses.get(&c.id) {
                Some(PresenceStatus::Online { addr }) => Some(addr.to_string()),
                _ => c.last_known_addr.clone(),
            };
            ApiContact {
                id: c.id.to_string(),
                display_name: c.display_name,
                fingerprint: c.fingerprint,
                public_key: c.public_key,
                is_online,
                last_known_addr: last_addr,
                last_seen: c.last_seen,
            }
        })
        .collect()
}

// ── Two-phase send flow ───────────────────────────────────────────────────────
// Phase 1: generate a code immediately so it can be displayed to the user.
// Phase 2: announce with that code, wait for peer, return handle.
// Phase 3: drive transfer with api_drive_send.

/// Generate a share code without starting any network activity.
/// Call this first so the code can be shown immediately.
#[frb(sync)]
pub fn api_generate_share_code() -> String {
    generate_share_code().display
}

/// Phase 2 of send — full flow (LAN mDNS + DHT + relay fallback).
/// Blocks until a receiver connects with the given code.
pub async fn api_begin_send(code: String) -> Result<u64, String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;
    let dht = DhtLayer::new().map_err(|e| e.to_string())?;
    let session = announce_and_connect_with_code(&identity, &dht, &code)
        .await
        .map_err(|e| e.to_string())?;
    Ok(store_session(session))
}

/// Phase 2 of send — LAN-only (mDNS, no DHT/relay).
/// Blocks until a receiver connects directly on the same network.
pub async fn api_begin_send_lan_only(code: String) -> Result<u64, String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;
    let session = announce_mdns_only_with_code(&identity, &code)
        .await
        .map_err(|e| e.to_string())?;
    Ok(store_session(session))
}

/// Receiver: connect via LAN-only (mDNS, no DHT/relay).
/// Returns session handle for use with api_drive_receive.
pub async fn api_connect_lan_only(code: String) -> Result<u64, String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;
    let session = lookup_mdns_only(&identity, &code)
        .await
        .map_err(|e| e.to_string())?;
    Ok(store_session(session))
}

/// Phase 2 of send — relay-only (no LAN/DHT).
/// Blocks until a receiver connects via relay with the given code.
pub async fn api_begin_send_relay_only(code: String) -> Result<u64, String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;
    let session = announce_via_relay_only_with_code(&identity, &code)
        .await
        .map_err(|e| e.to_string())?;
    Ok(store_session(session))
}

// ── Send flow ─────────────────────────────────────────────────────────────────

/// Sender using relay only.
pub async fn api_send_file_relay(file_path: String) -> Result<String, String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;

    // This is synchronous from the Dart perspective — blocks until complete.
    // For a real streaming approach see api_create_send_session.
    let (code, session) =
        announce_via_relay_only(&identity).await.map_err(|e| e.to_string())?;

    let path = PathBuf::from(&file_path);
    send_file(&session, &path).await.map_err(|e| e.to_string())?;
    Ok(code)
}

/// Receiver: connect via code, receive file.
pub async fn api_receive_file_relay(
    code: String,
    output_dir: String,
) -> Result<ApiTransferResult, String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;

    let session = connect_via_relay_only(&identity, &code)
        .await
        .map_err(|e| e.to_string())?;

    let out_path = PathBuf::from(&output_dir);
    let saved_to = receive_file(&session, &out_path)
        .await
        .map_err(|e| e.to_string())?;

    let file_name = saved_to
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    Ok(ApiTransferResult {
        file_name,
        file_path: saved_to.to_string_lossy().into_owned(),
        bytes_transferred: saved_to.metadata().map(|m| m.len()).unwrap_or(0),
    })
}

// ── Full send/receive (DHT + LAN + relay fallback) ────────────────────────────

/// Sender: full flow (LAN mDNS + DHT + relay fallback).
/// Returns (code, session_handle) immediately — transfer must be driven by
/// api_drive_send(session_handle, file_path).
pub async fn api_create_send_session() -> Result<(String, u64), String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;
    let dht = DhtLayer::new().map_err(|e| e.to_string())?;

    let (code, session) = announce_and_connect(&identity, &dht)
        .await
        .map_err(|e| e.to_string())?;

    let handle = store_session(session);
    Ok((code, handle))
}

/// Drive a previously established send session to send a file.
pub async fn api_drive_send(session_handle: u64, file_path: String) -> Result<(), String> {
    let session = take_session(session_handle).ok_or("session not found")?;
    let path = PathBuf::from(&file_path);
    send_file(&session, &path).await.map_err(|e| e.to_string())
}

/// Receiver: look up code via LAN/DHT and connect.
/// Returns session_handle for use with api_drive_receive.
pub async fn api_connect_to_code(code: String) -> Result<(u64, String), String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;
    let dht = DhtLayer::new().map_err(|e| e.to_string())?;

    let session = lookup_and_connect(&identity, &code, &dht)
        .await
        .map_err(|e| e.to_string())?;

    let fingerprint = session.remote_fingerprint().to_string();
    let handle = store_session(session);
    Ok((handle, fingerprint))
}

/// Drive a previously established receive session to receive a file.
pub async fn api_drive_receive(
    session_handle: u64,
    output_dir: String,
) -> Result<ApiTransferResult, String> {
    let session = take_session(session_handle).ok_or("session not found")?;
    let out_path = PathBuf::from(&output_dir);
    let saved_to = receive_file(&session, &out_path)
        .await
        .map_err(|e| e.to_string())?;

    let file_name = saved_to
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    Ok(ApiTransferResult {
        file_name,
        file_path: saved_to.to_string_lossy().into_owned(),
        bytes_transferred: saved_to.metadata().map(|m| m.len()).unwrap_or(0),
    })
}

/// Connect to a known contact and return (session_handle, remote_fingerprint).
pub async fn api_connect_to_contact(contact_id: String) -> Result<(u64, String), String> {
    let identity = load()
        .map_err(|e| e.to_string())?
        .ok_or("no identity")?;
    let store = ContactStore::open().map_err(|e| e.to_string())?;
    let uuid = uuid::Uuid::parse_str(&contact_id).map_err(|e| e.to_string())?;

    let contacts = store.list().map_err(|e| e.to_string())?;
    let contact = contacts
        .into_iter()
        .find(|c| c.id == uuid)
        .ok_or("contact not found")?;

    let dht = DhtLayer::new().map_err(|e| e.to_string())?;
    let session = connect_to_contact(&identity, &contact, &dht)
        .await
        .map_err(|e| e.to_string())?;

    let fingerprint = session.remote_fingerprint().to_string();
    let handle = store_session(session);
    Ok((handle, fingerprint))
}

/// Get connection type for a session ("direct" | "relay").
#[frb(sync)]
pub fn api_session_type(session_handle: u64) -> String {
    match sessions().lock().unwrap().get(&session_handle) {
        Some(Session::Direct(_)) => "direct".into(),
        Some(Session::Relay(_)) => "relay".into(),
        None => "unknown".into(),
    }
}

/// Release a session that is no longer needed.
#[frb(sync)]
pub fn api_close_session(session_handle: u64) {
    take_session(session_handle);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn contact_to_api(c: Contact) -> ApiContact {
    ApiContact {
        id: c.id.to_string(),
        display_name: c.display_name,
        fingerprint: c.fingerprint,
        public_key: c.public_key,
        is_online: false,
        last_known_addr: c.last_known_addr,
        last_seen: c.last_seen,
    }
}
