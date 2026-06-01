use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Contact {
    pub id: Uuid,
    pub display_name: String,
    pub public_key: String,   // hex-encoded [u8; 32]
    pub fingerprint: String,
    pub last_known_addr: Option<String>, // "ip:port" string
    pub added_at: u64,
    pub last_seen: Option<u64>,
}

impl Contact {
    pub fn new(display_name: String, public_key: String, fingerprint: String) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            id: Uuid::new_v4(),
            display_name,
            public_key,
            fingerprint,
            last_known_addr: None,
            added_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_seen: None,
        }
    }
}
