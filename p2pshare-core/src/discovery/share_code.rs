use bip39::Language;
use rand::Rng;
use sha1::{Digest, Sha1};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ShareCode {
    pub display: String,
}

pub fn generate_share_code() -> ShareCode {
    let mut rng = rand::thread_rng();
    let words = Language::English.word_list();
    let word = words[rng.gen::<usize>() % 2048].to_uppercase();
    let num = rng.gen::<u16>() % 10000;
    ShareCode {
        display: format!("{word}-{num:04}"),
    }
}

fn current_hour() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 3600
}

pub fn to_infohash(code: &str) -> [u8; 20] {
    let input = format!("{}:{}", code, current_hour());
    Sha1::digest(input.as_bytes()).into()
}

pub fn to_recv_infohash(code: &str) -> [u8; 20] {
    let input = format!("{}:recv:{}", code, current_hour());
    Sha1::digest(input.as_bytes()).into()
}

/// Seconds until the current share code window expires.
pub fn secs_until_expiry() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let next_hour = (current_hour() + 1) * 3600;
    next_hour.saturating_sub(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infohash_is_deterministic_within_hour() {
        let h1 = to_infohash("MANGO-4471");
        let h2 = to_infohash("MANGO-4471");
        assert_eq!(h1, h2);
    }

    #[test]
    fn send_recv_infohashes_differ() {
        let code = "MANGO-4471";
        assert_ne!(to_infohash(code), to_recv_infohash(code));
    }
}
