use bip39::Language;

fn wordlist() -> &'static [&'static str; 2048] {
    Language::English.word_list()
}

pub fn to_fingerprint(pubkey: &[u8; 32]) -> String {
    let words = wordlist();
    let w1 = u16::from_be_bytes([pubkey[0], pubkey[1]]) as usize % 2048;
    let n1 = u16::from_be_bytes([pubkey[2], pubkey[3]]) % 10000;
    let w2 = u16::from_be_bytes([pubkey[4], pubkey[5]]) as usize % 2048;
    let n2 = u16::from_be_bytes([pubkey[6], pubkey[7]]) % 10000;

    format!(
        "{}-{:04}-{}-{:04}",
        words[w1].to_uppercase(),
        n1,
        words[w2].to_uppercase(),
        n2,
    )
}

/// Returns the canonical BIP-0039 English wordlist (2048 words).
pub fn bip39_wordlist() -> &'static [&'static str; 2048] {
    wordlist()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_2048_entries() {
        assert_eq!(wordlist().len(), 2048);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let key = [0u8; 32];
        assert_eq!(to_fingerprint(&key), to_fingerprint(&key));
    }

    #[test]
    fn different_keys_different_fingerprints() {
        let key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        key2[0] = 1;
        assert_ne!(to_fingerprint(&key1), to_fingerprint(&key2));
    }

    #[test]
    fn fingerprint_format_is_word_num_word_num() {
        let key = [42u8; 32];
        let fp = to_fingerprint(&key);
        let parts: Vec<&str> = fp.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts[1].len() == 4, "num1 should be zero-padded to 4 digits");
        assert!(parts[3].len() == 4, "num2 should be zero-padded to 4 digits");
        assert!(parts[1].chars().all(|c| c.is_ascii_digit()));
        assert!(parts[3].chars().all(|c| c.is_ascii_digit()));
    }
}
