use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Keypair {
    pub public: [u8; 32],
    pub secret: [u8; 32],
}

impl Keypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            public: *public.as_bytes(),
            secret: secret.to_bytes(),
        }
    }
}
