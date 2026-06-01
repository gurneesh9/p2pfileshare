use sha1::{Digest, Sha1};
use std::net::SocketAddr;
use std::collections::HashMap;
use uuid::Uuid;

use super::dht::DhtLayer;
use crate::contacts::model::Contact;

#[derive(Debug, Clone)]
pub enum PresenceStatus {
    Online { addr: SocketAddr },
    Offline,
}

pub async fn check_presence(
    contacts: &[Contact],
    dht: &DhtLayer,
) -> HashMap<Uuid, PresenceStatus> {
    let mut statuses = HashMap::new();

    for contact in contacts {
        let pk_bytes = hex::decode(&contact.public_key).unwrap_or_default();
        let infohash: [u8; 20] = Sha1::digest(&pk_bytes).into();
        let peers = dht.lookup(infohash).await;

        let status = match peers.into_iter().next() {
            Some(addr) => PresenceStatus::Online { addr },
            None => PresenceStatus::Offline,
        };

        statuses.insert(contact.id, status);
    }

    statuses
}
