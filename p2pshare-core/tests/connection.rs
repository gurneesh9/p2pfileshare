/// Integration tests for the connection coordinator.
///
/// Three tiers:
///   Tier 1 — loopback only, no internet required, always run
///   Tier 2 — requires internet (DHT/relay), #[ignore] by default
///
/// Run all including ignored:  cargo test -p xend-core -- --ignored
/// Run only relay tests:       cargo test -p xend-core relay -- --ignored

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use xend_core::{
    discovery::dht::DhtLayer,
    identity::{fingerprint::to_fingerprint, keypair::Keypair, storage::UserIdentity},
    session::{
        coordinator::{
            announce_and_connect_with_code, announce_via_relay_only_with_code,
            connect_via_relay_only, lookup_and_connect,
        },
        Session,
    },
    transfer::{receiver::receive_file, sender::send_file},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn test_identity(name: &str) -> UserIdentity {
    let kp = Keypair::generate();
    UserIdentity {
        public_key: hex::encode(kp.public),
        private_key: hex::encode(kp.secret),
        display_name: name.to_string(),
        fingerprint: to_fingerprint(&kp.public),
        created_at: 0,
    }
}

/// Unique short code per test run so parallel tests don't collide.
fn unique_code(prefix: &str) -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_millis();
    // Codes must be alphanumeric uppercase and short enough to be a valid infohash input.
    format!("{}{:03}", prefix, ms % 1000)
}

// ── Tier 1: loopback-only (no internet required) ──────────────────────────────

/// Regression test for the bug where a DHT miss in the receiver's internet arm
/// would propagate an error through `result?` in tokio::select!, killing the
/// whole call even though the LAN path (multicast) was still viable.
///
/// On the same machine, multicast has IP_MULTICAST_LOOP enabled, so sender and
/// receiver discover each other without any real network. DHT will return no peers
/// (no bootstrapped nodes reachable on loopback), so the internet arm gets
/// disabled — and with the fix, the LAN arm correctly wins and returns a Direct
/// session.
///
/// If this test regresses to relay, it means the internet arm error is killing
/// the select again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lan_path_wins_when_dht_empty() {
    let code = unique_code("LAN");

    let sender_id = test_identity("lan-sender");
    let receiver_id = test_identity("lan-receiver");

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("payload.bin");
    // 512 KB — small enough to finish quickly, large enough to exercise chunking.
    let content: Vec<u8> = (0u8..=255).cycle().take(512 * 1024).collect();
    tokio::fs::write(&src, &content).await.unwrap();
    let out_dir = tmp.path().join("recv");

    // Sender runs in a background task: advertise → accept connection → send file.
    let sender_dht = DhtLayer::new().unwrap();
    let code_s = code.clone();
    let src_s = src.clone();
    let sender_task = tokio::spawn(async move {
        let session = timeout(
            Duration::from_secs(20),
            announce_and_connect_with_code(&sender_id, &sender_dht, &code_s),
        )
        .await
        .expect("sender timed out waiting for peer")
        .expect("sender failed to connect");

        let was_direct = matches!(session, Session::Direct(_));
        send_file(&session, &src_s).await.expect("send_file failed");
        was_direct
    });

    // Brief pause so multicast advertisements are in-flight before receiver starts.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Receiver: LAN and internet paths race.  DHT will return empty (no loopback
    // DHT peers), but multicast should deliver sender's address in < 1 s.
    let receiver_dht = DhtLayer::new().unwrap();
    let recv_session = timeout(
        Duration::from_secs(15),
        lookup_and_connect(&receiver_id, &code, &receiver_dht),
    )
    .await
    .expect("receiver timed out waiting for sender")
    .expect("receiver failed to connect");

    // The critical assertion: LAN won → Direct session, not Relay.
    assert!(
        matches!(recv_session, Session::Direct(_)),
        "expected Session::Direct (LAN path) but got Session::Relay — \
         internet arm is likely still killing the select on DHT miss"
    );

    // Drive the transfer to completion and verify data integrity.
    let saved = receive_file(&recv_session, &out_dir)
        .await
        .expect("receive_file failed");
    let received = tokio::fs::read(&saved).await.unwrap();
    assert_eq!(received, content, "received file contents differ from sent");

    let sender_was_direct = sender_task.await.expect("sender task panicked");
    assert!(sender_was_direct, "sender also expected Direct session");
}

// ── Tier 2: internet required (run with -- --ignored) ─────────────────────────

/// Full relay round-trip: both peers connect via xend-relay.fly.dev, transfer a
/// file, and verify the received bytes match.
///
/// This exercises the relay path independently of LAN / DHT and validates the
/// relay server is healthy.  Marked ignored because it needs live internet.
///
/// Run: cargo test -p xend-core relay_roundtrip -- --ignored
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live relay at xend-relay.fly.dev"]
async fn relay_roundtrip_sends_file() {
    let code = unique_code("RLY");

    let sender_id = test_identity("relay-sender");
    let receiver_id = test_identity("relay-receiver");

    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("relay_payload.txt");
    let content = b"xend relay integration test payload";
    tokio::fs::write(&src, content).await.unwrap();
    let out_dir = tmp.path().join("recv");

    // Sender registers with relay first so receiver finds it immediately.
    let code_s = code.clone();
    let src_s = src.clone();
    let sender_task = tokio::spawn(async move {
        let session = timeout(
            Duration::from_secs(30),
            announce_via_relay_only_with_code(&sender_id, &code_s),
        )
        .await
        .expect("sender timed out")
        .expect("sender relay connect failed");

        assert!(
            matches!(session, Session::Relay(_)),
            "sender expected Relay session"
        );
        send_file(&session, &src_s).await.expect("send_file failed");
    });

    // Give sender time to register with relay before receiver connects.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let recv_session = timeout(
        Duration::from_secs(30),
        connect_via_relay_only(&receiver_id, &code),
    )
    .await
    .expect("receiver timed out")
    .expect("receiver relay connect failed");

    assert!(
        matches!(recv_session, Session::Relay(_)),
        "receiver expected Relay session"
    );

    let saved = receive_file(&recv_session, &out_dir)
        .await
        .expect("receive_file failed");
    let received = tokio::fs::read(&saved).await.unwrap();
    assert_eq!(received.as_slice(), content.as_slice());

    sender_task.await.expect("sender task panicked");
}

/// DHT lookup_with_retry returns an empty vec (not a panic) when the infohash
/// has no peers and honours the timeout duration.
///
/// This specifically validates that the retry loop terminates cleanly rather
/// than blocking forever, which was a risk with the `lookup_with_retry` change.
///
/// Slow (~8 s) and requires internet to bootstrap DHT nodes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires internet to bootstrap DHT; runs for ~8 s"]
async fn dht_lookup_retry_returns_empty_for_unknown_infohash() {
    let dht = DhtLayer::new().unwrap();

    // Random infohash — nothing will ever be announced here.
    let infohash = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];

    let start = std::time::Instant::now();
    let peers = dht
        .lookup_with_retry(infohash, Duration::from_secs(8), Duration::from_secs(2))
        .await;

    assert!(peers.is_empty(), "expected no peers for random infohash");
    // Should have waited close to the full 8 s timeout before giving up.
    assert!(
        start.elapsed() >= Duration::from_secs(7),
        "lookup_with_retry returned too early (elapsed: {:?})",
        start.elapsed()
    );
}
