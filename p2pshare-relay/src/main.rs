use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex},
    time::{timeout, Duration},
};

const BIND_ADDR: &str = "0.0.0.0:443";
const PAIR_TIMEOUT_SECS: u64 = 60;

// Maps a 16-byte token to the oneshot sender that will receive the second peer's stream.
type WaitMap = Arc<Mutex<HashMap<[u8; 16], oneshot::Sender<TcpStream>>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let listener = TcpListener::bind(BIND_ADDR).await?;
    tracing::info!("p2pshare relay listening on {}", BIND_ADDR);

    let waiting: WaitMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (stream, addr) = listener.accept().await?;
        tracing::debug!("new connection from {}", addr);
        tokio::spawn(handle(stream, addr, waiting.clone()));
    }
}

async fn handle(mut stream: TcpStream, addr: SocketAddr, waiting: WaitMap) {
    // Read 16-byte pairing token from client.
    let mut token = [0u8; 16];
    if stream.read_exact(&mut token).await.is_err() {
        tracing::warn!("{}: failed to read token", addr);
        return;
    }

    // Check atomically: are we first or second peer for this token?
    let maybe_tx = waiting.lock().await.remove(&token);

    match maybe_tx {
        Some(tx) => {
            // Second peer — hand our stream to the waiting first peer's task.
            tracing::info!("{}: paired (token {})", addr, hex_token(&token));
            let _ = tx.send(stream);
        }

        None => {
            // First peer — register and wait for the second peer.
            let (tx, rx) = oneshot::channel::<TcpStream>();
            waiting.lock().await.insert(token, tx);
            tracing::info!("{}: waiting for peer (token {})", addr, hex_token(&token));

            match timeout(Duration::from_secs(PAIR_TIMEOUT_SECS), rx).await {
                Ok(Ok(mut peer_stream)) => {
                    tracing::info!("piping session (token {})", hex_token(&token));

                    // Signal both clients that they are paired.
                    if stream.write_all(&[0x01]).await.is_err()
                        || peer_stream.write_all(&[0x01]).await.is_err()
                    {
                        tracing::warn!("failed to signal pairing (token {})", hex_token(&token));
                        return;
                    }

                    // Bidirectional pipe — relay sees nothing beyond byte counts.
                    let (mut r_a, mut w_a) = stream.into_split();
                    let (mut r_b, mut w_b) = peer_stream.into_split();

                    let a_to_b = tokio::io::copy(&mut r_a, &mut w_b);
                    let b_to_a = tokio::io::copy(&mut r_b, &mut w_a);
                    let _ = tokio::join!(a_to_b, b_to_a);

                    tracing::info!("session closed (token {})", hex_token(&token));
                }
                _ => {
                    // Timeout or channel dropped (second peer never arrived).
                    tracing::info!("{}: peer never arrived — closing", addr);
                    waiting.lock().await.remove(&token);
                }
            }
        }
    }
}

fn hex_token(token: &[u8; 16]) -> String {
    token.iter().map(|b| format!("{b:02x}")).collect()
}
