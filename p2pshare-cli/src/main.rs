use std::path::PathBuf;

use clap::{Parser, Subcommand};
use p2pshare_core::{
    contacts::{model::Contact, store::ContactStore},
    discovery::dht::DhtLayer,
    identity::storage::{load, reset, save},
    session::coordinator::{
        announce_and_connect, announce_via_relay_only, connect_via_relay_only, lookup_and_connect,
    },
    transfer::{receiver::receive_file, sender::send_file},
};
// Session is used via the return types of announce_and_connect / lookup_and_connect

#[derive(Parser)]
#[command(name = "p2pshare", about = "Decentralized encrypted file transfer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show (or update) your identity
    Identity {
        #[arg(long)]
        name: Option<String>,
        /// Regenerate keypair — destroys old identity
        #[arg(long)]
        reset: bool,
    },

    /// Generate a share code, wait for a receiver, then send a file
    Send {
        /// File to send
        file: PathBuf,
        /// Skip LAN discovery and DHT — connect straight through the relay server
        #[arg(long)]
        relay: bool,
    },

    /// Look up a share code and receive the file from the sender
    Receive {
        /// Share code from the sender (e.g. MANGO-4471)
        code: String,
        /// Directory to save the received file (default: current directory)
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        /// Skip LAN discovery and DHT — connect straight through the relay server
        #[arg(long)]
        relay: bool,
    },

    /// Look up a share code on the DHT and print the resolved peer address (no connection)
    Lookup {
        /// Share code to look up (e.g. MANGO-4471)
        code: String,
    },

    /// Phase-2 test: announce a code, complete handshake, print remote fingerprint
    Announce,

    /// Phase-2 test: connect via a share code, print remote fingerprint
    Connect {
        code: String,
    },

    /// Manage contacts
    #[command(subcommand)]
    Contacts(ContactsCommand),
}

#[derive(Subcommand)]
enum ContactsCommand {
    /// List all contacts
    List,
    /// Add a contact by fingerprint
    Add {
        fingerprint: String,
        name: String,
    },
    /// Remove a contact by fingerprint
    Remove { fingerprint: String },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("p2pshare=info".parse().unwrap()),
        )
        .init();

    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn load_identity_or_exit() -> p2pshare_core::identity::storage::UserIdentity {
    match load() {
        Ok(Some(id)) => id,
        Ok(None) => {
            println!("key not found");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error loading identity: {e}");
            std::process::exit(1);
        }
    }
}

async fn run(cli: Cli) -> p2pshare_core::Result<()> {
    match cli.command {
        // ── Identity ──────────────────────────────────────────────────────────
        Command::Identity { name, reset: do_reset } => {
            let mut identity = if do_reset {
                eprintln!("Regenerating identity...");
                reset()?
            } else {
                load_identity_or_exit()
            };
            if let Some(n) = name {
                identity.display_name = n;
                save(&identity)?;
            }
            println!("Name:        {}", identity.display_name);
            println!("Fingerprint: {}", identity.fingerprint);
            println!("Public key:  {}", identity.public_key);
            println!("Created:     {}", fmt_age(identity.created_at));
        }

        // ── Lookup (DHT only, no connection) ─────────────────────────────────
        Command::Lookup { code } => {
            use p2pshare_core::discovery::share_code::to_infohash;
            use std::time::Duration;

            let code = code.to_uppercase();
            let infohash = to_infohash(&code);
            let dht = DhtLayer::new()?;

            println!("Looking up {} on DHT...", code);
            println!("Infohash: {}", hex::encode(infohash));
            println!("(retrying for up to 30s — DHT may need time to propagate)");

            let peers = dht
                .lookup_with_retry(infohash, Duration::from_secs(30), Duration::from_secs(3))
                .await;

            if peers.is_empty() {
                println!("No peers found after 30s.");
                println!("Check that the sender's `announce` is still running and that");
                println!("UDP traffic is not blocked by a firewall.");
            } else {
                println!("Found {} peer(s):", peers.len());
                for addr in &peers {
                    println!("  {addr}");
                }
            }
        }

        // ── Send ──────────────────────────────────────────────────────────────
        Command::Send { file, relay } => {
            if !file.exists() {
                eprintln!("error: file not found: {}", file.display());
                std::process::exit(1);
            }
            let identity = load_identity_or_exit();

            println!("Your fingerprint: {}", identity.fingerprint);

            let (_code, session) = if relay {
                announce_via_relay_only(&identity).await?
            } else {
                let dht = DhtLayer::new()?;
                announce_and_connect(&identity, &dht).await?
            };

            println!();
            println!("Connected to: {}", session.remote_fingerprint());
            println!("Sending {}...", file.display());

            send_file(&session, &file).await?;

            println!("Done.");
        }

        // ── Receive ───────────────────────────────────────────────────────────
        Command::Receive { code, output, relay } => {
            let identity = load_identity_or_exit();

            println!("Your fingerprint: {}", identity.fingerprint);
            println!("Connecting via code: {}", code.to_uppercase());

            let session = if relay {
                connect_via_relay_only(&identity, &code).await?
            } else {
                let dht = DhtLayer::new()?;
                lookup_and_connect(&identity, &code, &dht).await?
            };

            println!();
            println!("Connected to: {}", session.remote_fingerprint());
            println!("Receiving...");

            let saved_to = receive_file(&session, &output).await?;

            println!("Saved to: {}", saved_to.display());
        }

        // ── Announce (Phase 2 handshake test) ─────────────────────────────────
        Command::Announce => {
            let identity = load_identity_or_exit();
            let dht = DhtLayer::new()?;

            println!("Your fingerprint: {}", identity.fingerprint);

            let (code, session) = announce_and_connect(&identity, &dht).await?;

            println!();
            println!("Share code used : {}", code);
            println!("Remote peer     : {}", session.remote_fingerprint());
            println!("Remote pubkey   : {}", hex::encode(session.remote_pubkey()));
        }

        // ── Connect (Phase 2 handshake test) ──────────────────────────────────
        Command::Connect { code } => {
            let identity = load_identity_or_exit();
            let dht = DhtLayer::new()?;

            println!("Your fingerprint: {}", identity.fingerprint);
            println!("Connecting via: {}", code.to_uppercase());

            let session = lookup_and_connect(&identity, &code, &dht).await?;

            println!();
            println!("Remote peer   : {}", session.remote_fingerprint());
            println!("Remote pubkey : {}", hex::encode(session.remote_pubkey()));
        }

        // ── Contacts ──────────────────────────────────────────────────────────
        Command::Contacts(cmd) => {
            let store = ContactStore::open()?;
            match cmd {
                ContactsCommand::List => {
                    let contacts = store.list()?;
                    if contacts.is_empty() {
                        println!("No contacts yet.");
                    } else {
                        println!("{:<20} {:<30} {}", "Name", "Fingerprint", "Last seen");
                        println!("{}", "-".repeat(70));
                        for c in contacts {
                            let seen = c.last_seen.map(fmt_age).unwrap_or_else(|| "never".to_string());
                            println!("{:<20} {:<30} {}", c.display_name, c.fingerprint, seen);
                        }
                    }
                }
                ContactsCommand::Add { fingerprint, name } => {
                    let fingerprint = fingerprint.to_uppercase();
                    if store.find_by_fingerprint(&fingerprint)?.is_some() {
                        println!("Contact {fingerprint} already exists.");
                        return Ok(());
                    }
                    let contact = Contact::new(name.clone(), String::new(), fingerprint.clone());
                    store.add(&contact)?;
                    println!("Added '{name}' ({fingerprint}).");
                    println!("Public key verified on first connection.");
                }
                ContactsCommand::Remove { fingerprint } => {
                    let fingerprint = fingerprint.to_uppercase();
                    match store.find_by_fingerprint(&fingerprint)? {
                        Some(c) => {
                            store.remove(c.id)?;
                            println!("Removed '{}'.", c.display_name);
                        }
                        None => println!("No contact with fingerprint {fingerprint}."),
                    }
                }
            }
        }
    }
    Ok(())
}

fn fmt_age(secs: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if secs > now {
        return format!("{}s", secs);
    }
    let d = now - secs;
    if d < 60 { format!("{d}s ago") }
    else if d < 3600 { format!("{}m ago", d / 60) }
    else if d < 86400 { format!("{}h ago", d / 3600) }
    else { format!("{}d ago", d / 86400) }
}
