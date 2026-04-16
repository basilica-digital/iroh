//! Native peer for the WebRTC browser-to-native example.
//!
//! This connects to (or accepts connections from) the `webrtc-browser` example,
//! demonstrating cross-platform WebRTC DataChannel transport between a native CLI
//! process and a browser tab.
//!
//! ## Usage
//!
//! ```sh
//! # Terminal: start the native peer
//! cargo run --example webrtc-native --features unstable-webrtc-transport
//!
//! # Browser: open the webrtc-browser example (via `trunk serve`)
//! # and paste each peer's address into the other.
//! ```
//!
//! The native peer prints its address as JSON. Paste it into the browser's
//! "Peer Address" field. Then copy the browser's address and paste it into
//! the native peer's stdin prompt.
//!
//! Messages sent from either side are echoed back. The native peer also
//! prints the active transport path after each exchange so you can watch
//! the relay → WebRTC transition happen.

use std::io::Write as _;

use iroh::{
    Endpoint, EndpointAddr, RelayMode, Watcher,
    endpoint::{Connection, presets},
};
use iroh_base::SecretKey;
use iroh_webrtc::{SIGNALING_ALPN, WebRtc, WebRtcConfig};
use n0_error::{Result, StdResultExt};

/// Must match the browser example's ALPN.
const ALPN: &[u8] = b"iroh-example/webrtc-chat/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    println!("Creating iroh endpoint with WebRTC transport...");

    let secret = SecretKey::generate();
    let webrtc = WebRtc::new(secret.clone(), WebRtcConfig::default());

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .relay_mode(RelayMode::Staging)
        .alpns(vec![ALPN.to_vec(), SIGNALING_ALPN.to_vec()])
        .add_custom_transport(webrtc.transport())
        .bind()
        .await?;

    // Keep the signaling bridge alive for the lifetime of the process.
    let _signaling = webrtc.attach_iroh_signaling(endpoint.clone());

    println!("Endpoint ID: {}", endpoint.id().fmt_short());
    println!("Waiting for relay connection...");

    endpoint.online().await;

    let addr = endpoint.addr();
    let addr_json = serde_json::to_string(&addr).anyerr()?;
    println!("Online! Relay connected.\n");
    println!("=== YOUR ADDRESS (paste into browser) ===");
    println!("{addr_json}");
    println!("==========================================\n");

    // Spawn background acceptor
    let ep = endpoint.clone();
    let signaling_handle = _signaling;
    let accept_handle = tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Accept error: {e}");
                    continue;
                }
            };
            if conn.alpn() == SIGNALING_ALPN {
                signaling_handle.handle_incoming(conn);
                continue;
            }
            let remote = conn.remote_id().fmt_short().to_string();
            println!("Accepted connection from {remote}");
            print_paths(&conn);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn).await {
                    eprintln!("Connection error with {remote}: {e}");
                }
            });
        }
    });

    // Interactive connect-and-send loop
    println!("Paste the browser's address JSON below and press Enter to connect.");
    println!("(Or just wait for the browser to connect to you.)\n");

    let stdin = std::io::stdin();
    let mut line = String::new();

    print!("Peer address> ");
    std::io::stdout().flush().anyerr()?;
    stdin.read_line(&mut line).anyerr()?;
    let line = line.trim();

    if !line.is_empty() {
        let peer_addr: EndpointAddr = serde_json::from_str(line).anyerr()?;
        println!("Connecting to {}...", peer_addr.id.fmt_short());

        let conn = endpoint.connect(peer_addr, ALPN).await?;
        println!("Connected to {}!", conn.remote_id().fmt_short());
        print_paths(&conn);

        // Interactive send loop
        loop {
            let mut msg = String::new();
            print!("\nMessage (empty to quit)> ");
            std::io::stdout().flush().anyerr()?;
            stdin.read_line(&mut msg).anyerr()?;
            let msg = msg.trim();
            if msg.is_empty() {
                break;
            }

            let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
            send.write_all(msg.as_bytes()).await.anyerr()?;
            send.finish().anyerr()?;

            println!("> {msg}");

            let response = recv.read_to_end(64 * 1024).await.anyerr()?;
            let reply = String::from_utf8_lossy(&response);
            println!("< {reply}");

            print_paths(&conn);
        }

        conn.close(0u32.into(), b"done");
    }

    // Let the acceptor keep running until interrupted
    println!("\nPress Ctrl+C to exit.");
    accept_handle.await.anyerr()?;

    endpoint.close().await;
    Ok(())
}

/// Prints all network paths for a connection, highlighting the selected one.
fn print_paths(conn: &Connection) {
    let mut paths = conn.paths();
    let path_list = paths.get();
    if path_list.is_empty() {
        println!("  paths: (none yet)");
        return;
    }
    for path in path_list.iter() {
        let addr = path.remote_addr();
        let kind = if addr.is_relay() {
            "relay"
        } else if addr.is_ip() {
            "ip"
        } else if addr.is_custom() {
            "webrtc"
        } else {
            "unknown"
        };
        let selected = if path.is_selected() {
            " [SELECTED]"
        } else {
            ""
        };
        let rtt = path
            .rtt()
            .map(|d| format!(" rtt={d:?}"))
            .unwrap_or_default();
        println!("  path: {kind}{selected}{rtt}");
    }
}

/// Handles an accepted connection: reads messages and echoes them back.
async fn handle_connection(conn: Connection) -> Result<()> {
    loop {
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        let data = recv.read_to_end(64 * 1024).await.anyerr()?;
        let msg = String::from_utf8_lossy(&data);
        println!("< {msg}");

        let reply = format!("echo: {msg}");
        send.write_all(reply.as_bytes()).await.anyerr()?;
        send.finish().anyerr()?;

        println!("> {reply}");
        print_paths(&conn);
    }
}
