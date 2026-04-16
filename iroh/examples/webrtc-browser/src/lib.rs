//! Browser-to-browser WebRTC example for iroh.
//!
//! Build and serve with [Trunk](https://trunkrs.dev/):
//!
//! ```sh
//! cd iroh/examples/webrtc-browser
//! trunk serve
//! ```
//!
//! Then open two browser tabs at <http://localhost:8080>.

use std::sync::OnceLock;

use iroh::{
    Endpoint, EndpointAddr, RelayMode, Watcher,
    endpoint::{Connection, presets, transports::webrtc::WebRtcConfig},
};
use n0_future::task;
use tracing::info;
use wasm_bindgen::prelude::*;

const ALPN: &[u8] = b"iroh-example/webrtc-chat/0";

/// Global endpoint, initialized once.
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();

/// Global outgoing connection, set by `connect()`.
static CONN: OnceLock<Connection> = OnceLock::new();

/// Append a line to the `#log` textarea in the page.
fn log(msg: &str) {
    info!("{msg}");
    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(doc) = window.document() else { return };
    let Some(el) = doc.get_element_by_id("log") else {
        return;
    };
    let ta: web_sys::HtmlTextAreaElement = el.unchecked_into();
    let prev = ta.value();
    let next = if prev.is_empty() {
        msg.to_string()
    } else {
        format!("{prev}\n{msg}")
    };
    ta.set_value(&next);
    ta.set_scroll_top(ta.scroll_height());
}

/// Initialize the iroh endpoint with WebRTC transport.
///
/// Call this once from JS. It creates the endpoint, starts accepting
/// connections in the background, and returns the endpoint's address as JSON.
#[wasm_bindgen]
pub async fn init() -> Result<String, JsValue> {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
    let mut config = wasm_tracing::WasmLayerConfig::new();
    config.set_max_level(tracing::Level::DEBUG);
    let _ = wasm_tracing::set_as_global_default_with_config(config);

    log("Creating iroh endpoint with WebRTC transport...");

    let endpoint = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Staging)
        .alpns(vec![ALPN.to_vec()])
        .add_webrtc_transport(WebRtcConfig::default())
        .bind()
        .await
        .map_err(|e| JsValue::from_str(&format!("bind failed: {e}")))?;

    log(&format!("Endpoint ID: {}", endpoint.id().fmt_short()));
    log("Waiting for relay connection...");

    n0_future::time::timeout(std::time::Duration::from_secs(15), endpoint.online())
        .await
        .map_err(|_| JsValue::from_str("timeout waiting for relay connection"))?;

    let addr = endpoint.addr();
    let addr_json = serde_json::to_string(&addr)
        .map_err(|e| JsValue::from_str(&format!("serialize addr: {e}")))?;

    log("Online! Relay connected.");
    log(&format!("Address: {addr_json}"));

    // Spawn background task to accept incoming connections
    let ep = endpoint.clone();
    task::spawn(async move {
        log("Listening for incoming connections...");
        while let Some(incoming) = ep.accept().await {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    log(&format!("Accept error: {e}"));
                    continue;
                }
            };
            let remote = conn.remote_id().fmt_short().to_string();
            log(&format!("Accepted connection from {remote}"));
            log_paths(&conn);

            task::spawn(async move {
                match handle_connection(conn).await {
                    Ok(()) => log(&format!("Connection with {remote} closed")),
                    Err(e) => log(&format!("Connection error with {remote}: {e}")),
                }
            });
        }
        log("Endpoint closed, stopping accept loop");
    });

    ENDPOINT
        .set(endpoint)
        .map_err(|_| JsValue::from_str("endpoint already initialized"))?;

    Ok(addr_json)
}

/// Logs all network paths for a connection, highlighting the selected (active) one.
fn log_paths(conn: &Connection) {
    let mut paths = conn.paths();
    let path_list = paths.get();
    if path_list.is_empty() {
        log("  paths: (none yet)");
        return;
    }
    for path in path_list.iter() {
        let addr = path.remote_addr();
        let kind = if addr.is_relay() {
            "relay"
        } else if addr.is_ip() {
            "ip"
        } else if addr.is_custom() {
            "webrtc (custom)"
        } else {
            "unknown"
        };
        let selected = if path.is_selected() { " [SELECTED]" } else { "" };
        let rtt = path
            .rtt()
            .map(|d| format!(" rtt={d:?}"))
            .unwrap_or_default();
        log(&format!("  path: {kind}{selected}{rtt}"));
    }
}

/// Handle an accepted connection: read messages and echo them back.
async fn handle_connection(conn: Connection) -> Result<(), String> {
    loop {
        let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| format!("{e}"))?;
        let data = recv
            .read_to_end(64 * 1024)
            .await
            .map_err(|e| format!("read: {e}"))?;
        let msg = String::from_utf8_lossy(&data);
        log(&format!("< {msg}"));

        let reply = format!("echo: {msg}");
        send.write_all(reply.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;
    }
}

/// Connect to a remote peer and keep the connection open.
///
/// `addr_json` is the JSON-serialized `EndpointAddr` from the other browser tab.
/// The connection is stored globally so subsequent `send_message` calls reuse it.
/// This gives WebRTC signaling time to complete and establish a direct path.
#[wasm_bindgen]
pub async fn connect(addr_json: &str) -> Result<(), JsValue> {
    let endpoint = ENDPOINT
        .get()
        .ok_or_else(|| JsValue::from_str("endpoint not initialized — call init() first"))?;

    let addr: EndpointAddr = serde_json::from_str(addr_json)
        .map_err(|e| JsValue::from_str(&format!("invalid address JSON: {e}")))?;

    log(&format!("Connecting to {}...", addr.id.fmt_short()));

    let conn = endpoint
        .connect(addr, ALPN)
        .await
        .map_err(|e| JsValue::from_str(&format!("connect failed: {e}")))?;

    log(&format!(
        "Connected to {}!",
        conn.remote_id().fmt_short()
    ));
    log_paths(&conn);

    CONN.set(conn)
        .map_err(|_| JsValue::from_str("already connected — reload to reconnect"))?;

    Ok(())
}

/// Send a message over the existing connection.
///
/// Must call `connect()` first to establish the connection.
#[wasm_bindgen]
pub async fn send_message(message: &str) -> Result<String, JsValue> {
    let conn = CONN
        .get()
        .ok_or_else(|| JsValue::from_str("not connected — call connect() first"))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| JsValue::from_str(&format!("open_bi: {e:#}")))?;

    send.write_all(message.as_bytes())
        .await
        .map_err(|e| JsValue::from_str(&format!("write: {e}")))?;
    send.finish()
        .map_err(|e| JsValue::from_str(&format!("finish: {e}")))?;

    log(&format!("> {message}"));

    let response = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| JsValue::from_str(&format!("read response: {e}")))?;
    let reply = String::from_utf8_lossy(&response).to_string();

    log(&format!("< {reply}"));

    // Log paths so we can see if WebRTC has kicked in.
    log_paths(conn);

    Ok(reply)
}

/// Get the current endpoint address as JSON.
#[wasm_bindgen]
pub fn get_addr() -> Result<String, JsValue> {
    let endpoint = ENDPOINT
        .get()
        .ok_or_else(|| JsValue::from_str("endpoint not initialized"))?;

    let addr = endpoint.addr();
    serde_json::to_string(&addr).map_err(|e| JsValue::from_str(&format!("serialize: {e}")))
}

/// Returns the current WebRTC diagnostic log for copy-paste debugging.
///
/// Each entry is prefixed with a `Date.now()` millisecond timestamp. Covers
/// SDP offer/answer exchange, local/remote ICE candidates, ICE state
/// transitions, addIceCandidate failures, and DataChannel open.
#[wasm_bindgen]
pub fn webrtc_debug() -> String {
    iroh::endpoint::transports::webrtc::webrtc_debug_snapshot()
}

/// Clears the WebRTC diagnostic log.
#[wasm_bindgen]
pub fn webrtc_debug_reset() {
    iroh::endpoint::transports::webrtc::webrtc_debug_clear();
}
