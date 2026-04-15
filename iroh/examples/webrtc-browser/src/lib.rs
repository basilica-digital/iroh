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
    Endpoint, EndpointAddr, RelayMode,
    endpoint::{presets, transports::webrtc::WebRtcConfig},
};
use n0_future::task;
use tracing::info;
use wasm_bindgen::prelude::*;

const ALPN: &[u8] = b"iroh-example/webrtc-chat/0";

/// Global endpoint, initialized once.
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();

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
        loop {
            match ep.accept().await {
                Some(incoming) => {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            log(&format!("Accept error: {e}"));
                            continue;
                        }
                    };
                    let remote = conn.remote_id().fmt_short().to_string();
                    log(&format!("Accepted connection from {remote}"));

                    task::spawn(async move {
                        match handle_connection(conn).await {
                            Ok(()) => log(&format!("Connection with {remote} closed")),
                            Err(e) => log(&format!("Connection error with {remote}: {e}")),
                        }
                    });
                }
                None => {
                    log("Endpoint closed, stopping accept loop");
                    break;
                }
            }
        }
    });

    ENDPOINT
        .set(endpoint)
        .map_err(|_| JsValue::from_str("endpoint already initialized"))?;

    Ok(addr_json)
}

/// Handle an accepted connection: read messages and echo them back.
async fn handle_connection(conn: iroh::endpoint::Connection) -> Result<(), String> {
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

/// Connect to a remote peer and send a message.
///
/// `addr_json` is the JSON-serialized `EndpointAddr` from the other browser tab.
/// `message` is the text to send.
#[wasm_bindgen]
pub async fn send_message(addr_json: &str, message: &str) -> Result<String, JsValue> {
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
        "Connected to {}! Sending message...",
        conn.remote_id().fmt_short()
    ));

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

    conn.close(0u32.into(), b"done");

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
