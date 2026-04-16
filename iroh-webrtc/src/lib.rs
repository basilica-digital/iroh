//! WebRTC DataChannel custom transport for [iroh](https://docs.rs/iroh).
//!
//! This crate plugs into iroh's [`CustomTransport`](iroh::endpoint::transports::CustomTransport)
//! interface (behind the `unstable-custom-transports` feature) and lets two
//! iroh endpoints upgrade a connection to a direct WebRTC DataChannel — useful
//! wherever a browser is involved or where UDP traversal is difficult.
//!
//! # Architecture
//!
//! - [`WebRtcTransport`] is the [`CustomTransport`](iroh::endpoint::transports::CustomTransport)
//!   factory; it carries QUIC datagrams over a WebRTC DataChannel.
//! - WebRTC needs a side channel for SDP/ICE signaling. The transport exposes
//!   this flow via two [`tokio::sync::mpsc`] endpoints. Any carrier works.
//! - For iroh-based applications, [`IrohSignaling`] ships as a ready-made
//!   bridge that runs signaling over a dedicated ALPN on the user's existing
//!   iroh [`Endpoint`](iroh::Endpoint).
//!
//! # Bootstrap
//!
//! WebRTC is an **upgrade** transport: the initial QUIC handshake must complete
//! over relay or direct IP. Once connected, signaling flows over the
//! [`SIGNALING_ALPN`] stream, the DataChannel is negotiated, and the WebRTC
//! path appears on the existing connection.
//!
//! # Example
//!
//! ```no_run
//! use iroh::{Endpoint, endpoint::presets};
//! use iroh_base::SecretKey;
//! use iroh_webrtc::{SIGNALING_ALPN, WebRtc, WebRtcConfig};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let secret = SecretKey::generate();
//! let webrtc = WebRtc::new(secret.clone(), WebRtcConfig::default());
//!
//! let endpoint = Endpoint::builder(presets::N0)
//!     .secret_key(secret)
//!     .alpns(vec![SIGNALING_ALPN.to_vec(), b"my-app/1".to_vec()])
//!     .add_custom_transport(webrtc.transport())
//!     .bind()
//!     .await?;
//!
//! let signaling = webrtc.attach_iroh_signaling(endpoint.clone());
//!
//! // Dispatch inbound signaling connections from your accept loop:
//! while let Some(incoming) = endpoint.accept().await {
//!     let conn = match incoming.await { Ok(c) => c, Err(_) => continue };
//!     if conn.alpn() == SIGNALING_ALPN {
//!         signaling.handle_incoming(conn);
//!         continue;
//!     }
//!     // ... application ALPN handling ...
//! }
//! # Ok(()) }
//! ```

pub mod addr;
pub mod config;
pub mod signaling;
pub mod transport;

mod peer_connection;

/// In-browser diagnostic log snapshot; see module-level docs.
#[cfg(wasm_browser)]
pub use peer_connection::{webrtc_debug_clear, webrtc_debug_snapshot};

use std::sync::{Arc, Mutex};

use iroh::endpoint::transports::CustomTransport;
use iroh_base::SecretKey;
use tokio::sync::mpsc;

pub use crate::{
    addr::{WEBRTC_TRANSPORT_ID, to_custom_addr},
    config::{IceServer, RetryConfig, WebRtcConfig},
    signaling::{SignalingEnvelope, SignalingMsg},
    transport::WebRtcTransport,
};

#[cfg(feature = "iroh-signaling")]
pub use crate::signaling::iroh::{IrohSignaling, SIGNALING_ALPN};

/// Channel capacity for both signaling mpsc pairs. 64 is enough to absorb a
/// burst of ICE candidates without blocking the state machine.
const SIGNALING_CHANNEL_CAP: usize = 64;

/// Convenience handle owning the [`WebRtcTransport`] factory and the
/// user-side ends of the signaling mpsc pair.
///
/// The typical flow is:
///
/// 1. [`WebRtc::new`] — create the handle and internal channels.
/// 2. [`WebRtc::transport`] — pass the factory to
///    [`iroh::endpoint::Builder::add_custom_transport`].
/// 3. [`WebRtc::attach_iroh_signaling`] — spawn the signaling bridge over the
///    bound [`iroh::Endpoint`].
///
/// For custom signaling carriers, bypass this handle and use
/// [`WebRtcTransport::new`] directly with your own mpsc pair.
#[derive(Debug)]
pub struct WebRtc {
    transport: Arc<WebRtcTransport>,
    /// User-side send: pushes inbound signaling INTO the transport.
    to_transport_tx: mpsc::Sender<SignalingEnvelope>,
    /// User-side recv: receives outbound signaling FROM the transport.
    /// Consumed at most once by [`Self::attach_iroh_signaling`].
    from_transport_rx: Arc<Mutex<Option<mpsc::Receiver<SignalingEnvelope>>>>,
}

impl WebRtc {
    /// Constructs a new handle with its own signaling mpsc pair.
    pub fn new(secret_key: SecretKey, config: WebRtcConfig) -> Self {
        let (to_transport_tx, to_transport_rx) = mpsc::channel(SIGNALING_CHANNEL_CAP);
        let (from_transport_tx, from_transport_rx) = mpsc::channel(SIGNALING_CHANNEL_CAP);

        let transport =
            WebRtcTransport::new(secret_key, config, to_transport_rx, from_transport_tx);

        Self {
            transport: Arc::new(transport),
            to_transport_tx,
            from_transport_rx: Arc::new(Mutex::new(Some(from_transport_rx))),
        }
    }

    /// Returns the transport factory, ready to pass to
    /// [`iroh::endpoint::Builder::add_custom_transport`].
    pub fn transport(&self) -> Arc<dyn CustomTransport> {
        self.transport.clone()
    }

    /// Spawns the iroh-ALPN signaling bridge.
    ///
    /// Must be called at most once per [`WebRtc`] handle; subsequent calls
    /// panic. Drop the returned [`IrohSignaling`] to stop the bridge.
    #[cfg(feature = "iroh-signaling")]
    pub fn attach_iroh_signaling(&self, endpoint: iroh::Endpoint) -> IrohSignaling {
        let rx = self
            .from_transport_rx
            .lock()
            .expect("poisoned")
            .take()
            .expect("attach_iroh_signaling called twice on the same WebRtc handle");
        IrohSignaling::spawn(endpoint, rx, self.to_transport_tx.clone())
    }

    /// Returns a clone of the sender used to feed inbound signaling messages
    /// into the transport.
    ///
    /// Only needed if you are wiring a custom (non-iroh) signaling carrier —
    /// in that case pair this with [`Self::take_outgoing_rx`].
    pub fn to_transport_tx(&self) -> mpsc::Sender<SignalingEnvelope> {
        self.to_transport_tx.clone()
    }

    /// Takes the receiver for outbound signaling. Can only be called once.
    ///
    /// Only needed for custom signaling carriers. Mutually exclusive with
    /// [`Self::attach_iroh_signaling`].
    pub fn take_outgoing_rx(&self) -> Option<mpsc::Receiver<SignalingEnvelope>> {
        self.from_transport_rx.lock().expect("poisoned").take()
    }

    /// Notifies the transport of a network-change event.
    ///
    /// Mirrors QUIC's hole-punch retry behavior: when the local link or IP
    /// changes (e.g. Wi-Fi ↔ cellular roam), WebRTC peers that are stuck in
    /// exponential backoff get re-armed so the next send attempt retries
    /// immediately. When `major = true`, even active peers are torn down so
    /// they re-gather ICE candidates from the new local address.
    ///
    /// This is a best-effort nudge — calls are silently dropped if the
    /// transport is not yet bound or the internal control channel is full.
    pub fn on_network_change(&self, major: bool) {
        self.transport.on_network_change(major);
    }
}
