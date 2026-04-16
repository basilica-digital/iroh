//! WebRTC custom transport for direct peer-to-peer connections.
//!
//! This module implements the [`CustomTransport`] trait using WebRTC DataChannels,
//! enabling direct P2P connections between iroh endpoints — particularly useful in
//! browser/Wasm environments where raw UDP sockets are not available.
//!
//! # Architecture
//!
//! The transport carries QUIC datagrams over unreliable, unordered WebRTC DataChannels.
//! QUIC handles reliability and ordering, so the DataChannel acts as a raw datagram pipe.
//!
//! Signaling (SDP offer/answer and ICE candidate exchange) is performed through the
//! relay transport: signaling messages are tagged with a magic prefix and demuxed from
//! regular QUIC traffic at the [`Transports`](super::Transports) layer.
//!
//! # Platform Support
//!
//! - **Browser (Wasm)**: Uses the browser's native `RTCPeerConnection` via `web-sys`.
//! - **Native**: Uses the [`str0m`] crate, a pure-Rust sans-I/O WebRTC implementation.

mod peer_connection;
pub(crate) mod signaling;

use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh_base::{CustomAddr, EndpointId, SecretKey};
use n0_watcher::Watchable;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use self::{
    peer_connection::PeerConnectionManager,
    signaling::{SignalingEnvelope, SignalingMsg},
};
use super::{Addr, CustomEndpoint, CustomSender, Transmit};

/// Transport ID for WebRTC, registered in `TRANSPORTS.md`.
///
/// ASCII for "WRT" = `0x575254`.
pub const WEBRTC_TRANSPORT_ID: u64 = 0x575254;

/// Configuration for a STUN or TURN server used during ICE gathering.
#[derive(Debug, Clone)]
pub struct IceServer {
    /// STUN/TURN server URLs (e.g. `"stun:stun.l.google.com:19302"`).
    pub urls: Vec<String>,
    /// Optional username for TURN authentication.
    pub username: Option<String>,
    /// Optional credential for TURN authentication.
    pub credential: Option<String>,
}

impl Default for IceServer {
    fn default() -> Self {
        Self {
            urls: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            username: None,
            credential: None,
        }
    }
}

/// Configuration for the WebRTC transport.
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    /// ICE servers to use for gathering candidates.
    pub ice_servers: Vec<IceServer>,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            ice_servers: vec![IceServer::default()],
        }
    }
}

/// WebRTC transport factory.
///
/// Creates [`WebRtcEndpoint`] instances when bound. Each endpoint manages
/// peer connections and signaling for a single iroh endpoint.
#[derive(Debug, Clone)]
pub struct WebRtcTransport {
    secret_key: SecretKey,
    config: WebRtcConfig,
}

impl WebRtcTransport {
    /// Creates a new WebRTC transport with the given secret key and configuration.
    pub fn new(secret_key: SecretKey, config: WebRtcConfig) -> Self {
        Self { secret_key, config }
    }

    /// Binds the transport with externally-provided signaling channels.
    ///
    /// The signaling channels are wired by the [`Transports`](super::Transports) layer
    /// to route signaling datagrams between the relay transport and this WebRTC endpoint.
    ///
    /// - `signaling_incoming_rx`: receives signaling messages intercepted from relay datagrams
    /// - `signaling_outgoing_tx`: sends signaling messages to be forwarded through the relay
    pub(crate) fn bind_with_signaling(
        &self,
        signaling_incoming_rx: mpsc::Receiver<SignalingEnvelope>,
        signaling_outgoing_tx: mpsc::Sender<SignalingEnvelope>,
    ) -> io::Result<Box<dyn CustomEndpoint>> {
        let my_id = self.secret_key.public();
        let (datagram_tx, datagram_rx) = mpsc::channel(512);

        let peer_mgr = PeerConnectionManager::new(
            my_id,
            self.config.clone(),
            signaling_outgoing_tx,
            datagram_tx,
        );

        let endpoint = WebRtcEndpoint {
            my_id,
            addrs: Watchable::new(vec![to_custom_addr(my_id)]),
            peer_mgr: Arc::new(Mutex::new(peer_mgr)),
            signaling_incoming_rx,
            datagram_rx,
        };

        debug!("WebRTC transport bound for {}", my_id.fmt_short());
        Ok(Box::new(endpoint))
    }
}

/// Converts an [`EndpointId`] to a [`CustomAddr`] for this transport.
pub fn to_custom_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from((WEBRTC_TRANSPORT_ID, &endpoint.as_bytes()[..]))
}

/// Parses an [`EndpointId`] from a WebRTC [`CustomAddr`].
fn parse_endpoint_id(addr: &CustomAddr) -> io::Result<EndpointId> {
    if addr.id() != WEBRTC_TRANSPORT_ID {
        return Err(io::Error::other("not a WebRTC transport address"));
    }
    let key_bytes: &[u8; 32] = addr
        .data()
        .try_into()
        .map_err(|_| io::Error::other("invalid WebRTC address: wrong key length"))?;
    EndpointId::from_bytes(key_bytes)
        .map_err(|_| io::Error::other("invalid WebRTC address: bad public key"))
}

/// A bound WebRTC endpoint implementing [`CustomEndpoint`].
///
/// Manages peer connections and routes datagrams between the QUIC stack
/// and WebRTC DataChannels.
#[derive(Debug)]
pub(crate) struct WebRtcEndpoint {
    my_id: EndpointId,
    addrs: Watchable<Vec<CustomAddr>>,
    peer_mgr: Arc<Mutex<PeerConnectionManager>>,

    /// Incoming signaling messages from the relay (fed by the `Transports` layer).
    signaling_incoming_rx: mpsc::Receiver<SignalingEnvelope>,
    /// Datagrams received from peer DataChannels.
    datagram_rx: mpsc::Receiver<(EndpointId, Bytes)>,
}

impl WebRtcEndpoint {
    /// Processes pending incoming signaling messages.
    ///
    /// Called from `poll_recv` to drive the signaling state machine.
    fn process_signaling(&mut self, cx: &mut Context) {
        while let Poll::Ready(Some(envelope)) = self.signaling_incoming_rx.poll_recv(cx) {
            let mut mgr = self.peer_mgr.lock().expect("poisoned");
            match &envelope.msg {
                SignalingMsg::Offer { session_id, sdp } => {
                    info!(
                        peer = %envelope.peer.fmt_short(),
                        session_id,
                        "received WebRTC offer via signaling"
                    );
                    if let Err(e) = mgr.handle_offer(envelope.peer, *session_id, sdp) {
                        warn!(
                            peer = %envelope.peer.fmt_short(),
                            "failed to handle WebRTC offer: {e}"
                        );
                    }
                }
                SignalingMsg::Answer { session_id, sdp } => {
                    info!(
                        peer = %envelope.peer.fmt_short(),
                        session_id,
                        "received WebRTC answer via signaling"
                    );
                    if let Err(e) = mgr.handle_answer(envelope.peer, *session_id, sdp) {
                        warn!(
                            peer = %envelope.peer.fmt_short(),
                            "failed to handle WebRTC answer: {e}"
                        );
                    }
                }
                SignalingMsg::IceCandidate {
                    session_id,
                    candidate,
                    sdp_mid,
                } => {
                    info!(
                        peer = %envelope.peer.fmt_short(),
                        session_id,
                        %candidate,
                        "received ICE candidate via signaling"
                    );
                    if let Err(e) = mgr.handle_ice_candidate(
                        envelope.peer,
                        *session_id,
                        candidate,
                        sdp_mid.as_deref(),
                    ) {
                        warn!(
                            peer = %envelope.peer.fmt_short(),
                            "failed to handle ICE candidate: {e}"
                        );
                    }
                }
                SignalingMsg::Close { session_id } => {
                    debug!(
                        peer = %envelope.peer.fmt_short(),
                        session_id,
                        "received WebRTC close"
                    );
                    mgr.handle_close(envelope.peer, *session_id);
                }
            }
        }
    }
}

impl CustomEndpoint for WebRtcEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(WebRtcSender {
            peer_mgr: self.peer_mgr.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        let n = bufs.len();
        debug_assert_eq!(n, metas.len());
        debug_assert_eq!(n, source_addrs.len());
        if n == 0 {
            return Poll::Ready(Ok(0));
        }

        // Drive signaling state machine
        self.process_signaling(cx);

        // Drive the peer connection manager (native only — handles I/O polling)
        {
            let mut mgr = self.peer_mgr.lock().expect("poisoned");
            mgr.poll(cx);
        }

        // Receive datagrams from DataChannels
        let mut count = 0;
        while count < n {
            match self.datagram_rx.poll_recv(cx) {
                Poll::Ready(Some((from, data))) => {
                    if bufs[count].len() < data.len() {
                        // Buffer too small, skip this datagram
                        break;
                    }
                    bufs[count][..data.len()].copy_from_slice(&data);
                    metas[count].len = data.len();
                    metas[count].stride = data.len();
                    source_addrs[count] = Addr::Custom(to_custom_addr(from));
                    count += 1;
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("datagram channel closed")));
                }
                Poll::Pending => break,
            }
        }

        if count > 0 {
            trace!("WebRTC recv: filled {count} slots");
            Poll::Ready(Ok(count))
        } else {
            Poll::Pending
        }
    }
}

/// Sender for the WebRTC transport.
#[derive(Debug)]
struct WebRtcSender {
    peer_mgr: Arc<Mutex<PeerConnectionManager>>,
}

impl CustomSender for WebRtcSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == WEBRTC_TRANSPORT_ID
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        dst: &CustomAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let peer_id = parse_endpoint_id(dst)?;
        info!(
            peer = %peer_id.fmt_short(),
            len = transmit.contents.len(),
            "WebRTC poll_send called"
        );
        let mut mgr = self.peer_mgr.lock().expect("poisoned");

        // Split into individual datagrams if GSO segments are present
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        for chunk in transmit.contents.chunks(segment_size) {
            match mgr.send(cx, peer_id, chunk) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Connection not ready yet, return Pending
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(()))
    }
}

/// Channels used by the `Transports` layer to shuttle signaling messages
/// between the relay transport and the WebRTC transport.
#[derive(Debug)]
pub(crate) struct SignalingChannel {
    /// Send signaling to the WebRTC endpoint (relay → webrtc).
    pub incoming_tx: mpsc::Sender<SignalingEnvelope>,
    /// Receive outgoing signaling from the WebRTC endpoint (webrtc → relay).
    pub outgoing_rx: mpsc::Receiver<SignalingEnvelope>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_base::SecretKey;

    #[test]
    fn test_custom_addr_roundtrip() {
        let key = SecretKey::generate();
        let endpoint_id = key.public();

        let addr = to_custom_addr(endpoint_id);
        assert_eq!(addr.id(), WEBRTC_TRANSPORT_ID);

        let parsed = parse_endpoint_id(&addr).unwrap();
        assert_eq!(parsed, endpoint_id);
    }

    #[test]
    fn test_parse_wrong_transport_id() {
        let addr = CustomAddr::from((0x123456u64, &[0u8; 32][..]));
        let err = parse_endpoint_id(&addr).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn test_parse_wrong_key_length() {
        // 16 bytes instead of 32
        let addr = CustomAddr::from((WEBRTC_TRANSPORT_ID, &[0u8; 16][..]));
        let err = parse_endpoint_id(&addr).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn test_sender_validates_transport_id() {
        let (sig_tx, _) = tokio::sync::mpsc::channel(1);
        let (dgram_tx, _) = tokio::sync::mpsc::channel(1);
        let key = SecretKey::generate();
        let mgr = peer_connection::PeerConnectionManager::new(
            key.public(),
            WebRtcConfig::default(),
            sig_tx,
            dgram_tx,
        );
        let sender = WebRtcSender {
            peer_mgr: Arc::new(std::sync::Mutex::new(mgr)),
        };

        // Valid WebRTC address
        let valid = to_custom_addr(key.public());
        assert!(sender.is_valid_send_addr(&valid));

        // Wrong transport ID
        let invalid = CustomAddr::from((0x999999u64, &[0u8; 32][..]));
        assert!(!sender.is_valid_send_addr(&invalid));
    }
}
