//! WebRTC custom transport for direct peer-to-peer connections.
//!
//! Implements iroh's [`CustomTransport`] trait using WebRTC DataChannels,
//! enabling direct P2P connections between iroh endpoints — particularly
//! useful in browser/Wasm environments where raw UDP sockets are not
//! available.
//!
//! # Architecture
//!
//! The transport carries QUIC datagrams over unreliable, unordered WebRTC
//! DataChannels. QUIC handles reliability and ordering, so the DataChannel
//! acts as a raw datagram pipe.
//!
//! Signaling (SDP offer/answer and ICE candidate exchange) is pluggable: the
//! transport exposes its signaling flow via two [`mpsc`] endpoints, and the
//! user is free to pipe them over any carrier. See [`crate::signaling::iroh`]
//! for a ready-made iroh-ALPN bridge.
//!
//! # Platform support
//!
//! - **Browser (Wasm)**: uses the browser's native `RTCPeerConnection` via
//!   `web-sys`.
//! - **Native**: uses [`str0m`], a pure-Rust sans-I/O WebRTC implementation.

use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh::endpoint::transports::{Addr, CustomEndpoint, CustomSender, CustomTransport, Transmit};
use iroh_base::{CustomAddr, EndpointId, SecretKey};
use n0_watcher::Watchable;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::{
    addr::{parse_endpoint_id, to_custom_addr},
    config::WebRtcConfig,
    peer_connection::PeerConnectionManager,
    signaling::{SignalingEnvelope, SignalingMsg},
};

/// Out-of-band messages used by [`WebRtc::on_network_change`] to kick the
/// bound endpoint's reconnect state machine. Delivered over a dedicated mpsc
/// channel so the transport can be driven without holding a direct handle to
/// the [`PeerConnectionManager`] (which is created at bind time).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Control {
    /// A network-change notification. `major = true` means the local address
    /// or link changed (forces teardown of active peers); `major = false`
    /// only nudges peers that are currently in backoff.
    NetworkChange { major: bool },
}

/// Bundled signaling channel ends stashed inside the transport until
/// [`CustomTransport::bind`] is called.
///
/// `CustomTransport::bind` takes `&self`, so it cannot move fields out of the
/// transport. We put the to-be-consumed ends behind an `Option<Mutex<…>>` and
/// `.take()` them at bind time. Binding twice is an error.
type ChannelSlot = Arc<
    Mutex<
        Option<(
            mpsc::Receiver<SignalingEnvelope>,
            mpsc::Sender<SignalingEnvelope>,
            mpsc::Receiver<Control>,
        )>,
    >,
>;

/// WebRTC transport factory.
///
/// Instantiate via [`crate::WebRtc::new`] or construct directly with
/// [`WebRtcTransport::new`] if you want to drive signaling yourself.
#[derive(Debug, Clone)]
pub struct WebRtcTransport {
    secret_key: SecretKey,
    config: WebRtcConfig,
    channels: ChannelSlot,
    /// Sender for out-of-band control messages. Clones deliver into the same
    /// receiver owned by the bound endpoint.
    control_tx: mpsc::Sender<Control>,
}

impl WebRtcTransport {
    /// Creates a new WebRTC transport factory paired with externally-provided
    /// signaling channels.
    ///
    /// - `signaling_incoming_rx` receives [`SignalingEnvelope`]s that should
    ///   be fed into the transport's state machine (messages coming *from*
    ///   the remote peer).
    /// - `signaling_outgoing_tx` collects [`SignalingEnvelope`]s that the
    ///   transport wants to send *to* the remote peer.
    ///
    /// The caller is responsible for moving bytes between these channels and
    /// whatever signaling carrier they use (e.g. iroh QUIC streams via
    /// [`crate::signaling::iroh::IrohSignaling`], a WebSocket, etc.).
    pub fn new(
        secret_key: SecretKey,
        config: WebRtcConfig,
        signaling_incoming_rx: mpsc::Receiver<SignalingEnvelope>,
        signaling_outgoing_tx: mpsc::Sender<SignalingEnvelope>,
    ) -> Self {
        let (control_tx, control_rx) = mpsc::channel(16);
        Self {
            secret_key,
            config,
            channels: Arc::new(Mutex::new(Some((
                signaling_incoming_rx,
                signaling_outgoing_tx,
                control_rx,
            )))),
            control_tx,
        }
    }

    /// Notifies the bound endpoint of a network-change event.
    ///
    /// - `major = true` tears down all active WebRTC peers and re-negotiates
    ///   from scratch. Use this when the local IP or link state changes.
    /// - `major = false` only re-arms peers currently in exponential backoff,
    ///   letting them retry immediately.
    ///
    /// Must be called after [`CustomTransport::bind`] — before binding there
    /// is no endpoint to receive the event, and the call is silently dropped.
    pub fn on_network_change(&self, major: bool) {
        if let Err(e) = self.control_tx.try_send(Control::NetworkChange { major }) {
            debug!("WebRtcTransport::on_network_change: control channel send failed: {e}");
        }
    }
}

impl CustomTransport for WebRtcTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let (signaling_incoming_rx, signaling_outgoing_tx, control_rx) = self
            .channels
            .lock()
            .expect("poisoned")
            .take()
            .ok_or_else(|| io::Error::other("WebRtcTransport already bound"))?;

        let my_id = self.secret_key.public();
        let (datagram_tx, datagram_rx) = mpsc::channel(512);

        let peer_mgr = PeerConnectionManager::new(
            my_id,
            self.config.clone(),
            signaling_outgoing_tx,
            datagram_tx,
        );

        let endpoint = WebRtcEndpoint {
            addrs: Watchable::new(vec![to_custom_addr(my_id)]),
            peer_mgr: Arc::new(Mutex::new(peer_mgr)),
            signaling_incoming_rx,
            datagram_rx,
            control_rx,
        };

        debug!("WebRTC transport bound for {}", my_id.fmt_short());
        Ok(Box::new(endpoint))
    }
}

/// A bound WebRTC endpoint implementing [`CustomEndpoint`].
///
/// Manages peer connections and shuttles datagrams between the QUIC stack and
/// WebRTC DataChannels.
#[derive(Debug)]
pub(crate) struct WebRtcEndpoint {
    addrs: Watchable<Vec<CustomAddr>>,
    peer_mgr: Arc<Mutex<PeerConnectionManager>>,

    /// Incoming signaling messages fed in by the user-side signaling bridge.
    signaling_incoming_rx: mpsc::Receiver<SignalingEnvelope>,
    /// Datagrams received from peer DataChannels.
    datagram_rx: mpsc::Receiver<(EndpointId, Bytes)>,
    /// Out-of-band control messages from the [`WebRtcTransport`] factory
    /// (e.g. network-change notifications).
    control_rx: mpsc::Receiver<Control>,
}

impl WebRtcEndpoint {
    /// Drives the signaling state machine by draining any pending inbound
    /// signaling messages.
    fn process_signaling(&mut self, cx: &mut Context) {
        while let Poll::Ready(Some(envelope)) = self.signaling_incoming_rx.poll_recv(cx) {
            let mut mgr = self.peer_mgr.lock().expect("poisoned");
            match &envelope.msg {
                SignalingMsg::Offer { session_id, sdp } => {
                    debug!(
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
                    debug!(
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
                    debug!(
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

        // Drain out-of-band control messages (e.g. network-change notifications).
        while let Poll::Ready(Some(ctrl)) = self.control_rx.poll_recv(cx) {
            match ctrl {
                Control::NetworkChange { major } => {
                    debug!(major, "WebRTC: applying network-change control event");
                    let mut mgr = self.peer_mgr.lock().expect("poisoned");
                    mgr.on_network_change(major);
                }
            }
        }

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
        addr.id() == crate::addr::WEBRTC_TRANSPORT_ID
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        dst: &CustomAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let peer_id = parse_endpoint_id(dst)?;
        let mut mgr = self.peer_mgr.lock().expect("poisoned");

        // Split into individual datagrams if GSO segments are present.
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        for chunk in transmit.contents.chunks(segment_size) {
            match mgr.send(cx, peer_id, chunk) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Data has been queued in pending_sends and will be flushed
                    // when the DataChannel opens. Report success so QUIC's path
                    // validation tracks the PATH_CHALLENGE payload. If we
                    // returned Pending, QUIC would not track it, and when the
                    // response eventually arrives it would be silently dropped
                    // as unrecognized — causing path validation to always fail
                    // when the DataChannel takes time to establish.
                    debug!(
                        peer = %peer_id.fmt_short(),
                        "WebRTC send queued (DataChannel connecting)"
                    );
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sender_validates_transport_id() {
        let (sig_tx, _) = tokio::sync::mpsc::channel(1);
        let (dgram_tx, _) = tokio::sync::mpsc::channel(1);
        let key = SecretKey::generate();
        let mgr =
            PeerConnectionManager::new(key.public(), WebRtcConfig::default(), sig_tx, dgram_tx);
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

    #[tokio::test]
    async fn test_bind_twice_fails() {
        let (_in_tx, in_rx) = tokio::sync::mpsc::channel(1);
        let (out_tx, _out_rx) = tokio::sync::mpsc::channel(1);
        let key = SecretKey::generate();
        let t = WebRtcTransport::new(key, WebRtcConfig::default(), in_rx, out_tx);
        let first = t.bind();
        assert!(first.is_ok());
        let second = t.bind();
        assert!(second.is_err());
    }
}
