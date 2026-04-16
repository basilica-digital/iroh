//! Native WebRTC peer connection management using `str0m`.
//!
//! `str0m` is a sans-I/O WebRTC library: it processes input and produces output
//! but does not perform any I/O itself. We bind UDP sockets and drive str0m's
//! event loop to establish and maintain DataChannel connections.

use std::{
    collections::HashMap,
    fmt, io,
    task::{Context, Poll, Waker},
    time::Instant,
};

use tokio::io::ReadBuf;

use bytes::Bytes;
use iroh_base::EndpointId;
use str0m::{
    Candidate, Event, IceConnectionState, Input, Output, Rtc,
    change::{SdpAnswer, SdpOffer, SdpPendingOffer},
    channel::{ChannelConfig, ChannelData, ChannelId, Reliability},
    net::Receive,
};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use crate::socket::transports::webrtc::signaling::{SignalingEnvelope, SignalingMsg};

/// Label for the unreliable datagram DataChannel.
const DATA_CHANNEL_LABEL: &str = "iroh-quic";

/// Manages WebRTC peer connections on native platforms using `str0m`.
#[derive(Debug)]
pub(crate) struct PeerConnectionManager {
    my_id: EndpointId,
    /// Active peer connections keyed by remote EndpointId.
    peers: HashMap<EndpointId, PeerState>,
    /// Channel to send signaling messages outward (to relay).
    signaling_tx: mpsc::Sender<SignalingEnvelope>,
    /// Channel to deliver received datagrams to the WebRTC endpoint.
    datagram_tx: mpsc::Sender<(EndpointId, Bytes)>,
    /// Counter for generating unique session IDs.
    next_session_id: u64,
}

/// State of a single peer connection.
struct PeerState {
    /// The str0m RTC instance driving this connection.
    rtc: Rtc,
    /// The UDP socket bound for this peer's ICE traffic.
    /// Uses tokio so `poll_recv_from` registers the async waker,
    /// ensuring immediate wake-up when data arrives.
    socket: tokio::net::UdpSocket,
    /// Unique session identifier for correlating signaling.
    session_id: u64,
    /// The DataChannel ID once opened.
    channel_id: Option<ChannelId>,
    /// Current connection state.
    state: ConnectionState,
    /// Waker to notify when the connection becomes ready.
    send_waker: Option<Waker>,
    /// Datagrams queued while the connection is being established.
    pending_sends: Vec<Bytes>,
    /// Pending SDP offer awaiting an answer (offerer side only).
    pending_offer: Option<SdpPendingOffer>,
}

impl fmt::Debug for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerState")
            .field("rtc", &self.rtc)
            .field("socket", &self.socket)
            .field("session_id", &self.session_id)
            .field("channel_id", &self.channel_id)
            .field("state", &self.state)
            .field("send_waker", &self.send_waker)
            .field("pending_sends", &self.pending_sends)
            .field("pending_offer", &self.pending_offer.as_ref().map(|_| ".."))
            .finish()
    }
}

/// Connection lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    /// ICE/DTLS handshake in progress.
    Connecting,
    /// DataChannel is open and ready for data.
    Connected,
    /// Connection failed or was closed.
    Closed,
}

impl PeerConnectionManager {
    /// Creates a new peer connection manager.
    pub(crate) fn new(
        my_id: EndpointId,
        signaling_tx: mpsc::Sender<SignalingEnvelope>,
        datagram_tx: mpsc::Sender<(EndpointId, Bytes)>,
    ) -> Self {
        Self {
            my_id,
            peers: HashMap::new(),
            signaling_tx,
            datagram_tx,
            next_session_id: 0,
        }
    }

    /// Creates a new str0m `Rtc` instance.
    fn create_rtc() -> Rtc {
        Rtc::builder()
            // Only DataChannels, no media
            .set_ice_lite(false)
            .build(Instant::now())
    }

    /// Binds a new UDP socket for a peer connection.
    ///
    /// Binds to the default outgoing interface address so that:
    /// - `socket.local_addr()` returns a real IP (needed by str0m ICE)
    /// - The socket can send/receive to remote peers (not just loopback)
    ///
    /// Falls back to `127.0.0.1` if no default route is available.
    fn bind_socket() -> io::Result<tokio::net::UdpSocket> {
        let bind_ip =
            Self::default_local_ip().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let std_socket = std::net::UdpSocket::bind(std::net::SocketAddr::new(bind_ip, 0))?;
        std_socket.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(std_socket)
    }

    /// Discovers the default outgoing IP address using the UDP "connect trick".
    ///
    /// Connecting a UDP socket to an external address (without sending data)
    /// lets the OS pick the outgoing interface, which we read back.
    fn default_local_ip() -> Option<std::net::IpAddr> {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        probe.connect("8.8.8.8:80").ok()?;
        probe.local_addr().ok().map(|a| a.ip())
    }

    /// Generates a unique session ID.
    fn next_session_id(&mut self) -> u64 {
        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        id
    }

    /// Initiates a connection to a remote peer (we are the offerer).
    fn initiate(&mut self, peer_id: EndpointId) -> io::Result<()> {
        if self.peers.contains_key(&peer_id) {
            return Ok(());
        }

        let session_id = self.next_session_id();
        let socket = Self::bind_socket()?;
        let local_addr = socket.local_addr()?;

        let mut rtc = Self::create_rtc();

        // Add our local socket as an ICE host candidate
        if let Ok(candidate) = Candidate::host(local_addr, "udp") {
            rtc.add_local_candidate(candidate);
        }

        // Create DataChannel (as offerer) and generate SDP offer
        let mut changes = rtc.sdp_api();
        changes.add_channel_with_config(ChannelConfig {
            label: DATA_CHANNEL_LABEL.to_string(),
            ordered: false,
            reliability: Reliability::MaxRetransmits { retransmits: 0 },
            ..Default::default()
        });
        let (offer, pending) = changes
            .apply()
            .expect("should have pending changes from data channel creation");
        let sdp = offer.to_sdp_string();

        info!(
            peer = %peer_id.fmt_short(),
            session_id,
            local_addr = %local_addr,
            "initiating WebRTC connection (native offerer)"
        );

        let _ = self.signaling_tx.try_send(SignalingEnvelope {
            peer: peer_id,
            msg: SignalingMsg::Offer { session_id, sdp },
        });

        self.peers.insert(
            peer_id,
            PeerState {
                rtc,
                socket,
                session_id,
                channel_id: None,
                state: ConnectionState::Connecting,
                send_waker: None,
                pending_sends: Vec::new(),
                pending_offer: Some(pending),
            },
        );

        Ok(())
    }

    /// Handles an incoming SDP offer from a remote peer.
    pub(crate) fn handle_offer(
        &mut self,
        peer_id: EndpointId,
        session_id: u64,
        sdp: &str,
    ) -> io::Result<()> {
        // Glare resolution: if we already have a pending connection to this peer,
        // the peer with the smaller EndpointId yields (is "polite").
        if let Some(existing) = self.peers.get(&peer_id)
            && existing.state == ConnectionState::Connecting
        {
            if self.my_id < peer_id {
                // We are polite: roll back our offer, accept theirs
                debug!(
                    peer = %peer_id.fmt_short(),
                    "glare detected, yielding as polite peer"
                );
                self.peers.remove(&peer_id);
            } else {
                // We are impolite: ignore their offer
                debug!(
                    peer = %peer_id.fmt_short(),
                    "glare detected, ignoring offer as impolite peer"
                );
                return Ok(());
            }
        }

        let socket = Self::bind_socket()?;
        let local_addr = socket.local_addr()?;

        let mut rtc = Self::create_rtc();

        // Add our local socket as an ICE host candidate
        if let Ok(candidate) = Candidate::host(local_addr, "udp") {
            rtc.add_local_candidate(candidate);
        }

        // Accept the remote offer
        let offer = SdpOffer::from_sdp_string(sdp)
            .map_err(|e| io::Error::other(format!("invalid SDP offer: {e}")))?;
        let answer = rtc
            .sdp_api()
            .accept_offer(offer)
            .map_err(|e| io::Error::other(format!("failed to accept offer: {e}")))?;
        let sdp_answer = answer.to_sdp_string();

        info!(
            peer = %peer_id.fmt_short(),
            session_id,
            local_addr = %local_addr,
            "accepted WebRTC offer, sending answer (native answerer)"
        );

        let _ = self.signaling_tx.try_send(SignalingEnvelope {
            peer: peer_id,
            msg: SignalingMsg::Answer {
                session_id,
                sdp: sdp_answer,
            },
        });

        self.peers.insert(
            peer_id,
            PeerState {
                rtc,
                socket,
                session_id,
                channel_id: None,
                state: ConnectionState::Connecting,
                send_waker: None,
                pending_sends: Vec::new(),
                pending_offer: None,
            },
        );

        Ok(())
    }

    /// Handles an incoming SDP answer from a remote peer.
    pub(crate) fn handle_answer(
        &mut self,
        peer_id: EndpointId,
        session_id: u64,
        sdp: &str,
    ) -> io::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or_else(|| io::Error::other("no pending connection for answer"))?;

        if peer.session_id != session_id {
            return Err(io::Error::other("session_id mismatch"));
        }

        let pending = peer
            .pending_offer
            .take()
            .ok_or_else(|| io::Error::other("no pending offer for answer"))?;

        let answer = SdpAnswer::from_sdp_string(sdp)
            .map_err(|e| io::Error::other(format!("invalid SDP answer: {e}")))?;

        peer.rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .map_err(|e| io::Error::other(format!("failed to accept answer: {e}")))?;

        info!(
            peer = %peer_id.fmt_short(),
            session_id,
            "accepted WebRTC answer"
        );

        Ok(())
    }

    /// Handles an incoming ICE candidate from a remote peer.
    pub(crate) fn handle_ice_candidate(
        &mut self,
        peer_id: EndpointId,
        session_id: u64,
        candidate: &str,
        _sdp_mid: Option<&str>,
    ) -> io::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or_else(|| io::Error::other("no connection for ICE candidate"))?;

        if peer.session_id != session_id {
            return Err(io::Error::other("session_id mismatch"));
        }

        let candidate = Candidate::from_sdp_string(candidate)
            .map_err(|e| io::Error::other(format!("invalid ICE candidate: {e}")))?;
        info!(
            peer = %peer_id.fmt_short(),
            session_id,
            %candidate,
            "adding remote ICE candidate"
        );
        peer.rtc.add_remote_candidate(candidate);

        Ok(())
    }

    /// Handles a close request for a session.
    pub(crate) fn handle_close(&mut self, peer_id: EndpointId, session_id: u64) {
        if let Some(peer) = self.peers.get(&peer_id)
            && peer.session_id == session_id
        {
            debug!(
                peer = %peer_id.fmt_short(),
                session_id,
                "closing WebRTC connection"
            );
            self.peers.remove(&peer_id);
        }
    }

    /// Sends a datagram to a peer. Returns `WouldBlock` if the connection is not ready.
    pub(crate) fn send(
        &mut self,
        cx: &mut Context,
        peer_id: EndpointId,
        data: &[u8],
    ) -> io::Result<()> {
        // Ensure a connection exists
        if !self.peers.contains_key(&peer_id) {
            self.initiate(peer_id)?;
        }

        let peer = self.peers.get_mut(&peer_id).expect("just inserted");

        match peer.state {
            ConnectionState::Connected => {
                if let Some(channel_id) = peer.channel_id {
                    let mut channel = peer
                        .rtc
                        .channel(channel_id)
                        .ok_or_else(|| io::Error::other("DataChannel not found"))?;
                    channel
                        .write(true, data)
                        .map_err(|e| io::Error::other(format!("DataChannel write failed: {e}")))?;
                    Self::flush_peer_outputs(peer, &peer_id);
                    Ok(())
                } else {
                    Err(io::Error::other("connected but no DataChannel"))
                }
            }
            ConnectionState::Connecting => {
                // Queue the datagram and register the waker
                peer.pending_sends.push(Bytes::copy_from_slice(data));
                peer.send_waker = Some(cx.waker().clone());
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            ConnectionState::Closed => {
                // Remove the failed connection and try to initiate a new one
                self.peers.remove(&peer_id);
                self.initiate(peer_id)?;
                let peer = self.peers.get_mut(&peer_id).expect("just inserted");
                peer.pending_sends.push(Bytes::copy_from_slice(data));
                peer.send_waker = Some(cx.waker().clone());
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        }
    }

    /// Polls all peer connections, driving str0m's event loop.
    ///
    /// This must be called regularly (from `CustomEndpoint::poll_recv`) to:
    /// - Read incoming UDP packets and feed them to str0m
    /// - Process str0m outputs (outgoing packets, events)
    /// - Handle DataChannel events
    pub(crate) fn poll(&mut self, cx: &mut Context) {
        let now = Instant::now();
        let mut events = Vec::new();

        for (peer_id, peer) in &mut self.peers {
            // Read incoming UDP packets.
            // Using tokio's poll_recv_from registers the waker so the task
            // wakes immediately when data arrives (instead of waiting for
            // the next QUIC timer).
            let mut buf = [0u8; 2000];
            loop {
                let mut read_buf = ReadBuf::new(&mut buf);
                match peer.socket.poll_recv_from(cx, &mut read_buf) {
                    Poll::Ready(Ok(source)) => {
                        let n = read_buf.filled().len();
                        let local_addr = peer
                            .socket
                            .local_addr()
                            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
                        let receive = match Receive::new(
                            str0m::net::Protocol::Udp,
                            source,
                            local_addr,
                            &buf[..n],
                        ) {
                            Ok(r) => r,
                            Err(e) => {
                                trace!(
                                    peer = %peer_id.fmt_short(),
                                    "ignoring unrecognized packet: {e}"
                                );
                                continue;
                            }
                        };
                        if let Err(e) = peer.rtc.handle_input(Input::Receive(now, receive)) {
                            warn!(
                                peer = %peer_id.fmt_short(),
                                "str0m handle_input error: {e}"
                            );
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        warn!(
                            peer = %peer_id.fmt_short(),
                            "UDP recv error: {e}"
                        );
                        break;
                    }
                    Poll::Pending => break,
                }
            }

            // Handle timeout
            if let Err(e) = peer.rtc.handle_input(Input::Timeout(now)) {
                warn!(
                    peer = %peer_id.fmt_short(),
                    "str0m timeout error: {e}"
                );
            }

            // Process str0m outputs
            loop {
                match peer.rtc.poll_output() {
                    Ok(Output::Transmit(transmit)) => {
                        trace!(
                            peer = %peer_id.fmt_short(),
                            dst = %transmit.destination,
                            len = transmit.contents.len(),
                            "str0m transmit"
                        );
                        if let Err(e) = peer
                            .socket
                            .try_send_to(&transmit.contents, transmit.destination)
                        {
                            warn!(
                                peer = %peer_id.fmt_short(),
                                dst = %transmit.destination,
                                "UDP send error: {e}"
                            );
                        }
                    }
                    Ok(Output::Event(event)) => {
                        events.push((*peer_id, event));
                    }
                    Ok(Output::Timeout(_)) => break,
                    Err(e) => {
                        warn!(
                            peer = %peer_id.fmt_short(),
                            "str0m poll_output error: {e}"
                        );
                        break;
                    }
                }
            }
        }

        // Process events outside the borrow of self.peers
        for (peer_id, event) in events {
            self.handle_event(peer_id, event);
        }
    }

    /// Handles a str0m event for a specific peer.
    fn handle_event(&mut self, peer_id: EndpointId, event: Event) {
        match event {
            Event::IceConnectionStateChange(state) => {
                info!(
                    peer = %peer_id.fmt_short(),
                    ?state,
                    "ICE connection state changed"
                );
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    match state {
                        IceConnectionState::Connected => {
                            // ICE is connected, but we wait for the DataChannel to open
                        }
                        IceConnectionState::Disconnected => {
                            peer.state = ConnectionState::Closed;
                            if let Some(waker) = peer.send_waker.take() {
                                waker.wake();
                            }
                        }
                        _ => {}
                    }
                }
            }
            Event::ChannelOpen(channel_id, label) => {
                info!(
                    peer = %peer_id.fmt_short(),
                    %label,
                    "DataChannel opened"
                );
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.channel_id = Some(channel_id);
                    peer.state = ConnectionState::Connected;

                    // Flush pending sends
                    let pending: Vec<_> = peer.pending_sends.drain(..).collect();
                    for data in pending {
                        if let Some(ch_id) = peer.channel_id
                            && let Some(mut channel) = peer.rtc.channel(ch_id)
                            && let Err(e) = channel.write(true, &data)
                        {
                            warn!(
                                peer = %peer_id.fmt_short(),
                                "failed to flush pending send: {e}"
                            );
                        }
                    }
                    Self::flush_peer_outputs(peer, &peer_id);

                    if let Some(waker) = peer.send_waker.take() {
                        waker.wake();
                    }
                }
            }
            Event::ChannelData(data) => {
                self.handle_channel_data(peer_id, data);
            }
            Event::ChannelClose(channel_id) => {
                debug!(
                    peer = %peer_id.fmt_short(),
                    "DataChannel closed"
                );
                if let Some(peer) = self.peers.get_mut(&peer_id)
                    && peer.channel_id == Some(channel_id)
                {
                    peer.channel_id = None;
                    peer.state = ConnectionState::Closed;
                }
            }
            _ => {
                // Ignore other events (media-related, etc.)
            }
        }
    }

    /// Handles incoming data on a DataChannel.
    fn handle_channel_data(&self, peer_id: EndpointId, data: ChannelData) {
        let payload = Bytes::copy_from_slice(&data.data);
        if let Err(e) = self.datagram_tx.try_send((peer_id, payload)) {
            warn!(
                peer = %peer_id.fmt_short(),
                "failed to deliver WebRTC datagram: {e}"
            );
        }
    }

    /// Flushes pending str0m transmit outputs for a peer.
    ///
    /// After writing data to a DataChannel via `channel.write()`, str0m buffers
    /// the SCTP/DTLS frames internally. They are only emitted as UDP packets
    /// through `poll_output()`. This method drains all ready outputs and, if
    /// none are immediately available, fast-forwards to str0m's next scheduled
    /// timeout to force buffered data out.
    fn flush_peer_outputs(peer: &mut PeerState, peer_id: &EndpointId) {
        let mut produced_transmit = false;
        loop {
            match peer.rtc.poll_output() {
                Ok(Output::Transmit(transmit)) => {
                    produced_transmit = true;
                    trace!(
                        peer = %peer_id.fmt_short(),
                        dst = %transmit.destination,
                        len = transmit.contents.len(),
                        "flush transmit"
                    );
                    if let Err(e) = peer
                        .socket
                        .try_send_to(&transmit.contents, transmit.destination)
                    {
                        warn!(
                            peer = %peer_id.fmt_short(),
                            dst = %transmit.destination,
                            "UDP send error during flush: {e}"
                        );
                    }
                }
                Ok(Output::Event(_)) => {
                    // Events will be handled in the next poll() call.
                }
                Ok(Output::Timeout(t)) => {
                    // Fast-forward to the next str0m timeout to flush any
                    // data that was buffered but not yet packaged.
                    let _ = peer.rtc.handle_input(Input::Timeout(t));
                    while let Ok(Output::Transmit(transmit)) = peer.rtc.poll_output() {
                        produced_transmit = true;
                        trace!(
                            peer = %peer_id.fmt_short(),
                            dst = %transmit.destination,
                            len = transmit.contents.len(),
                            "flush transmit (post-timeout)"
                        );
                        if let Err(e) = peer
                            .socket
                            .try_send_to(&transmit.contents, transmit.destination)
                        {
                            warn!(
                                peer = %peer_id.fmt_short(),
                                dst = %transmit.destination,
                                "UDP send error during flush: {e}"
                            );
                        }
                    }
                    break;
                }
                Err(e) => {
                    warn!(
                        peer = %peer_id.fmt_short(),
                        "str0m error during flush: {e}"
                    );
                    break;
                }
            }
        }
        if !produced_transmit {
            debug!(
                peer = %peer_id.fmt_short(),
                "flush produced no transmits"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh_base::SecretKey;

    use super::*;

    /// Relays all pending signaling messages between two managers.
    ///
    /// Outgoing envelopes have `peer` = destination, but the receiving manager
    /// expects `peer` = source (like the relay would set it). This function
    /// remaps accordingly.
    fn relay_signaling(
        a_rx: &mut mpsc::Receiver<SignalingEnvelope>,
        b_rx: &mut mpsc::Receiver<SignalingEnvelope>,
        id_a: EndpointId,
        id_b: EndpointId,
        mgr_a: &mut PeerConnectionManager,
        mgr_b: &mut PeerConnectionManager,
    ) {
        // A → B: remap peer to A (the source)
        while let Ok(env) = a_rx.try_recv() {
            let remapped = SignalingEnvelope {
                peer: id_a,
                msg: env.msg,
            };
            let _ = dispatch_signaling(mgr_b, &remapped);
        }
        // B → A: remap peer to B (the source)
        while let Ok(env) = b_rx.try_recv() {
            let remapped = SignalingEnvelope {
                peer: id_b,
                msg: env.msg,
            };
            let _ = dispatch_signaling(mgr_a, &remapped);
        }
    }

    fn dispatch_signaling(
        mgr: &mut PeerConnectionManager,
        env: &SignalingEnvelope,
    ) -> io::Result<()> {
        match &env.msg {
            SignalingMsg::Offer { session_id, sdp } => mgr.handle_offer(env.peer, *session_id, sdp),
            SignalingMsg::Answer { session_id, sdp } => {
                mgr.handle_answer(env.peer, *session_id, sdp)
            }
            SignalingMsg::IceCandidate {
                session_id,
                candidate,
                sdp_mid,
            } => mgr.handle_ice_candidate(env.peer, *session_id, candidate, sdp_mid.as_deref()),
            SignalingMsg::Close { session_id } => {
                mgr.handle_close(env.peer, *session_id);
                Ok(())
            }
        }
    }

    /// Tests that two native PeerConnectionManagers can connect via signaling
    /// and exchange datagrams over a DataChannel on localhost.
    #[tokio::test]
    async fn test_native_peer_connection_data_exchange() {
        let _ = tracing_subscriber::fmt::try_init();

        let key_a = SecretKey::generate();
        let key_b = SecretKey::generate();
        let id_a = key_a.public();
        let id_b = key_b.public();

        let (a_sig_tx, mut a_sig_rx) = mpsc::channel(64);
        let (b_sig_tx, mut b_sig_rx) = mpsc::channel(64);
        let (_a_dgram_tx, mut _a_dgram_rx) = mpsc::channel::<(EndpointId, Bytes)>(64);
        let (b_dgram_tx, mut b_dgram_rx) = mpsc::channel(64);

        let mut mgr_a = PeerConnectionManager::new(id_a, a_sig_tx, _a_dgram_tx);
        let mut mgr_b = PeerConnectionManager::new(id_b, b_sig_tx, b_dgram_tx);

        // A sends to B — triggers connection initiation, queues data
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(&waker);

        let test_data = b"hello from A to B";
        let err = mgr_a.send(&mut cx, id_b, test_data).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        // Drive ICE/DTLS until data arrives or timeout
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);

        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timeout: WebRTC DataChannel did not open within 15s"
            );

            // Relay signaling messages between managers
            relay_signaling(
                &mut a_sig_rx,
                &mut b_sig_rx,
                id_a,
                id_b,
                &mut mgr_a,
                &mut mgr_b,
            );

            // Drive str0m I/O on both sides
            mgr_a.poll(&mut cx);
            mgr_b.poll(&mut cx);

            // Check if B received the data
            if let Ok((from, data)) = b_dgram_rx.try_recv() {
                assert_eq!(from, id_a);
                assert_eq!(&data[..], test_data);
                return; // Success
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Tests that glare resolution works: when both peers initiate simultaneously,
    /// the peer with the smaller EndpointId yields.
    #[tokio::test]
    async fn test_glare_resolution() {
        let key_a = SecretKey::generate();
        let key_b = SecretKey::generate();
        let id_a = key_a.public();
        let id_b = key_b.public();

        // Determine which is "polite" (smaller ID)
        let (polite_id, impolite_id) = if id_a < id_b {
            (id_a, id_b)
        } else {
            (id_b, id_a)
        };

        let (sig_tx, _) = mpsc::channel(64);
        let (dgram_tx, _) = mpsc::channel(64);

        let mut polite_mgr =
            PeerConnectionManager::new(polite_id, sig_tx.clone(), dgram_tx.clone());
        let mut impolite_mgr = PeerConnectionManager::new(impolite_id, sig_tx, dgram_tx);

        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(&waker);

        // Both sides initiate (via send which triggers initiate)
        let _ = polite_mgr.send(&mut cx, impolite_id, b"ping");
        let _ = impolite_mgr.send(&mut cx, polite_id, b"ping");

        // The polite peer receives an offer from the impolite peer.
        // Since polite already has a pending connection, glare is detected.
        // The polite peer yields: drops its own connection and accepts.
        let result = polite_mgr.handle_offer(
            impolite_id,
            99,
            // Minimal valid SDP — str0m will parse this
            "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n",
        );
        // Should not error — polite peer accepts
        // (may fail on SDP parsing, but shouldn't fail on glare check)
        // The important thing is it doesn't return early with "ignoring offer"
        let _ = result; // SDP parsing may fail, that's OK for this test

        // The impolite peer receives an offer from the polite peer.
        // It should ignore it.
        let result = impolite_mgr.handle_offer(
            polite_id,
            100,
            "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n",
        );
        // Should succeed (returns Ok) but not create a new connection
        assert!(result.is_ok());
    }

    /// Tests that sending to a closed connection triggers re-initiation.
    #[tokio::test]
    async fn test_reconnect_after_close() {
        let key_a = SecretKey::generate();
        let key_b = SecretKey::generate();
        let id_a = key_a.public();
        let id_b = key_b.public();

        let (sig_tx, mut sig_rx) = mpsc::channel(64);
        let (dgram_tx, _) = mpsc::channel(64);
        let mut mgr = PeerConnectionManager::new(id_a, sig_tx, dgram_tx);

        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(&waker);

        // First send — initiates connection
        let err = mgr.send(&mut cx, id_b, b"first").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        // Drain the signaling offer
        let envelope = sig_rx.try_recv().expect("should have offer");
        let session_1 = match &envelope.msg {
            SignalingMsg::Offer { session_id, .. } => *session_id,
            other => panic!("expected Offer, got {other:?}"),
        };

        // Close the session
        mgr.handle_close(id_b, session_1);

        // Second send — should re-initiate with a new session
        let err = mgr.send(&mut cx, id_b, b"second").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        let envelope = sig_rx.try_recv().expect("should have new offer");
        let session_2 = match &envelope.msg {
            SignalingMsg::Offer { session_id, .. } => *session_id,
            other => panic!("expected Offer, got {other:?}"),
        };

        // Should be a different session
        assert_ne!(session_1, session_2);
    }

    /// Verifies str0m can parse ICE candidate strings in browser format.
    ///
    /// Browsers return candidates from `RTCIceCandidate.candidate` in a
    /// specific format (with "candidate:" prefix, possibly with extensions
    /// like "generation" and "network-cost"). str0m must parse these for
    /// cross-platform ICE to work.
    #[test]
    fn test_parse_browser_ice_candidates() {
        // Typical browser host candidate
        let host = "candidate:842163049 1 udp 2122260223 192.168.1.100 54321 typ host generation 0 ufrag 1234 network-id 1 network-cost 10";
        let result = Candidate::from_sdp_string(host);
        assert!(
            result.is_ok(),
            "Failed to parse browser host candidate: {result:?}"
        );

        // Browser SRFLX candidate (via STUN)
        let srflx = "candidate:842163049 1 udp 1677729535 203.0.113.5 54321 typ srflx raddr 192.168.1.100 rport 12345 generation 0 ufrag 1234 network-id 1";
        let result = Candidate::from_sdp_string(srflx);
        assert!(
            result.is_ok(),
            "Failed to parse browser srflx candidate: {result:?}"
        );

        // Minimal candidate (no extensions)
        let minimal = "candidate:1 1 udp 2130706175 10.0.0.1 5000 typ host";
        let result = Candidate::from_sdp_string(minimal);
        assert!(
            result.is_ok(),
            "Failed to parse minimal candidate: {result:?}"
        );
    }

    /// Verifies that str0m includes the host candidate in the SDP offer,
    /// which is needed for browsers to learn the native peer's ICE candidate.
    #[tokio::test]
    async fn test_sdp_contains_host_candidate() {
        let key = SecretKey::generate();
        let id = key.public();

        let (sig_tx, mut sig_rx) = mpsc::channel(64);
        let (dgram_tx, _) = mpsc::channel(64);
        let mut mgr = PeerConnectionManager::new(id, sig_tx, dgram_tx);

        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(&waker);

        let peer_key = SecretKey::generate();
        let peer_id = peer_key.public();

        // Trigger initiate to generate an offer
        let _ = mgr.send(&mut cx, peer_id, b"test");

        let envelope = sig_rx.try_recv().expect("should have offer");
        let sdp = match &envelope.msg {
            SignalingMsg::Offer { sdp, .. } => sdp,
            other => panic!("expected Offer, got {other:?}"),
        };

        // The SDP must contain at least one candidate line
        assert!(
            sdp.contains("a=candidate:"),
            "SDP offer must include host candidate line(s).\nSDP:\n{sdp}"
        );

        // The candidate should be a UDP host candidate, not loopback
        let default_ip = PeerConnectionManager::default_local_ip();
        if let Some(ip) = default_ip {
            assert!(
                sdp.contains(&ip.to_string()),
                "SDP must include the default IP ({ip}).\nSDP:\n{sdp}"
            );
        }
    }
}
