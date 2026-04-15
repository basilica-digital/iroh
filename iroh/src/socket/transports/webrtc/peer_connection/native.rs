//! Native WebRTC peer connection management using `str0m`.
//!
//! `str0m` is a sans-I/O WebRTC library: it processes input and produces output
//! but does not perform any I/O itself. We bind UDP sockets and drive str0m's
//! event loop to establish and maintain DataChannel connections.

use std::{
    collections::HashMap,
    fmt, io,
    net::UdpSocket,
    task::{Context, Waker},
    time::Instant,
};

use bytes::Bytes;
use iroh_base::EndpointId;
use str0m::{
    Candidate, Event, IceConnectionState, Input, Output, Rtc,
    change::{SdpAnswer, SdpOffer, SdpPendingOffer},
    channel::{ChannelConfig, ChannelData, ChannelId, Reliability},
    net::Receive,
};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::socket::transports::webrtc::{
    WebRtcConfig,
    signaling::{SignalingEnvelope, SignalingMsg},
};

/// Label for the unreliable datagram DataChannel.
const DATA_CHANNEL_LABEL: &str = "iroh-quic";

/// Manages WebRTC peer connections on native platforms using `str0m`.
#[derive(Debug)]
pub(crate) struct PeerConnectionManager {
    my_id: EndpointId,
    config: WebRtcConfig,
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
    socket: UdpSocket,
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
        config: WebRtcConfig,
        signaling_tx: mpsc::Sender<SignalingEnvelope>,
        datagram_tx: mpsc::Sender<(EndpointId, Bytes)>,
    ) -> Self {
        Self {
            my_id,
            config,
            peers: HashMap::new(),
            signaling_tx,
            datagram_tx,
            next_session_id: 0,
        }
    }

    /// Creates a new str0m `Rtc` instance with our ICE configuration.
    fn create_rtc(&self) -> Rtc {
        let rtc = Rtc::builder()
            // Only DataChannels, no media
            .set_ice_lite(false)
            .build(Instant::now());

        // Add STUN servers as remote candidates will be discovered via ICE
        // str0m handles STUN binding requests internally
        rtc
    }

    /// Binds a new UDP socket for a peer connection.
    ///
    /// Uses `127.0.0.1:0` so the local address is a valid host candidate for str0m.
    // TODO: For LAN/direct connectivity, discover real interface addresses
    // and add each as a host candidate. For NAT traversal, integrate STUN.
    fn bind_socket() -> io::Result<UdpSocket> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        Ok(socket)
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

        let mut rtc = self.create_rtc();

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

        debug!(
            peer = %peer_id.fmt_short(),
            session_id,
            local_addr = %local_addr,
            "initiating WebRTC connection"
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
        if let Some(existing) = self.peers.get(&peer_id) {
            if existing.state == ConnectionState::Connecting {
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
        }

        let socket = Self::bind_socket()?;
        let local_addr = socket.local_addr()?;

        let mut rtc = self.create_rtc();

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

        debug!(
            peer = %peer_id.fmt_short(),
            session_id,
            local_addr = %local_addr,
            "accepted WebRTC offer, sending answer"
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

        debug!(
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
        peer.rtc.add_remote_candidate(candidate);

        Ok(())
    }

    /// Handles a close request for a session.
    pub(crate) fn handle_close(&mut self, peer_id: EndpointId, session_id: u64) {
        if let Some(peer) = self.peers.get(&peer_id) {
            if peer.session_id == session_id {
                debug!(
                    peer = %peer_id.fmt_short(),
                    session_id,
                    "closing WebRTC connection"
                );
                self.peers.remove(&peer_id);
            }
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
                        .write(false, data)
                        .map_err(|e| io::Error::other(format!("DataChannel write failed: {e}")))?;
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
    pub(crate) fn poll(&mut self, _cx: &mut Context) {
        let now = Instant::now();
        let mut events = Vec::new();

        for (peer_id, peer) in &mut self.peers {
            // Read incoming UDP packets
            let mut buf = [0u8; 2000];
            loop {
                match peer.socket.recv_from(&mut buf) {
                    Ok((n, source)) => {
                        let local_addr = peer
                            .socket
                            .local_addr()
                            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
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
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        warn!(
                            peer = %peer_id.fmt_short(),
                            "UDP recv error: {e}"
                        );
                        break;
                    }
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
                        if let Err(e) = peer
                            .socket
                            .send_to(&transmit.contents, transmit.destination)
                        {
                            trace!(
                                peer = %peer_id.fmt_short(),
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
                debug!(
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
                debug!(
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
                        if let Some(ch_id) = peer.channel_id {
                            if let Some(mut channel) = peer.rtc.channel(ch_id) {
                                if let Err(e) = channel.write(false, &data) {
                                    warn!(
                                        peer = %peer_id.fmt_short(),
                                        "failed to flush pending send: {e}"
                                    );
                                }
                            }
                        }
                    }

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
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    if peer.channel_id == Some(channel_id) {
                        peer.channel_id = None;
                        peer.state = ConnectionState::Closed;
                    }
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
}
