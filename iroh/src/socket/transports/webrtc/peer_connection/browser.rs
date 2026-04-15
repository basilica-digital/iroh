//! Browser WebRTC peer connection management using `web-sys`.
//!
//! Uses the browser's native `RTCPeerConnection` API through `web-sys` bindings.
//! All JavaScript callbacks push events to Rust channels for poll-based integration.

use std::{
    cell::RefCell,
    collections::HashMap,
    io,
    rc::Rc,
    task::{Context, Waker},
};

use bytes::Bytes;
use iroh_base::EndpointId;
use js_sys::{Array, Object, Reflect, Uint8Array};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{
    MessageEvent, RtcConfiguration, RtcDataChannel, RtcDataChannelEvent, RtcDataChannelInit,
    RtcDataChannelType, RtcIceCandidateInit, RtcIceConnectionState, RtcPeerConnection,
    RtcPeerConnectionIceEvent, RtcSdpType, RtcSessionDescriptionInit,
};

use crate::socket::transports::webrtc::{
    WebRtcConfig,
    signaling::{SignalingEnvelope, SignalingMsg},
};

/// Label for the unreliable datagram DataChannel.
const DATA_CHANNEL_LABEL: &str = "iroh-quic";

/// Manages WebRTC peer connections in the browser using `web-sys`.
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

// SAFETY: Wasm is single-threaded. The `!Send` types (`RtcPeerConnection`, `Closure`)
// in `PeerState` are JS objects that cannot cross thread boundaries, but on wasm there
// are no threads to cross. The `CustomSender` trait requires `Send + Sync`.
unsafe impl Send for PeerConnectionManager {}
unsafe impl Sync for PeerConnectionManager {}

/// State of a single browser peer connection.
///
/// Note: `RtcPeerConnection` and `Closure` are `!Send`, so browser
/// `PeerConnectionManager` is also `!Send`. This is fine because Wasm
/// is single-threaded.
struct PeerState {
    /// The browser RTCPeerConnection.
    pc: RtcPeerConnection,
    /// The DataChannel for sending/receiving QUIC datagrams.
    data_channel: Option<RtcDataChannel>,
    /// Unique session identifier for correlating signaling.
    session_id: u64,
    /// Current connection state.
    state: ConnectionState,
    /// Waker to notify when the connection becomes ready.
    send_waker: Option<Waker>,
    /// Datagrams queued while the connection is being established.
    pending_sends: Vec<Bytes>,
    /// Closures we need to keep alive for the JS callbacks.
    _closures: Vec<Closure<dyn FnMut(JsValue)>>,
}

impl std::fmt::Debug for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerState")
            .field("session_id", &self.session_id)
            .field("state", &self.state)
            .field("pending_sends", &self.pending_sends.len())
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

/// Events from JavaScript callbacks, pushed into a channel.
#[derive(Debug)]
enum PeerEvent {
    /// ICE candidate gathered locally.
    IceCandidate {
        candidate: String,
        sdp_mid: Option<String>,
    },
    /// ICE gathering produced a null candidate (gathering complete).
    IceGatheringComplete,
    /// ICE connection state changed.
    IceConnectionStateChange(String),
    /// DataChannel opened (either created by us or received from remote).
    DataChannelOpen,
    /// Data received on the DataChannel.
    DataChannelMessage(Bytes),
    /// DataChannel closed.
    DataChannelClose,
}

impl PeerConnectionManager {
    /// Creates a new browser peer connection manager.
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

    /// Creates a browser `RtcConfiguration` from our ICE server config.
    fn create_rtc_config(&self) -> RtcConfiguration {
        let config = RtcConfiguration::new();
        let ice_servers = Array::new();

        for server in &self.config.ice_servers {
            let ice_server = Object::new();
            let urls = Array::new();
            for url in &server.urls {
                urls.push(&JsValue::from_str(url));
            }
            Reflect::set(&ice_server, &"urls".into(), &urls).ok();
            if let Some(username) = &server.username {
                Reflect::set(&ice_server, &"username".into(), &username.into()).ok();
            }
            if let Some(credential) = &server.credential {
                Reflect::set(&ice_server, &"credential".into(), &credential.into()).ok();
            }
            ice_servers.push(&ice_server);
        }

        config.set_ice_servers(&ice_servers);
        config
    }

    /// Creates a new RTCPeerConnection with event handlers.
    fn create_peer_connection(
        &self,
        peer_id: EndpointId,
        session_id: u64,
    ) -> io::Result<(
        RtcPeerConnection,
        mpsc::Receiver<PeerEvent>,
        Vec<Closure<dyn FnMut(JsValue)>>,
    )> {
        let config = self.create_rtc_config();
        let pc = RtcPeerConnection::new_with_configuration(&config)
            .map_err(|e| io::Error::other(format!("failed to create RTCPeerConnection: {e:?}")))?;

        let (event_tx, event_rx) = mpsc::channel(64);
        let mut closures: Vec<Closure<dyn FnMut(JsValue)>> = Vec::new();

        // onicecandidate
        let signaling_tx = self.signaling_tx.clone();
        let pid = peer_id;
        let sid = session_id;
        let on_ice_candidate = Closure::wrap(Box::new(move |event: JsValue| {
            let event: RtcPeerConnectionIceEvent = event.unchecked_into();
            if let Some(candidate) = event.candidate() {
                let candidate_str = candidate.candidate();
                if !candidate_str.is_empty() {
                    let _ = signaling_tx.try_send(SignalingEnvelope {
                        peer: pid,
                        msg: SignalingMsg::IceCandidate {
                            session_id: sid,
                            candidate: candidate_str,
                            sdp_mid: candidate.sdp_mid(),
                        },
                    });
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        pc.set_onicecandidate(Some(on_ice_candidate.as_ref().unchecked_ref()));
        closures.push(on_ice_candidate);

        // oniceconnectionstatechange
        let pc_clone = pc.clone();
        let event_tx_clone = event_tx.clone();
        let on_ice_state = Closure::wrap(Box::new(move |_: JsValue| {
            let state = pc_clone.ice_connection_state();
            let state_str = format!("{:?}", state);
            let _ = event_tx_clone.try_send(PeerEvent::IceConnectionStateChange(state_str));
        }) as Box<dyn FnMut(JsValue)>);
        pc.set_oniceconnectionstatechange(Some(on_ice_state.as_ref().unchecked_ref()));
        closures.push(on_ice_state);

        // ondatachannel (for the answerer — the offerer creates the channel directly)
        let datagram_tx = self.datagram_tx.clone();
        let event_tx_clone = event_tx.clone();
        let pid = peer_id;
        let on_datachannel = Closure::wrap(Box::new(move |event: JsValue| {
            let event: RtcDataChannelEvent = event.unchecked_into();
            let channel = event.channel();
            channel.set_binary_type(RtcDataChannelType::Arraybuffer);

            // Set up message handler on the received channel
            let dtx = datagram_tx.clone();
            let p = pid;
            let on_message = Closure::wrap(Box::new(move |event: JsValue| {
                let event: MessageEvent = event.unchecked_into();
                if let Ok(buf) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                    let array = Uint8Array::new(&buf);
                    let data = Bytes::from(array.to_vec());
                    let _ = dtx.try_send((p, data));
                }
            }) as Box<dyn FnMut(JsValue)>);
            channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            on_message.forget(); // Leak closure — channel owns the callback

            let etx = event_tx_clone.clone();
            let on_open = Closure::wrap(Box::new(move |_: JsValue| {
                let _ = etx.try_send(PeerEvent::DataChannelOpen);
            }) as Box<dyn FnMut(JsValue)>);
            channel.set_onopen(Some(on_open.as_ref().unchecked_ref()));
            on_open.forget();
        }) as Box<dyn FnMut(JsValue)>);
        pc.set_ondatachannel(Some(on_datachannel.as_ref().unchecked_ref()));
        closures.push(on_datachannel);

        Ok((pc, event_rx, closures))
    }

    /// Sets up event handlers on a DataChannel we created (offerer side).
    fn setup_data_channel_events(
        &self,
        channel: &RtcDataChannel,
        peer_id: EndpointId,
        event_tx: &mpsc::Sender<PeerEvent>,
    ) -> Vec<Closure<dyn FnMut(JsValue)>> {
        let mut closures = Vec::new();
        channel.set_binary_type(RtcDataChannelType::Arraybuffer);

        // onopen
        let etx = event_tx.clone();
        let on_open = Closure::wrap(Box::new(move |_: JsValue| {
            let _ = etx.try_send(PeerEvent::DataChannelOpen);
        }) as Box<dyn FnMut(JsValue)>);
        channel.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        closures.push(on_open);

        // onmessage
        let dtx = self.datagram_tx.clone();
        let pid = peer_id;
        let on_message = Closure::wrap(Box::new(move |event: JsValue| {
            let event: MessageEvent = event.unchecked_into();
            if let Ok(buf) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                let array = Uint8Array::new(&buf);
                let data = Bytes::from(array.to_vec());
                let _ = dtx.try_send((pid, data));
            }
        }) as Box<dyn FnMut(JsValue)>);
        channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        closures.push(on_message);

        // onclose
        let etx = event_tx.clone();
        let on_close = Closure::wrap(Box::new(move |_: JsValue| {
            let _ = etx.try_send(PeerEvent::DataChannelClose);
        }) as Box<dyn FnMut(JsValue)>);
        channel.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        closures.push(on_close);

        closures
    }

    /// Generates a unique session ID.
    fn next_session_id(&mut self) -> u64 {
        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        id
    }

    /// Initiates a connection to a remote peer (we are the offerer).
    ///
    /// This spawns an async task to create the offer since browser WebRTC APIs
    /// are promise-based.
    fn initiate(&mut self, peer_id: EndpointId) -> io::Result<()> {
        if self.peers.contains_key(&peer_id) {
            return Ok(());
        }

        let session_id = self.next_session_id();
        let (pc, event_rx, mut closures) = self.create_peer_connection(peer_id, session_id)?;

        // Create DataChannel (as offerer)
        let mut dc_init = RtcDataChannelInit::new();
        dc_init.set_ordered(false);
        dc_init.set_max_retransmits(0);

        let channel = pc.create_data_channel_with_data_channel_dict(DATA_CHANNEL_LABEL, &dc_init);
        let dc_closures = self.setup_data_channel_events(&channel, peer_id, &mpsc::channel(1).0);
        closures.extend(dc_closures);

        // Spawn async task to create offer
        let signaling_tx = self.signaling_tx.clone();
        let pc_clone = pc.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let offer = wasm_bindgen_futures::JsFuture::from(pc_clone.create_offer())
                .await
                .expect("create_offer failed");

            let offer_sdp = Reflect::get(&offer, &"sdp".into())
                .expect("no sdp in offer")
                .as_string()
                .expect("sdp is not a string");

            let mut desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
            desc.set_sdp(&offer_sdp);
            wasm_bindgen_futures::JsFuture::from(pc_clone.set_local_description(&desc))
                .await
                .expect("set_local_description failed");

            let _ = signaling_tx
                .send(SignalingEnvelope {
                    peer: peer_id,
                    msg: SignalingMsg::Offer {
                        session_id,
                        sdp: offer_sdp,
                    },
                })
                .await;
        });

        debug!(
            peer = %peer_id.fmt_short(),
            session_id,
            "initiating WebRTC connection (browser)"
        );

        self.peers.insert(
            peer_id,
            PeerState {
                pc,
                data_channel: Some(channel),
                session_id,
                state: ConnectionState::Connecting,
                send_waker: None,
                pending_sends: Vec::new(),
                _closures: closures,
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
        // Glare resolution: peer with smaller EndpointId yields
        if let Some(existing) = self.peers.get(&peer_id) {
            if existing.state == ConnectionState::Connecting {
                if self.my_id < peer_id {
                    debug!(
                        peer = %peer_id.fmt_short(),
                        "glare detected, yielding as polite peer"
                    );
                    self.peers.remove(&peer_id);
                } else {
                    debug!(
                        peer = %peer_id.fmt_short(),
                        "glare detected, ignoring offer as impolite peer"
                    );
                    return Ok(());
                }
            }
        }

        let (pc, event_rx, closures) = self.create_peer_connection(peer_id, session_id)?;

        // Set remote description (offer) and create answer
        let sdp_owned = sdp.to_string();
        let signaling_tx = self.signaling_tx.clone();
        let pc_clone = pc.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let mut offer_desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
            offer_desc.set_sdp(&sdp_owned);
            wasm_bindgen_futures::JsFuture::from(pc_clone.set_remote_description(&offer_desc))
                .await
                .expect("set_remote_description failed");

            let answer = wasm_bindgen_futures::JsFuture::from(pc_clone.create_answer())
                .await
                .expect("create_answer failed");

            let answer_sdp = Reflect::get(&answer, &"sdp".into())
                .expect("no sdp in answer")
                .as_string()
                .expect("sdp is not a string");

            let mut desc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
            desc.set_sdp(&answer_sdp);
            wasm_bindgen_futures::JsFuture::from(pc_clone.set_local_description(&desc))
                .await
                .expect("set_local_description failed");

            let _ = signaling_tx
                .send(SignalingEnvelope {
                    peer: peer_id,
                    msg: SignalingMsg::Answer {
                        session_id,
                        sdp: answer_sdp,
                    },
                })
                .await;
        });

        self.peers.insert(
            peer_id,
            PeerState {
                pc,
                data_channel: None, // Will be set via ondatachannel
                session_id,
                state: ConnectionState::Connecting,
                send_waker: None,
                pending_sends: Vec::new(),
                _closures: closures,
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

        let pc_clone = peer.pc.clone();
        let sdp_owned = sdp.to_string();
        wasm_bindgen_futures::spawn_local(async move {
            let mut desc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
            desc.set_sdp(&sdp_owned);
            wasm_bindgen_futures::JsFuture::from(pc_clone.set_remote_description(&desc))
                .await
                .expect("set_remote_description failed");
        });

        Ok(())
    }

    /// Handles an incoming ICE candidate from a remote peer.
    pub(crate) fn handle_ice_candidate(
        &mut self,
        peer_id: EndpointId,
        session_id: u64,
        candidate: &str,
        sdp_mid: Option<&str>,
    ) -> io::Result<()> {
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or_else(|| io::Error::other("no connection for ICE candidate"))?;

        if peer.session_id != session_id {
            return Err(io::Error::other("session_id mismatch"));
        }

        let mut init = RtcIceCandidateInit::new(&candidate);
        if let Some(mid) = sdp_mid {
            init.set_sdp_mid(Some(mid));
        }

        let pc_clone = peer.pc.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = wasm_bindgen_futures::JsFuture::from(
                pc_clone.add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init)),
            )
            .await;
        });

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
        if !self.peers.contains_key(&peer_id) {
            self.initiate(peer_id)?;
        }

        let peer = self.peers.get_mut(&peer_id).expect("just inserted");

        match peer.state {
            ConnectionState::Connected => {
                if let Some(channel) = &peer.data_channel {
                    channel
                        .send_with_u8_array(data)
                        .map_err(|e| io::Error::other(format!("DataChannel send failed: {e:?}")))?;
                    Ok(())
                } else {
                    Err(io::Error::other("connected but no DataChannel"))
                }
            }
            ConnectionState::Connecting => {
                peer.pending_sends.push(Bytes::copy_from_slice(data));
                peer.send_waker = Some(cx.waker().clone());
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            ConnectionState::Closed => {
                self.peers.remove(&peer_id);
                self.initiate(peer_id)?;
                let peer = self.peers.get_mut(&peer_id).expect("just inserted");
                peer.pending_sends.push(Bytes::copy_from_slice(data));
                peer.send_waker = Some(cx.waker().clone());
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        }
    }

    /// Polls for events. On browser this is a no-op since events arrive via callbacks.
    pub(crate) fn poll(&mut self, _cx: &mut Context) {
        // Browser WebRTC is event-driven via JS callbacks.
        // Events are delivered directly to the datagram_tx channel.
        // No manual polling needed.
    }
}
