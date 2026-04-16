//! Browser WebRTC peer connection management using `web-sys`.
//!
//! Uses the browser's native `RTCPeerConnection` API through `web-sys` bindings.
//! All JavaScript callbacks push events to Rust channels for poll-based integration.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    io,
    rc::Rc,
    task::{Context, Poll, Waker},
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

// -----------------------------------------------------------------------------
// Diagnostic event log
//
// The browser's devtools console is not easily accessible on mobile (iOS in
// particular), so we keep an in-memory ring buffer of WebRTC signaling and ICE
// events that can be retrieved as a single `String` via
// [`webrtc_debug_snapshot`] and copy-pasted out of the page. Entries are
// prefixed with a millisecond timestamp so relative timing between events
// (e.g. how long ICE stayed in `checking`) is visible.
// -----------------------------------------------------------------------------

/// Maximum number of diagnostic entries to keep in memory.
const DEBUG_LOG_MAX_ENTRIES: usize = 1024;

thread_local! {
    static DEBUG_LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Records a diagnostic event into the in-memory log.
fn debug_record(msg: impl Into<String>) {
    let ts = js_sys::Date::now();
    let entry = format!("[{ts:.0}] {}", msg.into());
    DEBUG_LOG.with(|log| {
        let mut log = log.borrow_mut();
        if log.len() >= DEBUG_LOG_MAX_ENTRIES {
            log.remove(0);
        }
        log.push(entry);
    });
}

/// Returns the current WebRTC diagnostic log as a newline-joined string.
///
/// Use this from the browser example or other wasm code to expose the log to
/// JavaScript for copy-paste debugging. Entries are timestamped with
/// `Date.now()` milliseconds.
pub fn webrtc_debug_snapshot() -> String {
    DEBUG_LOG.with(|log| log.borrow().join("\n"))
}

/// Clears the in-memory WebRTC diagnostic log.
pub fn webrtc_debug_clear() {
    DEBUG_LOG.with(|log| log.borrow_mut().clear());
}

/// Counts `a=candidate:...typ <kind>` lines in a raw SDP blob, returning
/// a short human-readable summary like `host=1 srflx=1 relay=0 prflx=0 total=2`.
///
/// This is purely observational — we do not parse or modify the SDP.
fn summarize_sdp_candidates(sdp: &str) -> String {
    let mut host = 0;
    let mut srflx = 0;
    let mut relay = 0;
    let mut prflx = 0;
    let mut total = 0;
    for line in sdp.lines() {
        let Some(rest) = line.strip_prefix("a=candidate:") else {
            continue;
        };
        total += 1;
        if rest.contains(" typ host") {
            host += 1;
        } else if rest.contains(" typ srflx") {
            srflx += 1;
        } else if rest.contains(" typ relay") {
            relay += 1;
        } else if rest.contains(" typ prflx") {
            prflx += 1;
        }
    }
    format!("host={host} srflx={srflx} relay={relay} prflx={prflx} total={total}")
}

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
    /// Set directly for the offerer, or via [`remote_channel`] for the answerer.
    data_channel: Option<RtcDataChannel>,
    /// Shared storage for the DataChannel received via `ondatachannel` (answerer side).
    /// The JS callback writes here; [`poll()`] reads and moves it to [`data_channel`].
    remote_channel: Rc<RefCell<Option<RtcDataChannel>>>,
    /// Unique session identifier for correlating signaling.
    session_id: u64,
    /// Current connection state.
    state: ConnectionState,
    /// Waker to notify when the connection becomes ready.
    send_waker: Option<Waker>,
    /// Datagrams queued while the connection is being established.
    pending_sends: Vec<Bytes>,
    /// Channel receiving events from JS callbacks (ICE state changes, DataChannel open/close).
    event_rx: mpsc::Receiver<PeerEvent>,
    /// Whether `setRemoteDescription` has completed on this peer connection.
    /// Shared with the async block that applies the remote description.
    remote_desc_set: Rc<Cell<bool>>,
    /// ICE candidates buffered while waiting for `setRemoteDescription` to complete.
    /// `addIceCandidate()` fails if called before the remote description is set,
    /// so we queue candidates here and flush them once the description is applied.
    /// Shared with the async block that applies the remote description.
    pending_remote_candidates: Rc<RefCell<Vec<(String, Option<String>)>>>,
    /// Closures we need to keep alive for the JS callbacks.
    _closures: Vec<Closure<dyn FnMut(JsValue)>>,
}

impl std::fmt::Debug for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerState")
            .field("session_id", &self.session_id)
            .field("state", &self.state)
            .field("pending_sends", &self.pending_sends.len())
            .finish_non_exhaustive()
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
    ///
    /// Returns the peer connection, an event sender (for wiring up additional
    /// callbacks like DataChannel events), the event receiver, and closures
    /// that must be kept alive.
    fn create_peer_connection(
        &self,
        peer_id: EndpointId,
        session_id: u64,
    ) -> io::Result<(
        RtcPeerConnection,
        mpsc::Sender<PeerEvent>,
        mpsc::Receiver<PeerEvent>,
        Rc<RefCell<Option<RtcDataChannel>>>,
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
        let peer_short_ice = peer_id.fmt_short().to_string();
        let on_ice_candidate = Closure::wrap(Box::new(move |event: JsValue| {
            let event: RtcPeerConnectionIceEvent = event.unchecked_into();
            if let Some(candidate) = event.candidate() {
                let candidate_str = candidate.candidate();
                if !candidate_str.is_empty() {
                    debug_record(format!(
                        "[{peer_short_ice}] local ICE candidate (trickling): {candidate_str}"
                    ));
                    if let Err(e) = signaling_tx.try_send(SignalingEnvelope {
                        peer: pid,
                        msg: SignalingMsg::IceCandidate {
                            session_id: sid,
                            candidate: candidate_str.clone(),
                            sdp_mid: candidate.sdp_mid(),
                        },
                    }) {
                        warn!("failed to send local ICE candidate via signaling: {e}");
                        debug_record(format!(
                            "[{peer_short_ice}] FAILED to enqueue local ICE candidate: {e}"
                        ));
                    }
                }
            } else {
                debug_record(format!(
                    "[{peer_short_ice}] local ICE gathering complete (null candidate)"
                ));
            }
        }) as Box<dyn FnMut(JsValue)>);
        pc.set_onicecandidate(Some(on_ice_candidate.as_ref().unchecked_ref()));
        closures.push(on_ice_candidate);

        // oniceconnectionstatechange
        let pc_clone = pc.clone();
        let event_tx_clone = event_tx.clone();
        let peer_short_state = peer_id.fmt_short().to_string();
        let on_ice_state = Closure::wrap(Box::new(move |_: JsValue| {
            let state = pc_clone.ice_connection_state();
            let state_str = format!("{:?}", state);
            debug_record(format!(
                "[{peer_short_state}] ICE connection state -> {state_str}"
            ));
            let _ = event_tx_clone.try_send(PeerEvent::IceConnectionStateChange(state_str));
        }) as Box<dyn FnMut(JsValue)>);
        pc.set_oniceconnectionstatechange(Some(on_ice_state.as_ref().unchecked_ref()));
        closures.push(on_ice_state);

        // Shared storage for the answerer's DataChannel (set by ondatachannel callback,
        // read by poll() to move into PeerState.data_channel).
        let remote_channel: Rc<RefCell<Option<RtcDataChannel>>> = Rc::new(RefCell::new(None));

        // ondatachannel (for the answerer — the offerer creates the channel directly)
        let datagram_tx = self.datagram_tx.clone();
        let event_tx_clone = event_tx.clone();
        let pid = peer_id;
        let dc_ref = remote_channel.clone();
        let peer_short_dc = peer_id.fmt_short().to_string();
        let on_datachannel = Closure::wrap(Box::new(move |event: JsValue| {
            let event: RtcDataChannelEvent = event.unchecked_into();
            let channel = event.channel();
            channel.set_binary_type(RtcDataChannelType::Arraybuffer);
            debug_record(format!(
                "[{peer_short_dc}] ondatachannel fired (answerer received DataChannel)"
            ));

            // Store channel reference so PeerState can pick it up in poll().
            *dc_ref.borrow_mut() = Some(channel.clone());

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

            let etx2 = event_tx_clone.clone();
            let on_close = Closure::wrap(Box::new(move |_: JsValue| {
                let _ = etx2.try_send(PeerEvent::DataChannelClose);
            }) as Box<dyn FnMut(JsValue)>);
            channel.set_onclose(Some(on_close.as_ref().unchecked_ref()));
            on_close.forget();
        }) as Box<dyn FnMut(JsValue)>);
        pc.set_ondatachannel(Some(on_datachannel.as_ref().unchecked_ref()));
        closures.push(on_datachannel);

        Ok((pc, event_tx, event_rx, remote_channel, closures))
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
        let (pc, event_tx, event_rx, remote_channel, mut closures) =
            self.create_peer_connection(peer_id, session_id)?;

        // Create DataChannel (as offerer)
        let mut dc_init = RtcDataChannelInit::new();
        dc_init.set_ordered(false);
        dc_init.set_max_retransmits(0);

        let channel = pc.create_data_channel_with_data_channel_dict(DATA_CHANNEL_LABEL, &dc_init);
        let dc_closures = self.setup_data_channel_events(&channel, peer_id, &event_tx);
        closures.extend(dc_closures);

        debug_record(format!(
            "[{peer}] initiate (browser offerer) session={session_id}",
            peer = peer_id.fmt_short()
        ));

        // Spawn async task to create offer
        let signaling_tx = self.signaling_tx.clone();
        let pc_clone = pc.clone();
        let peer_short = peer_id.fmt_short().to_string();
        wasm_bindgen_futures::spawn_local(async move {
            let offer = match wasm_bindgen_futures::JsFuture::from(pc_clone.create_offer()).await {
                Ok(o) => o,
                Err(e) => {
                    warn!(?e, "create_offer failed");
                    debug_record(format!("[{peer_short}] create_offer FAILED: {e:?}"));
                    return;
                }
            };

            let offer_sdp = match Reflect::get(&offer, &"sdp".into())
                .ok()
                .and_then(|v| v.as_string())
            {
                Some(sdp) => sdp,
                None => {
                    warn!("offer missing sdp string");
                    debug_record(format!("[{peer_short}] offer missing sdp string"));
                    return;
                }
            };

            debug_record(format!(
                "[{peer_short}] created offer: {len} bytes, candidates: {summary}",
                len = offer_sdp.len(),
                summary = summarize_sdp_candidates(&offer_sdp)
            ));

            let mut desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
            desc.set_sdp(&offer_sdp);
            if let Err(e) =
                wasm_bindgen_futures::JsFuture::from(pc_clone.set_local_description(&desc)).await
            {
                warn!(?e, "set_local_description failed for offer");
                debug_record(format!(
                    "[{peer_short}] setLocalDescription(offer) FAILED: {e:?}"
                ));
                return;
            }
            debug_record(format!("[{peer_short}] setLocalDescription(offer) OK"));

            let _ = signaling_tx
                .send(SignalingEnvelope {
                    peer: peer_id,
                    msg: SignalingMsg::Offer {
                        session_id,
                        sdp: offer_sdp,
                    },
                })
                .await;
            debug_record(format!("[{peer_short}] sent offer via signaling"));
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
                remote_channel,
                session_id,
                state: ConnectionState::Connecting,
                send_waker: None,
                pending_sends: Vec::new(),
                event_rx,
                remote_desc_set: Rc::new(Cell::new(false)),
                pending_remote_candidates: Rc::new(RefCell::new(Vec::new())),
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

        let (pc, _event_tx, event_rx, remote_channel, closures) =
            self.create_peer_connection(peer_id, session_id)?;

        debug_record(format!(
            "[{peer}] received OFFER (browser answerer): {len} bytes, candidates: {summary}",
            peer = peer_id.fmt_short(),
            len = sdp.len(),
            summary = summarize_sdp_candidates(sdp)
        ));

        // Set remote description (offer) and create answer.
        // ICE candidates arriving before setRemoteDescription completes are
        // buffered in pending_remote_candidates and flushed here.
        let sdp_owned = sdp.to_string();
        let signaling_tx = self.signaling_tx.clone();
        let pc_clone = pc.clone();
        let remote_desc_set = Rc::new(Cell::new(false));
        let pending_remote_candidates: Rc<RefCell<Vec<(String, Option<String>)>>> =
            Rc::new(RefCell::new(Vec::new()));
        let rds = remote_desc_set.clone();
        let prc = pending_remote_candidates.clone();
        let peer_short = peer_id.fmt_short().to_string();
        wasm_bindgen_futures::spawn_local(async move {
            let mut offer_desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
            offer_desc.set_sdp(&sdp_owned);
            if let Err(e) =
                wasm_bindgen_futures::JsFuture::from(pc_clone.set_remote_description(&offer_desc))
                    .await
            {
                warn!(?e, "set_remote_description failed for offer");
                debug_record(format!(
                    "[{peer_short}] setRemoteDescription(offer) FAILED: {e:?}"
                ));
                return;
            }
            debug_record(format!("[{peer_short}] setRemoteDescription(offer) OK"));

            // Remote description is now set — flush any buffered ICE candidates.
            rds.set(true);
            let buffered: Vec<_> = prc.borrow_mut().drain(..).collect();
            if !buffered.is_empty() {
                debug!(
                    count = buffered.len(),
                    "flushing buffered ICE candidates after setRemoteDescription (answerer)"
                );
                debug_record(format!(
                    "[{peer_short}] flushing {n} buffered remote ICE candidates (answerer)",
                    n = buffered.len()
                ));
            }
            for (candidate, sdp_mid) in buffered {
                let mut init = RtcIceCandidateInit::new(&candidate);
                if let Some(mid) = &sdp_mid {
                    init.set_sdp_mid(Some(mid));
                }
                match wasm_bindgen_futures::JsFuture::from(
                    pc_clone.add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init)),
                )
                .await
                {
                    Ok(_) => {
                        debug!(%candidate, "addIceCandidate succeeded (buffered, answerer)");
                        debug_record(format!(
                            "[{peer_short}] addIceCandidate OK (buffered): {candidate}"
                        ));
                    }
                    Err(e) => {
                        warn!(%candidate, ?e, "addIceCandidate failed for buffered candidate");
                        debug_record(format!(
                            "[{peer_short}] addIceCandidate FAILED (buffered): {candidate} err={e:?}"
                        ));
                    }
                }
            }

            let answer = match wasm_bindgen_futures::JsFuture::from(pc_clone.create_answer()).await
            {
                Ok(a) => a,
                Err(e) => {
                    warn!(?e, "create_answer failed");
                    debug_record(format!("[{peer_short}] create_answer FAILED: {e:?}"));
                    return;
                }
            };

            let answer_sdp = match Reflect::get(&answer, &"sdp".into())
                .ok()
                .and_then(|v| v.as_string())
            {
                Some(sdp) => sdp,
                None => {
                    warn!("answer missing sdp string");
                    debug_record(format!("[{peer_short}] answer missing sdp string"));
                    return;
                }
            };

            debug_record(format!(
                "[{peer_short}] created answer: {len} bytes, candidates: {summary}",
                len = answer_sdp.len(),
                summary = summarize_sdp_candidates(&answer_sdp)
            ));

            let mut desc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
            desc.set_sdp(&answer_sdp);
            if let Err(e) =
                wasm_bindgen_futures::JsFuture::from(pc_clone.set_local_description(&desc)).await
            {
                warn!(?e, "set_local_description failed for answer");
                debug_record(format!(
                    "[{peer_short}] setLocalDescription(answer) FAILED: {e:?}"
                ));
                return;
            }
            debug_record(format!("[{peer_short}] setLocalDescription(answer) OK"));

            let _ = signaling_tx
                .send(SignalingEnvelope {
                    peer: peer_id,
                    msg: SignalingMsg::Answer {
                        session_id,
                        sdp: answer_sdp,
                    },
                })
                .await;
            debug_record(format!("[{peer_short}] sent answer via signaling"));
        });

        self.peers.insert(
            peer_id,
            PeerState {
                pc,
                data_channel: None, // Will be set via ondatachannel → remote_channel → poll()
                remote_channel,
                session_id,
                state: ConnectionState::Connecting,
                send_waker: None,
                pending_sends: Vec::new(),
                event_rx,
                remote_desc_set,
                pending_remote_candidates,
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

        debug_record(format!(
            "[{peer}] received ANSWER (browser offerer): {len} bytes, candidates: {summary}",
            peer = peer_id.fmt_short(),
            len = sdp.len(),
            summary = summarize_sdp_candidates(sdp)
        ));

        let pc_clone = peer.pc.clone();
        let sdp_owned = sdp.to_string();
        let rds = peer.remote_desc_set.clone();
        let prc = peer.pending_remote_candidates.clone();
        let peer_short = peer_id.fmt_short().to_string();
        wasm_bindgen_futures::spawn_local(async move {
            let mut desc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
            desc.set_sdp(&sdp_owned);
            if let Err(e) =
                wasm_bindgen_futures::JsFuture::from(pc_clone.set_remote_description(&desc)).await
            {
                warn!(?e, "set_remote_description failed for answer");
                debug_record(format!(
                    "[{peer_short}] setRemoteDescription(answer) FAILED: {e:?}"
                ));
                return;
            }
            debug_record(format!("[{peer_short}] setRemoteDescription(answer) OK"));

            // Remote description is now set — flush any buffered ICE candidates.
            rds.set(true);
            let buffered: Vec<_> = prc.borrow_mut().drain(..).collect();
            if !buffered.is_empty() {
                debug!(
                    count = buffered.len(),
                    "flushing buffered ICE candidates after setRemoteDescription (offerer)"
                );
                debug_record(format!(
                    "[{peer_short}] flushing {n} buffered remote ICE candidates (offerer)",
                    n = buffered.len()
                ));
            }
            for (candidate, sdp_mid) in buffered {
                let mut init = RtcIceCandidateInit::new(&candidate);
                if let Some(mid) = &sdp_mid {
                    init.set_sdp_mid(Some(mid));
                }
                match wasm_bindgen_futures::JsFuture::from(
                    pc_clone.add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init)),
                )
                .await
                {
                    Ok(_) => {
                        debug!(%candidate, "addIceCandidate succeeded (buffered, offerer)");
                        debug_record(format!(
                            "[{peer_short}] addIceCandidate OK (buffered): {candidate}"
                        ));
                    }
                    Err(e) => {
                        warn!(%candidate, ?e, "addIceCandidate failed for buffered candidate");
                        debug_record(format!(
                            "[{peer_short}] addIceCandidate FAILED (buffered): {candidate} err={e:?}"
                        ));
                    }
                }
            }
        });

        Ok(())
    }

    /// Handles an incoming ICE candidate from a remote peer.
    ///
    /// If `setRemoteDescription` hasn't completed yet, the candidate is buffered
    /// and will be added once the remote description is applied. Calling
    /// `addIceCandidate` before the remote description is set would fail with
    /// `InvalidStateError`.
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

        // Buffer the candidate if remote description hasn't been applied yet.
        // The setRemoteDescription async block will flush these.
        if !peer.remote_desc_set.get() {
            debug!(
                peer = %peer_id.fmt_short(),
                %candidate,
                "buffering ICE candidate (remote description not yet set)"
            );
            debug_record(format!(
                "[{peer}] BUFFERING remote ICE candidate (srd not done): {candidate}",
                peer = peer_id.fmt_short()
            ));
            peer.pending_remote_candidates
                .borrow_mut()
                .push((candidate.to_string(), sdp_mid.map(|s| s.to_string())));
            return Ok(());
        }

        debug_record(format!(
            "[{peer}] received remote ICE candidate: {candidate}",
            peer = peer_id.fmt_short()
        ));

        let candidate_owned = candidate.to_string();
        let mut init = RtcIceCandidateInit::new(candidate);
        if let Some(mid) = sdp_mid {
            init.set_sdp_mid(Some(mid));
        }

        let pc_clone = peer.pc.clone();
        let peer_short = peer_id.fmt_short().to_string();
        wasm_bindgen_futures::spawn_local(async move {
            match wasm_bindgen_futures::JsFuture::from(
                pc_clone.add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init)),
            )
            .await
            {
                Ok(_) => {
                    debug_record(format!(
                        "[{peer_short}] addIceCandidate OK: {candidate_owned}"
                    ));
                }
                Err(e) => {
                    warn!(
                        candidate = %candidate_owned,
                        ?e,
                        "addIceCandidate failed"
                    );
                    debug_record(format!(
                        "[{peer_short}] addIceCandidate FAILED: {candidate_owned} err={e:?}"
                    ));
                }
            }
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
                debug_record(format!(
                    "[{peer}] received CLOSE signal (session={session_id})",
                    peer = peer_id.fmt_short()
                ));
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

    /// Polls for events from JS callbacks and updates peer connection states.
    ///
    /// JS callbacks push events into per-peer channels. This method drains
    /// those channels and transitions `ConnectionState` accordingly.
    /// Using `poll_recv(cx)` registers the waker so the task is woken
    /// immediately when JS callbacks fire (e.g. DataChannelOpen), rather
    /// than waiting for unrelated activity to trigger a poll cycle.
    pub(crate) fn poll(&mut self, cx: &mut Context) {
        let peer_ids: Vec<EndpointId> = self.peers.keys().copied().collect();
        for peer_id in peer_ids {
            let Some(peer) = self.peers.get_mut(&peer_id) else {
                continue;
            };

            // Drain all pending events for this peer.
            loop {
                match peer.event_rx.poll_recv(cx) {
                    Poll::Ready(Some(event)) => match event {
                        PeerEvent::DataChannelOpen => {
                            debug!(
                                peer = %peer_id.fmt_short(),
                                session_id = peer.session_id,
                                "DataChannel opened"
                            );
                            debug_record(format!(
                                "[{peer}] DataChannel OPEN — connection is live",
                                peer = peer_id.fmt_short()
                            ));
                            peer.state = ConnectionState::Connected;

                            // On the answerer side, the DataChannel arrives via
                            // the ondatachannel JS callback which stores it in
                            // remote_channel. Move it into data_channel now.
                            if peer.data_channel.is_none() {
                                peer.data_channel = peer.remote_channel.borrow_mut().take();
                            }

                            // Flush pending sends.
                            if let Some(channel) = &peer.data_channel {
                                for data in peer.pending_sends.drain(..) {
                                    if let Err(e) = channel.send_with_u8_array(&data) {
                                        warn!(
                                            peer = %peer_id.fmt_short(),
                                            "failed to flush pending send: {e:?}"
                                        );
                                    }
                                }
                            }

                            // Wake the send task so QUIC retries on this path.
                            if let Some(waker) = peer.send_waker.take() {
                                waker.wake();
                            }
                        }
                        PeerEvent::DataChannelClose => {
                            debug!(
                                peer = %peer_id.fmt_short(),
                                "DataChannel closed"
                            );
                            peer.state = ConnectionState::Closed;
                        }
                        PeerEvent::DataChannelMessage(data) => {
                            // Forward to the datagram channel.
                            let _ = self.datagram_tx.try_send((peer_id, data));
                        }
                        PeerEvent::IceConnectionStateChange(state_str) => {
                            debug!(
                                peer = %peer_id.fmt_short(),
                                state = %state_str,
                                "ICE connection state changed"
                            );
                            if state_str.contains("failed") || state_str.contains("disconnected") {
                                peer.state = ConnectionState::Closed;
                            }
                        }
                        PeerEvent::IceCandidate { .. } | PeerEvent::IceGatheringComplete => {
                            // ICE candidates are sent directly from the JS callback.
                        }
                    },
                    Poll::Ready(None) => {
                        peer.state = ConnectionState::Closed;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }
    }
}
