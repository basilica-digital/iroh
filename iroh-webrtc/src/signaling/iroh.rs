//! Bridge iroh-webrtc's signaling mpsc endpoints to a dedicated ALPN over an
//! iroh [`Endpoint`](iroh::Endpoint).
//!
//! # Usage
//!
//! Outbound messages (WebRTC transport → peer) are delivered automatically by
//! a background task spawned in [`IrohSignaling::spawn`]. Inbound connections
//! (peer → WebRTC transport) cannot be claimed transparently because iroh's
//! [`Endpoint::accept`](iroh::Endpoint::accept) is single-consumer, so the
//! user's accept loop must dispatch signaling connections to us:
//!
//! ```ignore
//! while let Some(incoming) = endpoint.accept().await {
//!     let conn = incoming.await?;
//!     if conn.alpn() == iroh_webrtc::SIGNALING_ALPN {
//!         signaling.handle_incoming(conn);
//!         continue;
//!     }
//!     // ... handle user ALPNs ...
//! }
//! ```

use std::{collections::HashMap, sync::Arc};

use iroh::{
    Endpoint,
    endpoint::{Connection, HandshakeCompleted},
};
use iroh_base::{EndpointAddr, EndpointId};
use n0_future::task::{self, AbortHandle, JoinHandle};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, trace, warn};

use crate::signaling::{SignalingEnvelope, SignalingMsg, decode, encode};

/// ALPN bytes for the iroh-webrtc signaling protocol.
pub const SIGNALING_ALPN: &[u8] = b"iroh-webrtc/signaling/0";

/// Maximum length of a single signaling frame on the wire. Frames larger than
/// this are rejected to contain the blast radius of a garbage or hostile peer.
const MAX_FRAME_BYTES: u32 = 64 * 1024;

/// Handle to the iroh-based signaling runtime.
///
/// Dropping this handle cancels the dispatch task and all live per-peer
/// reader/writer tasks.
#[derive(Debug)]
pub struct IrohSignaling {
    inner: Arc<Inner>,
    _dispatch_handle: JoinHandle<()>,
}

#[derive(Debug)]
struct Inner {
    endpoint: Endpoint,
    /// Forwards decoded inbound signaling into the WebRTC transport.
    to_transport: mpsc::Sender<SignalingEnvelope>,
    /// Per-peer writers. Each entry holds a `Sender<SignalingMsg>` that feeds
    /// the peer's outbound stream writer task.
    peers: Mutex<HashMap<EndpointId, PeerState>>,
    my_id: EndpointId,
}

#[derive(Debug)]
struct PeerState {
    /// Outbound mpsc feeding the writer task.
    send: mpsc::Sender<SignalingMsg>,
    /// Aborted when the peer state is dropped/replaced.
    reader: AbortHandle,
    writer: AbortHandle,
    /// Keeps the signaling connection alive while reader/writer run.
    _conn: Connection<HandshakeCompleted>,
}

impl Drop for PeerState {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

impl IrohSignaling {
    /// Spawns the dispatch task that drains `outgoing_rx` (outbound signaling
    /// from the WebRTC transport) and routes each envelope to the peer over a
    /// dedicated ALPN connection.
    ///
    /// `to_transport_tx` is the side that forwards inbound signaling *into*
    /// the WebRTC transport — the dispatch task clones it for every reader.
    pub fn spawn(
        endpoint: Endpoint,
        mut outgoing_rx: mpsc::Receiver<SignalingEnvelope>,
        to_transport_tx: mpsc::Sender<SignalingEnvelope>,
    ) -> Self {
        let my_id = endpoint.id();
        let inner = Arc::new(Inner {
            endpoint,
            to_transport: to_transport_tx,
            peers: Mutex::new(HashMap::new()),
            my_id,
        });

        let dispatch_inner = inner.clone();
        let dispatch_handle = task::spawn(async move {
            while let Some(env) = outgoing_rx.recv().await {
                if let Err(e) = dispatch_inner.send_outbound(env).await {
                    warn!("iroh-webrtc signaling dispatch failed: {e:#}");
                }
            }
            debug!("iroh-webrtc signaling dispatch exiting");
        });

        Self {
            inner,
            _dispatch_handle: dispatch_handle,
        }
    }

    /// Handles an incoming iroh connection whose ALPN matches
    /// [`SIGNALING_ALPN`]. The caller has already resolved the connection
    /// past the handshake so we can read its remote id and accept streams.
    ///
    /// This spawns a reader (decoding inbound frames → WebRTC transport) and a
    /// writer (draining outbound queue → frames on the stream). If a previous
    /// connection for the same peer exists, it is aborted and replaced — see
    /// [`Self::handle_new_peer_conn`].
    pub fn handle_incoming(&self, conn: Connection<HandshakeCompleted>) {
        let inner = self.inner.clone();
        task::spawn(async move {
            let peer = conn.remote_id();
            if let Err(e) = inner.handle_new_peer_conn(peer, conn, false).await {
                warn!(peer = %peer.fmt_short(), "signaling incoming setup failed: {e:#}");
            }
        });
    }
}

impl Inner {
    /// Resolves the outbound channel for `env.peer` (dialing a new connection
    /// if needed) and queues the message.
    async fn send_outbound(self: &Arc<Self>, env: SignalingEnvelope) -> std::io::Result<()> {
        let sender = {
            let peers = self.peers.lock().await;
            peers.get(&env.peer).map(|p| p.send.clone())
        };

        let sender = match sender {
            Some(s) => s,
            None => self.dial_and_register(env.peer).await?,
        };

        // Single try_send. On Closed (peer state evicted), drop it and redial
        // once. On Full, drop the frame with a warning.
        match sender.try_send(env.msg) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Closed(msg)) => {
                debug!(peer = %env.peer.fmt_short(), "signaling writer channel closed; redialing");
                self.peers.lock().await.remove(&env.peer);
                let fresh = self.dial_and_register(env.peer).await?;
                let _ = fresh.send(msg).await;
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(peer = %env.peer.fmt_short(), "signaling outbound queue full; dropping");
            }
        }

        Ok(())
    }

    async fn dial_and_register(
        self: &Arc<Self>,
        peer: EndpointId,
    ) -> std::io::Result<mpsc::Sender<SignalingMsg>> {
        // Glare tiebreak: if the peer is sorted higher than us, they are
        // expected to dial. We still try ourselves as a fallback but prefer an
        // existing inbound if one appears first.
        let conn = self
            .endpoint
            .connect(EndpointAddr::from(peer), SIGNALING_ALPN)
            .await
            .map_err(|e| std::io::Error::other(format!("signaling connect: {e}")))?;
        let sender = self
            .handle_new_peer_conn(peer, conn, true)
            .await
            .map_err(|e| std::io::Error::other(format!("signaling register: {e}")))?;
        Ok(sender)
    }

    /// Installs reader+writer tasks for `conn` and stores the entry in
    /// `self.peers`, aborting any previous entry for this peer.
    ///
    /// When `outbound == true`, we opened the connection; otherwise it was
    /// inbound. Glare handling: if both sides dial, the lower-`EndpointId`
    /// side's entry wins (its connection is kept; the other is dropped).
    async fn handle_new_peer_conn(
        self: &Arc<Self>,
        peer: EndpointId,
        conn: Connection<HandshakeCompleted>,
        outbound: bool,
    ) -> std::io::Result<mpsc::Sender<SignalingMsg>> {
        let (send, recv) = if outbound {
            conn.open_bi()
                .await
                .map_err(|e| std::io::Error::other(format!("open_bi: {e}")))?
        } else {
            conn.accept_bi()
                .await
                .map_err(|e| std::io::Error::other(format!("accept_bi: {e}")))?
        };
        let keep_conn = conn.clone();

        let (out_tx, out_rx) = mpsc::channel::<SignalingMsg>(64);

        let writer_inner = self.clone();
        let writer_peer = peer;
        let writer = task::spawn(async move {
            writer_loop(writer_inner, writer_peer, send, out_rx).await;
        })
        .abort_handle();

        let reader_inner = self.clone();
        let reader_peer = peer;
        let reader = task::spawn(async move {
            reader_loop(reader_inner, reader_peer, recv).await;
        })
        .abort_handle();

        let mut peers = self.peers.lock().await;
        let keep_new = match peers.get(&peer) {
            None => true,
            Some(_) => {
                // Glare: an entry already exists. Lower-id side wins.
                // If the NEW connection is inbound and we are the lower id,
                // or the new is outbound and we are the higher id, we replace.
                // Simpler rule consistent with PeerConnectionManager tiebreak:
                // the lower-id side keeps the inbound connection (they accept).
                // Inbound replaces when `my_id < peer`. Outbound replaces when
                // `my_id > peer`.
                let i_am_lower = self.my_id.as_bytes() < peer.as_bytes();
                if outbound { !i_am_lower } else { i_am_lower }
            }
        };

        if keep_new {
            trace!(peer = %peer.fmt_short(), outbound, "installing signaling peer entry");
            peers.insert(
                peer,
                PeerState {
                    send: out_tx.clone(),
                    reader,
                    writer,
                    _conn: keep_conn,
                },
            );
        } else {
            trace!(peer = %peer.fmt_short(), outbound, "dropping duplicate signaling connection");
            reader.abort();
            writer.abort();
        }

        Ok(out_tx)
    }
}

/// Drains `out_rx` and writes length-prefixed encoded frames to `send`.
async fn writer_loop(
    _inner: Arc<Inner>,
    peer: EndpointId,
    mut send: iroh::endpoint::SendStream,
    mut out_rx: mpsc::Receiver<SignalingMsg>,
) {
    while let Some(msg) = out_rx.recv().await {
        let body = encode(&msg);
        let len = body.len() as u32;
        if len > MAX_FRAME_BYTES {
            warn!(peer = %peer.fmt_short(), "signaling frame too large, dropping");
            continue;
        }
        if let Err(e) = send.write_all(&len.to_be_bytes()).await {
            warn!(peer = %peer.fmt_short(), "signaling write length failed: {e}");
            break;
        }
        if let Err(e) = send.write_all(&body).await {
            warn!(peer = %peer.fmt_short(), "signaling write body failed: {e}");
            break;
        }
    }
    let _ = send.finish();
    trace!(peer = %peer.fmt_short(), "signaling writer exiting");
}

/// Reads length-prefixed frames from `recv` and forwards decoded messages to
/// the WebRTC transport's incoming channel.
async fn reader_loop(inner: Arc<Inner>, peer: EndpointId, mut recv: iroh::endpoint::RecvStream) {
    let mut len_buf = [0u8; 4];
    loop {
        if let Err(e) = recv.read_exact(&mut len_buf).await {
            debug!(peer = %peer.fmt_short(), "signaling read length ended: {e}");
            break;
        }
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_BYTES {
            warn!(peer = %peer.fmt_short(), "signaling frame oversize ({len}), closing");
            break;
        }
        let mut body = vec![0u8; len as usize];
        if let Err(e) = recv.read_exact(&mut body).await {
            warn!(peer = %peer.fmt_short(), "signaling read body failed: {e}");
            break;
        }
        let Some(msg) = decode(&body) else {
            warn!(peer = %peer.fmt_short(), "signaling frame decode failed");
            continue;
        };
        if let Err(e) = inner
            .to_transport
            .send(SignalingEnvelope { peer, msg })
            .await
        {
            debug!(peer = %peer.fmt_short(), "signaling forward to transport failed: {e}");
            break;
        }
    }
    // Evict on stream close.
    let mut peers = inner.peers.lock().await;
    peers.remove(&peer);
    trace!(peer = %peer.fmt_short(), "signaling reader exiting");
}
