//! WebRTC signaling protocol types.
//!
//! A signaling message ([`SignalingMsg`]) carries SDP offers/answers and
//! trickled ICE candidates between two peers. An [`SignalingEnvelope`] pairs
//! a message with the remote peer it comes from or is destined to.
//!
//! Signaling transport is pluggable: the [`WebRtc`](crate::WebRtc) handle
//! exposes two mpsc endpoints (incoming + outgoing `SignalingEnvelope`) and
//! the user is free to ferry messages over any channel — iroh QUIC streams,
//! WebSocket, HTTP, anything bytes-in / bytes-out.
//!
//! The included [`iroh`] helper wires signaling to a dedicated ALPN on an
//! iroh [`Endpoint`](iroh::Endpoint).

#[cfg(feature = "iroh-signaling")]
pub mod iroh;

use bytes::Bytes;
use iroh_base::EndpointId;
use serde::{Deserialize, Serialize};

/// A signaling message exchanged between peers to set up a WebRTC connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignalingMsg {
    /// SDP offer from the initiating peer.
    Offer {
        /// Unique session identifier to correlate offer/answer pairs.
        session_id: u64,
        /// The SDP offer string.
        sdp: String,
    },
    /// SDP answer from the responding peer.
    Answer {
        /// Must match the session_id from the corresponding offer.
        session_id: u64,
        /// The SDP answer string.
        sdp: String,
    },
    /// A trickled ICE candidate.
    IceCandidate {
        /// Session this candidate belongs to.
        session_id: u64,
        /// The ICE candidate string (SDP format).
        candidate: String,
        /// The SDP media line identifier.
        sdp_mid: Option<String>,
    },
    /// Request to close an existing WebRTC session.
    Close {
        /// Session to close.
        session_id: u64,
    },
}

/// An envelope wrapping a signaling message with its source/destination peer.
#[derive(Debug, Clone)]
pub struct SignalingEnvelope {
    /// The remote peer that sent (or should receive) this message.
    pub peer: EndpointId,
    /// The signaling message payload.
    pub msg: SignalingMsg,
}

/// Encodes a signaling message as a postcard-serialized byte buffer.
///
/// Framing (e.g. length prefixing for stream transports) is up to the caller.
pub fn encode(msg: &SignalingMsg) -> Bytes {
    let encoded =
        postcard::to_stdvec(msg).expect("signaling message serialization should not fail");
    Bytes::from(encoded)
}

/// Attempts to decode a postcard-serialized signaling message.
pub fn decode(data: &[u8]) -> Option<SignalingMsg> {
    postcard::from_bytes(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_offer() {
        let msg = SignalingMsg::Offer {
            session_id: 42,
            sdp: "v=0\r\no=- 123 456 IN IP4 0.0.0.0\r\n".to_string(),
        };
        let encoded = encode(&msg);
        let decoded = decode(&encoded).expect("should decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_answer() {
        let msg = SignalingMsg::Answer {
            session_id: 42,
            sdp: "v=0\r\no=- 789 012 IN IP4 0.0.0.0\r\n".to_string(),
        };
        let encoded = encode(&msg);
        let decoded = decode(&encoded).expect("should decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_ice_candidate() {
        let msg = SignalingMsg::IceCandidate {
            session_id: 42,
            candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 50000 typ host".to_string(),
            sdp_mid: Some("0".to_string()),
        };
        let encoded = encode(&msg);
        let decoded = decode(&encoded).expect("should decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_close() {
        let msg = SignalingMsg::Close { session_id: 42 };
        let encoded = encode(&msg);
        let decoded = decode(&encoded).expect("should decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_decode_garbage() {
        assert!(decode(&[0xff, 0xff, 0xff, 0xff, 0xff]).is_none());
    }
}
