//! WebRTC signaling protocol.
//!
//! Signaling messages are exchanged between peers via the relay transport to
//! establish WebRTC peer connections. Messages are tagged with a 4-byte magic
//! prefix (`WRTC`) so they can be distinguished from regular QUIC datagrams
//! in the relay stream.

use bytes::Bytes;
use iroh_base::EndpointId;
use serde::{Deserialize, Serialize};

/// Magic prefix for WebRTC signaling messages carried over relay datagrams.
///
/// ASCII for "WRTC" — used to demux signaling from regular QUIC traffic.
pub(crate) const SIGNALING_MAGIC: [u8; 4] = [0x57, 0x52, 0x54, 0x43];

/// A signaling message exchanged between peers to set up a WebRTC connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum SignalingMsg {
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

/// An envelope wrapping a signaling message with its source peer.
#[derive(Debug, Clone)]
pub(crate) struct SignalingEnvelope {
    /// The remote peer that sent (or should receive) this message.
    pub peer: EndpointId,
    /// The signaling message payload.
    pub msg: SignalingMsg,
}

/// Encodes a signaling message into a relay datagram payload.
///
/// Format: `[SIGNALING_MAGIC (4 bytes)][postcard-encoded message]`
pub(crate) fn encode(msg: &SignalingMsg) -> Bytes {
    let encoded =
        postcard::to_stdvec(msg).expect("signaling message serialization should not fail");
    let mut buf = Vec::with_capacity(SIGNALING_MAGIC.len() + encoded.len());
    buf.extend_from_slice(&SIGNALING_MAGIC);
    buf.extend_from_slice(&encoded);
    Bytes::from(buf)
}

/// Attempts to decode a signaling message from a relay datagram payload.
///
/// Returns `None` if the payload does not start with the signaling magic prefix
/// or if deserialization fails (in which case it's a regular QUIC datagram).
pub(crate) fn decode(data: &[u8]) -> Option<SignalingMsg> {
    if data.len() < SIGNALING_MAGIC.len() {
        return None;
    }
    if data[..SIGNALING_MAGIC.len()] != SIGNALING_MAGIC {
        return None;
    }
    postcard::from_bytes(&data[SIGNALING_MAGIC.len()..]).ok()
}

/// Returns `true` if the datagram payload starts with the signaling magic prefix.
pub(crate) fn is_signaling(data: &[u8]) -> bool {
    data.len() >= SIGNALING_MAGIC.len() && data[..SIGNALING_MAGIC.len()] == SIGNALING_MAGIC
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
        assert!(is_signaling(&encoded));
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
    fn test_non_signaling_data() {
        // Regular QUIC packets should not be detected as signaling
        let quic_data = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(!is_signaling(&quic_data));
        assert!(decode(&quic_data).is_none());
    }

    #[test]
    fn test_too_short() {
        assert!(!is_signaling(&[0x57, 0x52]));
        assert!(decode(&[0x57, 0x52]).is_none());
    }

    #[test]
    fn test_magic_but_invalid_payload() {
        // Magic prefix but garbage after it
        let mut data = SIGNALING_MAGIC.to_vec();
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        assert!(is_signaling(&data));
        assert!(decode(&data).is_none());
    }
}
