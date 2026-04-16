//! WebRTC address encoding as an iroh [`CustomAddr`].
//!
//! WebRTC addresses are tagged with [`WEBRTC_TRANSPORT_ID`] and carry the peer's
//! 32-byte public key verbatim, so an iroh endpoint can present a WebRTC path
//! in its [`EndpointAddr`](iroh_base::EndpointAddr) without any side table.

use std::io;

use iroh_base::{CustomAddr, EndpointId};

/// Transport ID for WebRTC, registered in `TRANSPORTS.md`.
///
/// ASCII for "WRT" = `0x575254`.
pub const WEBRTC_TRANSPORT_ID: u64 = 0x575254;

/// Converts an [`EndpointId`] into a WebRTC [`CustomAddr`].
pub fn to_custom_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from((WEBRTC_TRANSPORT_ID, &endpoint.as_bytes()[..]))
}

/// Parses an [`EndpointId`] from a WebRTC [`CustomAddr`].
pub(crate) fn parse_endpoint_id(addr: &CustomAddr) -> io::Result<EndpointId> {
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
        let addr = CustomAddr::from((WEBRTC_TRANSPORT_ID, &[0u8; 16][..]));
        let err = parse_endpoint_id(&addr).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
