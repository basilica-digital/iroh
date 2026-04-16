//! Minimal STUN Binding Request/Response implementation for server-reflexive
//! candidate gathering.
//!
//! This implements only the subset of RFC 5389 needed to query a public STUN
//! server for our mapped (public) address. We can't use str0m's built-in STUN
//! parser because it requires MESSAGE-INTEGRITY, which public STUN servers
//! don't include in their responses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// STUN magic cookie (RFC 5389 §6).
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// STUN Binding Request type (RFC 5389 §6).
const BINDING_REQUEST_TYPE: [u8; 2] = [0x00, 0x01];

/// STUN Binding Success Response type (RFC 5389 §6).
const BINDING_SUCCESS_TYPE: [u8; 2] = [0x01, 0x01];

/// XOR-MAPPED-ADDRESS attribute type (RFC 5389 §15.2).
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// MAPPED-ADDRESS attribute type (RFC 5389 §15.1).
/// Fallback for older servers that don't send XOR-MAPPED-ADDRESS.
const MAPPED_ADDRESS: u16 = 0x0001;

/// Minimum STUN header size.
const HEADER_SIZE: usize = 20;

/// Builds a STUN Binding Request packet.
///
/// The request is a bare 20-byte header with no attributes — sufficient for
/// querying a public STUN server.
pub(crate) fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE);
    buf.extend_from_slice(&BINDING_REQUEST_TYPE);
    buf.extend_from_slice(&[0x00, 0x00]); // Message length = 0 (no attributes)
    buf.extend_from_slice(&MAGIC_COOKIE);
    buf.extend_from_slice(transaction_id);
    buf
}

/// Parses a STUN Binding Success Response and extracts the mapped address.
///
/// Returns `None` if the packet is not a valid STUN Binding Response matching
/// the expected transaction ID, or if no mapped address attribute is found.
pub(crate) fn parse_binding_response(data: &[u8], expected_tid: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < HEADER_SIZE {
        return None;
    }

    // Check response type
    if data[0..2] != BINDING_SUCCESS_TYPE {
        return None;
    }

    // Check magic cookie
    if data[4..8] != MAGIC_COOKIE {
        return None;
    }

    // Check transaction ID
    if data[8..20] != *expected_tid {
        return None;
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < HEADER_SIZE + msg_len {
        return None;
    }

    // Walk TLV attributes looking for XOR-MAPPED-ADDRESS (preferred) or
    // MAPPED-ADDRESS (fallback).
    let attrs = &data[HEADER_SIZE..HEADER_SIZE + msg_len];
    let mut mapped = None;
    let mut offset = 0;

    while offset + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;

        if offset + 4 + attr_len > attrs.len() {
            break;
        }

        let attr_value = &attrs[offset + 4..offset + 4 + attr_len];

        if attr_type == XOR_MAPPED_ADDRESS {
            if let Some(addr) = decode_xor_mapped_address(attr_value, expected_tid) {
                return Some(addr);
            }
        } else if attr_type == MAPPED_ADDRESS && mapped.is_none() {
            mapped = decode_mapped_address(attr_value);
        }

        // Attributes are padded to 4-byte boundaries (RFC 5389 §15).
        let padded_len = (attr_len + 3) & !3;
        offset += 4 + padded_len;
    }

    mapped
}

/// Decodes an XOR-MAPPED-ADDRESS attribute value (RFC 5389 §15.2).
fn decode_xor_mapped_address(value: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }

    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]) ^ 0x2112;

    match family {
        // IPv4
        0x01 => {
            if value.len() < 8 {
                return None;
            }
            let ip = Ipv4Addr::new(
                value[4] ^ MAGIC_COOKIE[0],
                value[5] ^ MAGIC_COOKIE[1],
                value[6] ^ MAGIC_COOKIE[2],
                value[7] ^ MAGIC_COOKIE[3],
            );
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        // IPv6
        0x02 => {
            if value.len() < 20 {
                return None;
            }
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i] = value[4 + i] ^ MAGIC_COOKIE[i];
            }
            for i in 4..16 {
                bytes[i] = value[4 + i] ^ transaction_id[i - 4];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port))
        }
        _ => None,
    }
}

/// Decodes a MAPPED-ADDRESS attribute value (RFC 5389 §15.1).
///
/// Fallback for older STUN servers that don't send XOR-MAPPED-ADDRESS.
fn decode_mapped_address(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }

    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);

    match family {
        0x01 => {
            if value.len() < 8 {
                return None;
            }
            let ip = Ipv4Addr::new(value[4], value[5], value[6], value[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            if value.len() < 20 {
                return None;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&value[4..20]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_request_format() {
        let tid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = build_binding_request(&tid);

        assert_eq!(req.len(), 20);
        // Type: Binding Request
        assert_eq!(&req[0..2], &[0x00, 0x01]);
        // Length: 0
        assert_eq!(&req[2..4], &[0x00, 0x00]);
        // Magic cookie
        assert_eq!(&req[4..8], &MAGIC_COOKIE);
        // Transaction ID
        assert_eq!(&req[8..20], &tid);
    }

    #[test]
    fn test_parse_binding_response_ipv4() {
        let tid = [0xAA; 12];

        // Build a response with XOR-MAPPED-ADDRESS for 198.51.100.5:12345
        let ip = Ipv4Addr::new(198, 51, 100, 5);
        let port: u16 = 12345;
        let xor_port = port ^ 0x2112;
        let xor_ip = [
            ip.octets()[0] ^ MAGIC_COOKIE[0],
            ip.octets()[1] ^ MAGIC_COOKIE[1],
            ip.octets()[2] ^ MAGIC_COOKIE[2],
            ip.octets()[3] ^ MAGIC_COOKIE[3],
        ];

        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&BINDING_SUCCESS_TYPE);
        response.extend_from_slice(&[0x00, 0x0C]); // Message length = 12
        response.extend_from_slice(&MAGIC_COOKIE);
        response.extend_from_slice(&tid);
        // XOR-MAPPED-ADDRESS attribute
        response.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x08]); // Attribute length = 8
        response.push(0x00); // Reserved
        response.push(0x01); // Family: IPv4
        response.extend_from_slice(&xor_port.to_be_bytes());
        response.extend_from_slice(&xor_ip);

        let addr = parse_binding_response(&response, &tid).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(ip), port));
    }

    #[test]
    fn test_parse_binding_response_ipv6() {
        let tid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];

        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let port: u16 = 54321;
        let xor_port = port ^ 0x2112;
        let ip_bytes = ip.octets();
        let mut xor_ip = [0u8; 16];
        for i in 0..4 {
            xor_ip[i] = ip_bytes[i] ^ MAGIC_COOKIE[i];
        }
        for i in 4..16 {
            xor_ip[i] = ip_bytes[i] ^ tid[i - 4];
        }

        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&BINDING_SUCCESS_TYPE);
        response.extend_from_slice(&[0x00, 0x18]); // Message length = 24
        response.extend_from_slice(&MAGIC_COOKIE);
        response.extend_from_slice(&tid);
        // XOR-MAPPED-ADDRESS attribute
        response.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x14]); // Attribute length = 20
        response.push(0x00); // Reserved
        response.push(0x02); // Family: IPv6
        response.extend_from_slice(&xor_port.to_be_bytes());
        response.extend_from_slice(&xor_ip);

        let addr = parse_binding_response(&response, &tid).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V6(ip), port));
    }

    #[test]
    fn test_parse_wrong_transaction_id() {
        let tid = [0xAA; 12];
        let wrong_tid = [0xBB; 12];

        let mut response = Vec::new();
        response.extend_from_slice(&BINDING_SUCCESS_TYPE);
        response.extend_from_slice(&[0x00, 0x00]); // No attributes
        response.extend_from_slice(&MAGIC_COOKIE);
        response.extend_from_slice(&wrong_tid);

        assert!(parse_binding_response(&response, &tid).is_none());
    }

    #[test]
    fn test_parse_not_a_stun_response() {
        let tid = [0xAA; 12];
        // Random non-STUN data
        assert!(parse_binding_response(&[0x01, 0x02, 0x03], &tid).is_none());
    }

    #[test]
    fn test_parse_mapped_address_fallback() {
        let tid = [0xAA; 12];
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let port: u16 = 9999;

        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&BINDING_SUCCESS_TYPE);
        response.extend_from_slice(&[0x00, 0x0C]); // Message length = 12
        response.extend_from_slice(&MAGIC_COOKIE);
        response.extend_from_slice(&tid);
        // MAPPED-ADDRESS attribute (non-XOR fallback)
        response.extend_from_slice(&MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x08]); // Attribute length = 8
        response.push(0x00); // Reserved
        response.push(0x01); // Family: IPv4
        response.extend_from_slice(&port.to_be_bytes());
        response.extend_from_slice(&ip.octets());

        let addr = parse_binding_response(&response, &tid).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(ip), port));
    }
}
