//! WebRTC transport configuration.

/// Configuration for a STUN or TURN server used during ICE gathering.
#[derive(Debug, Clone)]
pub struct IceServer {
    /// STUN/TURN server URLs (e.g. `"stun:stun.l.google.com:19302"`).
    pub urls: Vec<String>,
    /// Optional username for TURN authentication.
    pub username: Option<String>,
    /// Optional credential for TURN authentication.
    pub credential: Option<String>,
}

impl Default for IceServer {
    fn default() -> Self {
        Self {
            urls: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            username: None,
            credential: None,
        }
    }
}

/// Configuration for the WebRTC transport.
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    /// ICE servers to use for gathering candidates.
    pub ice_servers: Vec<IceServer>,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            ice_servers: vec![IceServer::default()],
        }
    }
}
