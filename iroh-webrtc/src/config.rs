//! WebRTC transport configuration.

use std::time::Duration;

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

/// Controls how the transport re-attempts a failed WebRTC connection.
///
/// When a peer connection fails (ICE disconnect, DataChannel close, etc.), the
/// transport tears it down and schedules a reconnect using exponential backoff.
/// A peer that exhausts [`RetryConfig::max_attempts`] without succeeding is
/// parked until the next network-change notification (which resets the
/// counter).
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Backoff applied to the first retry after a failure.
    pub initial_backoff: Duration,
    /// Upper bound for the exponential backoff.
    pub max_backoff: Duration,
    /// Number of consecutive failures after which the peer is parked until
    /// the next external kick (e.g. a network-change notification).
    pub max_attempts: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            max_attempts: 6,
        }
    }
}

/// Configuration for the WebRTC transport.
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    /// ICE servers to use for gathering candidates.
    pub ice_servers: Vec<IceServer>,
    /// Retry / reconnect behavior on connection failure.
    pub retry: RetryConfig,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            ice_servers: vec![IceServer::default()],
            retry: RetryConfig::default(),
        }
    }
}
