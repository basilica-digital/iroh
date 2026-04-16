//! Platform-specific WebRTC peer connection management.
//!
//! This module provides a [`PeerConnectionManager`] that abstracts over:
//! - **Browser (Wasm)**: `web-sys` bindings to the browser's `RTCPeerConnection`
//! - **Native**: The `str0m` crate (pure-Rust, sans-I/O WebRTC)
//!
//! The manager handles the lifecycle of peer connections: creation, signaling,
//! data transfer, and cleanup.

#[cfg(wasm_browser)]
mod browser;
#[cfg(not(wasm_browser))]
mod native;
#[cfg(not(wasm_browser))]
mod stun;

#[cfg(wasm_browser)]
pub(crate) use browser::PeerConnectionManager;
#[cfg(not(wasm_browser))]
pub(crate) use native::PeerConnectionManager;

/// Copy-pasteable diagnostic log of WebRTC signaling and ICE events.
///
/// Intended for browser debugging where devtools are inconvenient (iOS
/// Safari, for example). See [`browser::webrtc_debug_snapshot`] for details.
#[cfg(wasm_browser)]
pub use browser::{webrtc_debug_clear, webrtc_debug_snapshot};
