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

#[cfg(wasm_browser)]
pub(crate) use browser::PeerConnectionManager;
#[cfg(not(wasm_browser))]
pub(crate) use native::PeerConnectionManager;
