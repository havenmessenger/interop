//! The client lane of mimihubd, version 1: what a provider's own server needs to talk to its hub.
//!
//! MIMI specifies how providers talk to each other and leaves how a provider's own server reaches its hub to the
//! provider. mimihubd's answer is its client lane (`mimihubd/README.md`, "The client lane"), and this crate is that
//! lane as a library, used by mimihubd itself for its side and by any server that talks to it:
//!
//! - [`wire`]: the request and answer bodies, JSON through serde, the provider event stream's events among them.
//! - [`sign`]: the signatures the lane takes (RFC 9421, Ed25519): a request for one user, a request the provider's
//!   server makes for itself, and a provider's own request (the profile a hub signs a push with).
//! - [`push`]: checking that an event batch was pushed by the hub, once.
//!
//! It holds no HTTP client or server and no async runtime: a synchronous server and an async one link it alike.

pub mod push;
pub mod sign;
pub mod wire;

/// The lane's contract version this crate implements, as the lane's `info` states it.
pub const LANE_VERSION: u32 = 1;

/// Where the lane's routes are: `<lane origin>/mimi/client/v1/<route>`.
pub const LANE_PATH_PREFIX: &str = "/mimi/client/v1/";
