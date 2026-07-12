//! mimi-core - pure MIMI/MLS provider logic. Self-contained: no networking, no server deps, no
//! WASM-incompatible dependencies (see Cargo.toml for the WHY).
//!
//! - [`gate`] - the security-critical foreign-input ingest logic: the ciphersuite accept-gate
//!   (INV-MLS-002, closes the libcrux-ChaCha reachability), the opt-in `identifier_query` (DIV-4),
//!   the one-time KeyPackage store contract (K1/K2), and the `/notify` dedup (M5).
//! - [`content`] - the MIMI content codec (content-09 §4–6): deterministic CBOR (§4.2.1, NOT the
//!   forbidden length-first order), the part type system, and the validation MUSTs (depth, nohtml,
//!   reply-loop).
//! - [`uri`] - MIMI identifier URIs (protocol-06 §4): the `mimi://authority/{u|r|d}/path` addressing
//!   primitive - authority extraction is how a provider knows the destination.
//! - [`virtual_clients`] - draft-ietf-mls-virtual-clients-01 §5-§6: the emulation-group secret
//!   derivation, Small-Space PRP + reuse_guard, and generation-ID mechanism multiple emulator clients
//!   use to jointly act as one virtual client under a single higher-level-group leaf.
//!
//! All modules are self-contained; their tests are self-contained.
//!
//! `external-ops` (default-off Cargo feature): when enabled, compiles a small proof-only test module
//! (`spec_capability_proof`, `#[cfg(all(feature = "external-ops", test))]`) demonstrating that
//! openmls's OWN external-commit and external-proposal mechanisms are real and testable, for a
//! full-fidelity ("SpecProfile") consumer such as `mimi-hub`. It is NOT Haven's own acceptance
//! mechanism - see `crate::gate`'s join-model note and `crypto_core::profile`'s policy for
//! Haven's actual posture, which excludes this feature by default and permanently in the native lane.

pub mod consent;
pub mod content;
pub mod gate;
pub mod participant_list;
pub mod protocol_wire;
pub mod room_policy;
#[cfg(all(feature = "external-ops", test))]
mod spec_capability_proof;
pub mod uri;
pub mod virtual_clients;
