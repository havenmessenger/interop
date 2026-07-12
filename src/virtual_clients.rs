//! MLS Virtual Clients (draft-ietf-mls-virtual-clients-01, WG Document, §5-§6) - the mechanism that
//! lets multiple emulator clients jointly act as one virtual client under a single leaf in a
//! higher-level MLS group. This is a **contribution-backing reference implementation**: the running
//! code behind Haven's multi-device standards contribution, built to conform to the now-normative
//! `-01` mechanism, NOT a Haven product feature (that is a separate design track touching Haven's
//! core session/key-management architecture, gated on its own security review).
//!
//! ## What's implemented (v1 conformance scope)
//! - **§5.2 Generating Virtual Client Secrets** - the five-secret derivation
//!   (`epoch_id`/`epoch_base_secret`/`epoch_encryption_key`/`generation_id_secret`/`reuse_guard_secret`)
//!   from an `emulator_epoch_secret`, via [`derive_epoch_secrets`].
//! - **§5.6.1 Small-Space PRP** - FF1 (NIST SP 800-38G) with AES-128, radix 2, a 32-bit numeral
//!   string, empty tweak: [`small_space_prp_encrypt`] / [`small_space_prp_decrypt`].
//! - **§5.6.2 Reuse Guard** - collision-free `reuse_guard` computation + the recipient-side leaf-index
//!   recovery: [`compute_reuse_guard`] / [`recover_sender_leaf_index`].
//! - **§5.6.3 Generation ID** - the DS-coordination value: [`compute_generation_id`].
//! - **§6.2 Joining externally / §6.3 Removing emulator clients** - proven at the conformance-test
//!   layer (not in this module) as ordinary openmls `MlsGroup` operations against the emulation group
//!   itself: an external commit (join) and an in-group Remove (removal), each followed by a fresh
//!   [`derive_epoch_secrets`] call to prove epoch advancement. See the crate's virtual-clients
//!   conformance tests.
//!
//! ## What's deliberately NOT implemented (v1 divergence, cited)
//! **§6.1 Variant A (provisioning state transfer)** - the full `NewEmulatorClientState` wire struct
//! (retained operation secrets, per-KeyPackage material, the PPRF-serialized Secret Tree state, and the
//! per-higher-level-group `HigherLevelGroupState`) is a substantial additional wire-format + state-
//! management build on top of the mechanism here. v1 onboards exclusively via **Variant B (external
//! commit)** (§6.2), which needs none of that retained state. This is a scope decision, not a gap in the
//! derivation logic: every secret Variant A would need to transfer is already produced by
//! [`derive_epoch_secrets`] + the per-leaf operation-ratchet derivation this module documents (§5.2);
//! what's missing is the serialization format for handing it to an offline-onboarded client.
//!
//! ## INV-MLS-001a scope note (the emulation group is not the invariant's target)
//! Haven's `INV-MLS-001a` ("no external commits", successor to the original single `INV-MLS-001`)
//! closes the ETK external-treekem attack (eprint 2025/229) on Haven's
//! **product/higher-level MLS groups** - the wire-facing surface a *foreign, untrusted* party could
//! reach over federation (see `gate.rs`'s join-model note and `DIV-1` in the conformance record, both
//! scoped to that cross-provider join path). The **emulation group** this module derives secrets for is a
//! different trust domain entirely: per §7.1 of the draft, "emulator clients have to trust each other
//! fully; the emulation group does not provide any isolation between them" - it is a private group
//! whose only members are devices of **one virtual client**, never exposed to a foreign party as a
//! joinable target. §6.2's external-commit join is a new, *legitimate* device of that same virtual
//! client onboarding itself - structurally the same trust relationship as a user's own
//! account-recovery flow, not the adversarial-relay scenario ETK attacks. Using
//! `join_by_external_commit` for the emulation group therefore does not touch `INV-MLS-001a`'s actual
//! target (Haven's higher-level chat groups still allow only the add-driven §5.2 KeyPackage + Welcome
//! join, unchanged - permanently, per that invariant). This module never calls `export_group_info` /
//! `join_by_external_commit` against a higher-level group; the conformance tests exercise it only
//! against a standalone emulation group with no foreign membership.

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use tls_codec::{Error as TlsError, Serialize as TlsSerialize, Size as TlsSize, VLBytes};

use fpe::ff1::{FlexibleNumeralString, FF1};

/// Errors from the virtual-clients mechanism. Kept separate from other modules' error enums (the
/// per-module `thiserror` convention) since these are cryptographic/format failures, not protocol
/// state-machine failures.
#[derive(Debug, thiserror::Error)]
pub enum VirtualClientError {
    #[error("KDF failure deriving a virtual-client secret: {0}")]
    Kdf(String),
    #[error("Small-Space PRP key must be 16 bytes (AES-128), got {0}")]
    InvalidPrpKeyLen(usize),
    #[error("Small-Space PRP (FF1) operation failed: {0}")]
    Prp(String),
    #[error("N_e (emulation-group leaf count, §5.6.2) must be a power of two, got {0}")]
    NotPowerOfTwo(u32),
    #[error("leaf_index_e {leaf_index} is out of range for N_e {n_e}")]
    LeafIndexOutOfRange { leaf_index: u32, n_e: u32 },
    #[error("OS CSPRNG read failed: {0}")]
    Rng(String),
    /// A wire discriminant decoded to `reserved(0)` or a value past the enum's known
    /// range - rejected before it can reach a secret-derivation call.
    #[error("{what} discriminant {got} is reserved or unknown")]
    ReservedOrUnknownDiscriminant { what: &'static str, got: u8 },
}

// ============================ RFC 9420 §8.1 DeriveSecret / ExpandWithLabel ============================
//
// openmls implements these internally (ciphersuite/secret.rs) but keeps them `pub(crate)` - this crate
// is a downstream consumer, not a fork, so the primitive is re-exposed here verbatim against the same
// public building blocks openmls itself uses (`tls_codec::VLBytes` + `OpenMlsCrypto::hkdf_expand`),
// confirmed against openmls's own `KdfLabel` (ciphersuite/kdf_label.rs) before writing this.

/// `struct { uint16 length = Length; opaque label<V> = "MLS 1.0 " + Label; opaque context<V> = Context; } KDFLabel;`
struct KdfLabel {
    length: u16,
    label: VLBytes,
    context: VLBytes,
}

impl TlsSize for KdfLabel {
    fn tls_serialized_len(&self) -> usize {
        self.length.tls_serialized_len()
            + self.label.tls_serialized_len()
            + self.context.tls_serialized_len()
    }
}
impl TlsSerialize for KdfLabel {
    fn tls_serialize<W: std::io::Write>(&self, w: &mut W) -> Result<usize, TlsError> {
        Ok(self.length.tls_serialize(w)?
            + self.label.tls_serialize(w)?
            + self.context.tls_serialize(w)?)
    }
}

/// RFC 9420 §8.1 `ExpandWithLabel(Secret, Label, Context, Length)`.
pub fn expand_with_label(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, VirtualClientError> {
    if length > u16::MAX as usize {
        return Err(VirtualClientError::Kdf(format!(
            "requested length {length} exceeds u16::MAX"
        )));
    }
    let kdf_label = KdfLabel {
        length: length as u16,
        label: format!("MLS 1.0 {label}").into_bytes().into(),
        context: context.to_vec().into(),
    };
    let info = kdf_label
        .tls_serialize_detached()
        .map_err(|e: TlsError| VirtualClientError::Kdf(format!("KDFLabel serialize: {e}")))?;
    crypto
        .hkdf_expand(ciphersuite.hash_algorithm(), secret, &info, length)
        .map(|s| s.as_slice().to_vec())
        .map_err(|e| VirtualClientError::Kdf(format!("hkdf_expand: {e:?}")))
}

/// RFC 9420 §8.1 `DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", Hash.length)`.
pub fn derive_secret(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    secret: &[u8],
    label: &str,
) -> Result<Vec<u8>, VirtualClientError> {
    expand_with_label(
        crypto,
        ciphersuite,
        secret,
        label,
        &[],
        ciphersuite.hash_length(),
    )
}

// ============================ §5.2 Generating Virtual Client Secrets ============================

/// One of the four `VirtualClientOperationType` values (§6.1.2 `enum { reserved(0), key_package(1),
/// leaf_node(2), application(3), (255) }` - a TLS presentation-language `uint8` enum, the `(255)`
/// marking the max discriminant width, not a fifth value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VirtualClientOperationType {
    Reserved = 0,
    KeyPackage = 1,
    LeafNode = 2,
    Application = 3,
}

impl VirtualClientOperationType {
    /// The TLS-encoded wire value (a bare `uint8`, per the enum's `(255)` width marker).
    pub const fn wire_value(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for VirtualClientOperationType {
    type Error = VirtualClientError;

    /// The canonical decode for this discriminant, for whenever a wire-decode path is built -
    /// `reserved(0)` and any value past the enum's known range (`>3`) are rejected here. This is
    /// preventive, not the load-bearing guard: a caller can also construct
    /// `VirtualClientOperationType::Reserved` directly as a Rust literal, bypassing this impl
    /// entirely - [`derive_initial_operation_ratchet_secret`] rejects `Reserved` itself, which is
    /// the check that actually matters.
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::KeyPackage),
            2 => Ok(Self::LeafNode),
            3 => Ok(Self::Application),
            got => Err(VirtualClientError::ReservedOrUnknownDiscriminant {
                what: "VirtualClientOperationType",
                got,
            }),
        }
    }
}

/// The five secrets §5.2 derives from `emulator_epoch_secret` for a single emulation-group epoch,
/// after which `emulator_epoch_secret` itself is deleted (draft text, §5.2 para 2). `epoch_base_secret`
/// additionally keys the Virtual Client Operation Secret Tree (not modeled as a full tree here - see
/// [`derive_initial_operation_ratchet_secret`] for the one derivation step this module implements from
/// that tree: the per-leaf, per-operation-type initial ratchet secret).
#[derive(Debug, Clone)]
pub struct EpochSecrets {
    pub epoch_id: Vec<u8>,
    pub epoch_base_secret: Vec<u8>,
    pub epoch_encryption_key: Vec<u8>,
    pub generation_id_secret: Vec<u8>,
    pub reuse_guard_secret: Vec<u8>,
}

/// §5.2: derive the five per-epoch virtual-client secrets from `emulator_epoch_secret`
/// (`emulator_epoch_secret = SafeExportSecret(virtual_clients_component_id)` at the call site - see the
/// module-level divergence note on the Safe Exporter API).
pub fn derive_epoch_secrets(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    emulator_epoch_secret: &[u8],
) -> Result<EpochSecrets, VirtualClientError> {
    Ok(EpochSecrets {
        epoch_id: derive_secret(crypto, ciphersuite, emulator_epoch_secret, "Epoch ID")?,
        epoch_base_secret: derive_secret(
            crypto,
            ciphersuite,
            emulator_epoch_secret,
            "Base Secret",
        )?,
        epoch_encryption_key: derive_secret(
            crypto,
            ciphersuite,
            emulator_epoch_secret,
            "Encryption Key",
        )?,
        generation_id_secret: derive_secret(
            crypto,
            ciphersuite,
            emulator_epoch_secret,
            "Generation ID Secret",
        )?,
        reuse_guard_secret: derive_secret(
            crypto,
            ciphersuite,
            emulator_epoch_secret,
            "Reuse Guard",
        )?,
    })
}

/// §5.2: `operation_ratchet_secret[operation_type][0] = ExpandWithLabel(leaf_secret, "vc operation init",
/// operation_type, Kdf.Nh)` - the initial per-operation-type ratchet secret derived when a Virtual
/// Client Operation Secret Tree leaf is expanded. `leaf_secret` is the tree-leaf secret at the emulator
/// client's own `leaf_index` (derived from `epoch_base_secret` by the Secret Tree construction, §9 of
/// RFC 9420, applied with `epoch_base_secret` as the tree root per §5.2) - the full per-leaf Secret Tree
/// expansion is standard RFC 9420 §9 machinery and is intentionally not re-derived here; this function
/// takes the already-expanded `leaf_secret` and performs the one operation-type-specific step the draft
/// adds on top of it.
///
/// `Reserved` is rejected here, not just at `TryFrom<u8>`. `VirtualClientOperationType`
/// is a public enum - a caller can write `VirtualClientOperationType::Reserved` directly and skip
/// `TryFrom` entirely, since a Rust-literal construction never touches a `TryFrom` impl. This is
/// the actual boundary that reaches secret derivation, so the load-bearing check lives here.
pub fn derive_initial_operation_ratchet_secret(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    leaf_secret: &[u8],
    operation_type: VirtualClientOperationType,
) -> Result<Vec<u8>, VirtualClientError> {
    if operation_type == VirtualClientOperationType::Reserved {
        return Err(VirtualClientError::ReservedOrUnknownDiscriminant {
            what: "VirtualClientOperationType",
            got: operation_type.wire_value(),
        });
    }
    expand_with_label(
        crypto,
        ciphersuite,
        leaf_secret,
        "vc operation init",
        &[operation_type.wire_value()],
        ciphersuite.hash_length(),
    )
}

// ============================ §5.6.1 Small-Space PRP ============================
//
// FF1 (NIST SP 800-38G) instantiated with AES-128, radix 2, a numeral string of length 32, empty
// tweak. Reused from the `fpe` crate (a maintained RustCrypto-adjacent FF1 implementation) rather than
// hand-rolling the Feistel-network construction. Bit mapping is spec-literal, NOT the `fpe` crate's own
// `BinaryNumeralString` byte-packing convention (whose internal bit order is an implementation detail
// of THAT crate's packed-byte optimization, not the draft's "list bits from most significant to least
// significant" definition) - `FlexibleNumeralString` is used instead, one `u16` per bit, in an order
// built directly from the draft's own words: index 0 = most significant bit. `FlexibleNumeralString`'s
// own `num_radix()` (`res = res*radix + digit`, iterating the vec in order) is exactly the Horner-method
// most-significant-first numeral-to-integer conversion FF1's `NUM()` operation specifies, so this
// mapping is unambiguous and directly checkable against the crate source (`src/ff1/alloc.rs`).

/// "A 32-bit unsigned integer is mapped to a numeral string by listing its bits from most significant
/// to least significant" (§5.6.1) - index 0 = bit 31 (MSB), index 31 = bit 0 (LSB).
fn u32_to_msb_bit_digits(value: u32) -> Vec<u16> {
    (0..32).rev().map(|i| ((value >> i) & 1) as u16).collect()
}

/// The inverse of [`u32_to_msb_bit_digits`]: "the output numeral string is mapped back to a 32-bit
/// unsigned integer in the same way" (§5.6.1).
fn msb_bit_digits_to_u32(digits: &[u16]) -> u32 {
    digits
        .iter()
        .fold(0u32, |acc, &d| (acc << 1) | u32::from(d))
}

/// §5.6.1 `SmallSpacePRP.Encrypt(key, input)`. `key` MUST be a 16-byte AES-128 key.
pub fn small_space_prp_encrypt(key: &[u8], input: u32) -> Result<u32, VirtualClientError> {
    if key.len() != 16 {
        return Err(VirtualClientError::InvalidPrpKeyLen(key.len()));
    }
    let ff1 = FF1::<aes::Aes128>::new(key, 2)
        .map_err(|e| VirtualClientError::Prp(format!("FF1::new: {e:?}")))?;
    let pt = FlexibleNumeralString::from(u32_to_msb_bit_digits(input));
    let ct = ff1
        .encrypt(&[], &pt)
        .map_err(|e| VirtualClientError::Prp(format!("FF1::encrypt: {e:?}")))?;
    Ok(msb_bit_digits_to_u32(&Vec::from(ct)))
}

/// §5.6.1 `SmallSpacePRP.Decrypt(key, output)`. `key` MUST be a 16-byte AES-128 key.
pub fn small_space_prp_decrypt(key: &[u8], output: u32) -> Result<u32, VirtualClientError> {
    if key.len() != 16 {
        return Err(VirtualClientError::InvalidPrpKeyLen(key.len()));
    }
    let ff1 = FF1::<aes::Aes128>::new(key, 2)
        .map_err(|e| VirtualClientError::Prp(format!("FF1::new: {e:?}")))?;
    let ct = FlexibleNumeralString::from(u32_to_msb_bit_digits(output));
    let pt = ff1
        .decrypt(&[], &ct)
        .map_err(|e| VirtualClientError::Prp(format!("FF1::decrypt: {e:?}")))?;
    Ok(msb_bit_digits_to_u32(&Vec::from(pt)))
}

// ============================ §5.6.2 Reuse Guard ============================

/// 16 cryptographically-random bytes from the OS CSPRNG, via `getrandom` (a portable, minimal,
/// widely-audited primitive already resolved transitively by this crate's MLS dependency tree - pinned
/// directly here rather than reused implicitly).
fn os_random_u8s<const N: usize>() -> Result<[u8; N], VirtualClientError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| VirtualClientError::Rng(e.to_string()))?;
    Ok(buf)
}

/// §5.6.2: the sending emulator client's half - compute a `reuse_guard` that (a) never collides with
/// another emulator client's for the same key-nonce pair, because its value modulo `n_e` is always
/// exactly `leaf_index_e`, and (b) is otherwise indistinguishable from random to an outside observer.
///
/// `n_e` MUST be a power of two (the draft: "since the ratchet tree is always full, N_e is a power of
/// two" - §7.7 RFC 9420) - this lets `x` be constructed directly (random high bits, `leaf_index_e` as
/// the fixed low bits) rather than by rejection-sampling a residue class, which is both simpler and
/// constant-time-shaped (no retry loop whose iteration count could leak `leaf_index_e`).
pub fn compute_reuse_guard(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    reuse_guard_secret: &[u8],
    key_schedule_nonce: &[u8],
    leaf_index_e: u32,
    n_e: u32,
) -> Result<[u8; 4], VirtualClientError> {
    let log2_n_e = check_power_of_two_and_range(n_e, leaf_index_e)?;
    let prp_key = expand_with_label(
        crypto,
        ciphersuite,
        reuse_guard_secret,
        "reuse guard",
        key_schedule_nonce,
        16,
    )?;
    // x such that x mod n_e == leaf_index_e: fix the low log2(n_e) bits to leaf_index_e, randomize
    // the rest. n_e a power of two makes "mod n_e" exactly "low log2(n_e) bits".
    let high_bits: u32 = if log2_n_e >= 32 {
        0
    } else {
        u32::from_le_bytes(os_random_u8s::<4>()?) << log2_n_e
    };
    let x = high_bits | leaf_index_e;
    let reuse_guard = small_space_prp_encrypt(&prp_key, x)?;
    Ok(reuse_guard.to_be_bytes())
}

/// §5.6.2: the recipient's half - recover the sending emulator client's leaf index in the emulation
/// group at epoch `e` from an observed `reuse_guard`, given the same `reuse_guard_secret` and
/// `key_schedule_nonce` used to send the message.
pub fn recover_sender_leaf_index(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    reuse_guard_secret: &[u8],
    key_schedule_nonce: &[u8],
    reuse_guard: &[u8; 4],
    n_e: u32,
) -> Result<u32, VirtualClientError> {
    if !n_e.is_power_of_two() {
        return Err(VirtualClientError::NotPowerOfTwo(n_e));
    }
    let prp_key = expand_with_label(
        crypto,
        ciphersuite,
        reuse_guard_secret,
        "reuse guard",
        key_schedule_nonce,
        16,
    )?;
    let x = small_space_prp_decrypt(&prp_key, u32::from_be_bytes(*reuse_guard))?;
    Ok(x % n_e)
}

const fn check_power_of_two_and_range(
    n_e: u32,
    leaf_index_e: u32,
) -> Result<u32, VirtualClientError> {
    if !n_e.is_power_of_two() {
        return Err(VirtualClientError::NotPowerOfTwo(n_e));
    }
    if leaf_index_e >= n_e {
        return Err(VirtualClientError::LeafIndexOutOfRange {
            leaf_index: leaf_index_e,
            n_e,
        });
    }
    Ok(n_e.trailing_zeros())
}

// ============================ §5.6.3 Coordinating ratchet generations with the DS ============================

/// §6.1.2 `enum { reserved(0), application(1), handshake(2), (255) } RatchetType;` - the ratchet whose
/// generation is being coordinated (a bare `uint8`, matching [`VirtualClientOperationType`]'s width
/// convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RatchetType {
    Reserved = 0,
    Application = 1,
    Handshake = 2,
}

impl TryFrom<u8> for RatchetType {
    type Error = VirtualClientError;

    /// The canonical decode for this discriminant, for whenever a wire-decode path is built -
    /// `reserved(0)` and any value past the enum's known range (`>2`) are rejected here. This is
    /// preventive, not the load-bearing guard: a caller can also construct
    /// `RatchetType::Reserved` directly as a Rust literal, bypassing this impl entirely -
    /// [`compute_generation_id`] rejects `Reserved` itself, which is the check that actually
    /// matters.
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Application),
            2 => Ok(Self::Handshake),
            got => Err(VirtualClientError::ReservedOrUnknownDiscriminant {
                what: "RatchetType",
                got,
            }),
        }
    }
}

/// `struct { opaque group_id<V>; uint64 epoch; uint32 generation; RatchetType ratchet_type; } PrivateMessageContext;`
struct PrivateMessageContext {
    group_id: VLBytes,
    epoch: u64,
    generation: u32,
    ratchet_type: u8,
}

impl TlsSize for PrivateMessageContext {
    fn tls_serialized_len(&self) -> usize {
        self.group_id.tls_serialized_len()
            + self.epoch.tls_serialized_len()
            + self.generation.tls_serialized_len()
            + self.ratchet_type.tls_serialized_len()
    }
}
impl TlsSerialize for PrivateMessageContext {
    fn tls_serialize<W: std::io::Write>(&self, w: &mut W) -> Result<usize, TlsError> {
        Ok(self.group_id.tls_serialize(w)?
            + self.epoch.tls_serialize(w)?
            + self.generation.tls_serialize(w)?
            + self.ratchet_type.tls_serialize(w)?)
    }
}

/// §5.6.3: `generation_id = ExpandWithLabel(generation_id_secret, "generation id", PrivateMessageContext,
/// Kdf.Nh)` - lets a strongly-consistent DS detect ratchet-generation collisions between concurrently
/// sending emulator clients (a functionality, not confidentiality/integrity, concern per §5.6.3).
///
/// `Reserved` is rejected here, not just at `TryFrom<u8>`. `RatchetType` is a public
/// enum - a caller can write `RatchetType::Reserved` directly and skip `TryFrom` entirely, since a
/// Rust-literal construction never touches a `TryFrom` impl. This is the actual boundary that
/// reaches `PrivateMessageContext`'s KDF context, so the load-bearing check lives here.
pub fn compute_generation_id(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    generation_id_secret: &[u8],
    group_id: &[u8],
    epoch: u64,
    generation: u32,
    ratchet_type: RatchetType,
) -> Result<Vec<u8>, VirtualClientError> {
    if ratchet_type == RatchetType::Reserved {
        return Err(VirtualClientError::ReservedOrUnknownDiscriminant {
            what: "RatchetType",
            got: ratchet_type as u8,
        });
    }
    let ctx = PrivateMessageContext {
        group_id: group_id.to_vec().into(),
        epoch,
        generation,
        ratchet_type: ratchet_type as u8,
    };
    let ctx_bytes = ctx
        .tls_serialize_detached()
        .map_err(|e: TlsError| VirtualClientError::Kdf(format!("PrivateMessageContext: {e}")))?;
    expand_with_label(
        crypto,
        ciphersuite,
        generation_id_secret,
        "generation id",
        &ctx_bytes,
        ciphersuite.hash_length(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsProvider;

    fn crypto() -> OpenMlsRustCrypto {
        OpenMlsRustCrypto::default()
    }

    const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // ---- §5.2 epoch secrets ----

    #[test]
    fn epoch_secrets_are_five_distinct_32_byte_values_deterministic_from_input() {
        let backend = crypto();
        let emulator_epoch_secret = [0x42u8; 32];
        let s1 = derive_epoch_secrets(backend.crypto(), SUITE, &emulator_epoch_secret).unwrap();
        let s2 = derive_epoch_secrets(backend.crypto(), SUITE, &emulator_epoch_secret).unwrap();

        // Deterministic: same input -> byte-identical output (every emulator client must derive the
        // SAME five secrets from the SAME emulator_epoch_secret for the mechanism to work at all).
        assert_eq!(s1.epoch_id, s2.epoch_id);
        assert_eq!(s1.reuse_guard_secret, s2.reuse_guard_secret);

        // All five secrets are distinct from each other (no accidental label collision) and
        // Nh = 32 bytes for suite 0x0001 (SHA-256).
        let all = [
            &s1.epoch_id,
            &s1.epoch_base_secret,
            &s1.epoch_encryption_key,
            &s1.generation_id_secret,
            &s1.reuse_guard_secret,
        ];
        for s in all {
            assert_eq!(s.len(), 32);
        }
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "secrets at {i} and {j} collided");
            }
        }
    }

    #[test]
    fn different_emulator_epoch_secrets_derive_different_epoch_secrets() {
        let backend = crypto();
        let s1 = derive_epoch_secrets(backend.crypto(), SUITE, &[0x11u8; 32]).unwrap();
        let s2 = derive_epoch_secrets(backend.crypto(), SUITE, &[0x22u8; 32]).unwrap();
        assert_ne!(s1.epoch_id, s2.epoch_id);
        assert_ne!(s1.reuse_guard_secret, s2.reuse_guard_secret);
    }

    #[test]
    fn initial_operation_ratchet_secret_differs_per_operation_type() {
        let backend = crypto();
        let leaf_secret = [0x33u8; 32];
        let kp = derive_initial_operation_ratchet_secret(
            backend.crypto(),
            SUITE,
            &leaf_secret,
            VirtualClientOperationType::KeyPackage,
        )
        .unwrap();
        let ln = derive_initial_operation_ratchet_secret(
            backend.crypto(),
            SUITE,
            &leaf_secret,
            VirtualClientOperationType::LeafNode,
        )
        .unwrap();
        let app = derive_initial_operation_ratchet_secret(
            backend.crypto(),
            SUITE,
            &leaf_secret,
            VirtualClientOperationType::Application,
        )
        .unwrap();
        assert_ne!(kp, ln);
        assert_ne!(ln, app);
        assert_ne!(kp, app);
    }

    /// `reserved(0)` and any value past the known range must never decode - the
    /// discriminant can never reach `derive_initial_operation_ratchet_secret` in the first place.
    #[test]
    fn operation_type_try_from_rejects_reserved_and_unknown() {
        assert!(matches!(
            VirtualClientOperationType::try_from(0u8),
            Err(VirtualClientError::ReservedOrUnknownDiscriminant { got: 0, .. })
        ));
        assert!(matches!(
            VirtualClientOperationType::try_from(4u8),
            Err(VirtualClientError::ReservedOrUnknownDiscriminant { got: 4, .. })
        ));
        assert!(matches!(
            VirtualClientOperationType::try_from(255u8),
            Err(VirtualClientError::ReservedOrUnknownDiscriminant { got: 255, .. })
        ));
    }

    #[test]
    fn operation_type_try_from_accepts_known_values() {
        assert_eq!(
            VirtualClientOperationType::try_from(1u8).unwrap(),
            VirtualClientOperationType::KeyPackage
        );
        assert_eq!(
            VirtualClientOperationType::try_from(2u8).unwrap(),
            VirtualClientOperationType::LeafNode
        );
        assert_eq!(
            VirtualClientOperationType::try_from(3u8).unwrap(),
            VirtualClientOperationType::Application
        );
    }

    /// `Reserved` constructed directly as a Rust literal (bypassing `TryFrom<u8>` entirely, not
    /// just the decode boundary) must still be rejected by the derivation function itself.
    #[test]
    fn initial_operation_ratchet_secret_rejects_reserved_bypassing_try_from() {
        let backend = crypto();
        let err = derive_initial_operation_ratchet_secret(
            backend.crypto(),
            SUITE,
            &[0x11u8; 32],
            VirtualClientOperationType::Reserved,
        )
        .expect_err("Reserved must never reach the KDF, even constructed directly");
        assert!(matches!(
            err,
            VirtualClientError::ReservedOrUnknownDiscriminant { got: 0, .. }
        ));
    }

    // ---- §5.6.1 Small-Space PRP ----

    #[test]
    fn small_space_prp_round_trips() {
        let key = [0x77u8; 16];
        for input in [0u32, 1, 2, 0xFFFF_FFFF, 0x8000_0000, 0x1234_5678, 42] {
            let ct = small_space_prp_encrypt(&key, input).unwrap();
            let pt = small_space_prp_decrypt(&key, ct).unwrap();
            assert_eq!(pt, input, "round-trip failed for input {input:#x}");
        }
    }

    #[test]
    fn small_space_prp_is_a_permutation_not_identity() {
        // A real PRP must not leak the input directly for a "random-looking" key.
        let key = [0x99u8; 16];
        let ct = small_space_prp_encrypt(&key, 0).unwrap();
        assert_ne!(
            ct, 0,
            "PRP output equalled input - looks like an identity bug"
        );
    }

    #[test]
    fn small_space_prp_different_keys_give_different_outputs() {
        let ct1 = small_space_prp_encrypt(&[0x01u8; 16], 12345).unwrap();
        let ct2 = small_space_prp_encrypt(&[0x02u8; 16], 12345).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn small_space_prp_rejects_non_16_byte_key() {
        assert!(matches!(
            small_space_prp_encrypt(&[0u8; 15], 0),
            Err(VirtualClientError::InvalidPrpKeyLen(15))
        ));
        assert!(matches!(
            small_space_prp_decrypt(&[0u8; 32], 0),
            Err(VirtualClientError::InvalidPrpKeyLen(32))
        ));
    }

    // ---- §5.6.2 Reuse Guard ----

    #[test]
    fn reuse_guard_round_trips_to_the_correct_leaf_index() {
        let backend = crypto();
        let secrets = derive_epoch_secrets(backend.crypto(), SUITE, &[0xAAu8; 32]).unwrap();
        let nonce = [0x01, 0x02, 0x03, 0x04];
        let n_e = 8u32; // a full 3-level tree, power of two
        for leaf_index_e in 0..n_e {
            let rg = compute_reuse_guard(
                backend.crypto(),
                SUITE,
                &secrets.reuse_guard_secret,
                &nonce,
                leaf_index_e,
                n_e,
            )
            .unwrap();
            let recovered = recover_sender_leaf_index(
                backend.crypto(),
                SUITE,
                &secrets.reuse_guard_secret,
                &nonce,
                &rg,
                n_e,
            )
            .unwrap();
            assert_eq!(recovered, leaf_index_e);
        }
    }

    #[test]
    fn two_emulator_clients_never_collide_on_reuse_guard_for_the_same_key_nonce() {
        // The load-bearing property (§5.6.2): "two emulator clients will never generate the same
        // value" for the SAME key-nonce pair, because their x values live in disjoint residue classes
        // mod n_e. Sampling many times per leaf to also confirm the recovered index never drifts.
        let backend = crypto();
        let secrets = derive_epoch_secrets(backend.crypto(), SUITE, &[0xBBu8; 32]).unwrap();
        let nonce = [0xAA; 4];
        let n_e = 4u32;
        for _ in 0..20 {
            let rg0 = compute_reuse_guard(
                backend.crypto(),
                SUITE,
                &secrets.reuse_guard_secret,
                &nonce,
                0,
                n_e,
            )
            .unwrap();
            let rg1 = compute_reuse_guard(
                backend.crypto(),
                SUITE,
                &secrets.reuse_guard_secret,
                &nonce,
                1,
                n_e,
            )
            .unwrap();
            assert_ne!(
                rg0, rg1,
                "two different leaves produced the same reuse_guard"
            );
            assert_eq!(
                recover_sender_leaf_index(
                    backend.crypto(),
                    SUITE,
                    &secrets.reuse_guard_secret,
                    &nonce,
                    &rg0,
                    n_e
                )
                .unwrap(),
                0
            );
            assert_eq!(
                recover_sender_leaf_index(
                    backend.crypto(),
                    SUITE,
                    &secrets.reuse_guard_secret,
                    &nonce,
                    &rg1,
                    n_e
                )
                .unwrap(),
                1
            );
        }
    }

    #[test]
    fn reuse_guard_rejects_non_power_of_two_n_e() {
        let backend = crypto();
        let secrets = derive_epoch_secrets(backend.crypto(), SUITE, &[0xCCu8; 32]).unwrap();
        assert!(matches!(
            compute_reuse_guard(
                backend.crypto(),
                SUITE,
                &secrets.reuse_guard_secret,
                &[0u8; 4],
                0,
                6,
            ),
            Err(VirtualClientError::NotPowerOfTwo(6))
        ));
    }

    #[test]
    fn reuse_guard_rejects_leaf_index_out_of_range() {
        let backend = crypto();
        let secrets = derive_epoch_secrets(backend.crypto(), SUITE, &[0xDDu8; 32]).unwrap();
        assert!(matches!(
            compute_reuse_guard(
                backend.crypto(),
                SUITE,
                &secrets.reuse_guard_secret,
                &[0u8; 4],
                8,
                8,
            ),
            Err(VirtualClientError::LeafIndexOutOfRange {
                leaf_index: 8,
                n_e: 8
            })
        ));
    }

    // ---- §5.6.3 Generation ID ----

    #[test]
    fn generation_id_is_deterministic_and_context_bound() {
        let backend = crypto();
        let secrets = derive_epoch_secrets(backend.crypto(), SUITE, &[0xEEu8; 32]).unwrap();
        let g1 = compute_generation_id(
            backend.crypto(),
            SUITE,
            &secrets.generation_id_secret,
            b"group-1",
            3,
            7,
            RatchetType::Application,
        )
        .unwrap();
        let g1_again = compute_generation_id(
            backend.crypto(),
            SUITE,
            &secrets.generation_id_secret,
            b"group-1",
            3,
            7,
            RatchetType::Application,
        )
        .unwrap();
        assert_eq!(
            g1, g1_again,
            "same context must derive the same generation_id"
        );

        // Any single differing context field must change the output (group_id, epoch, generation,
        // ratchet_type each bound into PrivateMessageContext independently).
        let differs_by_group = compute_generation_id(
            backend.crypto(),
            SUITE,
            &secrets.generation_id_secret,
            b"group-2",
            3,
            7,
            RatchetType::Application,
        )
        .unwrap();
        let differs_by_epoch = compute_generation_id(
            backend.crypto(),
            SUITE,
            &secrets.generation_id_secret,
            b"group-1",
            4,
            7,
            RatchetType::Application,
        )
        .unwrap();
        let differs_by_generation = compute_generation_id(
            backend.crypto(),
            SUITE,
            &secrets.generation_id_secret,
            b"group-1",
            3,
            8,
            RatchetType::Application,
        )
        .unwrap();
        let differs_by_ratchet_type = compute_generation_id(
            backend.crypto(),
            SUITE,
            &secrets.generation_id_secret,
            b"group-1",
            3,
            7,
            RatchetType::Handshake,
        )
        .unwrap();
        assert_ne!(g1, differs_by_group);
        assert_ne!(g1, differs_by_epoch);
        assert_ne!(g1, differs_by_generation);
        assert_ne!(g1, differs_by_ratchet_type);
    }

    /// `reserved(0)` and any value past the known range must never decode - the
    /// discriminant can never reach `compute_generation_id` in the first place.
    #[test]
    fn ratchet_type_try_from_rejects_reserved_and_unknown() {
        assert!(matches!(
            RatchetType::try_from(0u8),
            Err(VirtualClientError::ReservedOrUnknownDiscriminant { got: 0, .. })
        ));
        assert!(matches!(
            RatchetType::try_from(3u8),
            Err(VirtualClientError::ReservedOrUnknownDiscriminant { got: 3, .. })
        ));
        assert!(matches!(
            RatchetType::try_from(255u8),
            Err(VirtualClientError::ReservedOrUnknownDiscriminant { got: 255, .. })
        ));
    }

    #[test]
    fn ratchet_type_try_from_accepts_known_values() {
        assert_eq!(
            RatchetType::try_from(1u8).unwrap(),
            RatchetType::Application
        );
        assert_eq!(RatchetType::try_from(2u8).unwrap(), RatchetType::Handshake);
    }

    /// `Reserved` constructed directly as a Rust literal (bypassing `TryFrom<u8>` entirely)
    /// must still be rejected by the derivation function itself.
    #[test]
    fn generation_id_rejects_reserved_ratchet_type_bypassing_try_from() {
        let backend = crypto();
        let secrets = derive_epoch_secrets(backend.crypto(), SUITE, &[0x22u8; 32]).unwrap();
        let err = compute_generation_id(
            backend.crypto(),
            SUITE,
            &secrets.generation_id_secret,
            b"group-reserved",
            0,
            0,
            RatchetType::Reserved,
        )
        .expect_err("Reserved must never reach the KDF context, even constructed directly");
        assert!(matches!(
            err,
            VirtualClientError::ReservedOrUnknownDiscriminant { got: 0, .. }
        ));
    }

    // ============================ Emulation-group conformance tests (§5.2/§6.2/§6.3) ============================
    //
    // These tests build a REAL openmls "emulation group" (§5.1) - a private MLS group whose members
    // represent emulator clients of ONE virtual client - and prove the mechanism end-to-end: identical
    // secret derivation across members (§5.2), a new emulator client onboarding via external commit
    // (§6.2), and removal advancing the epoch (§6.3). Self-contained harness (own `ident`/`keypackage`
    // helpers), matching this crate's per-module test-independence convention.
    //
    // DIVERGENCE (v1, cited): `emulator_epoch_secret` is spec'd as `SafeExportSecret(component_id)` -
    // the forward-secure per-component exporter from mls-extensions §4.4 - but openmls only exposes
    // `safe_export_secret` behind the `extensions-draft-08` feature, not enabled here. These tests use
    // the plain RFC 9420 `export_secret(label, context, length)` basic exporter as the v1 stand-in: it
    // gives every member of an epoch the SAME derived value (the property the mechanism actually needs
    // to prove), just without the Safe Exporter's forward-secrecy-per-component upgrade. Swapping in
    // `safe_export_secret` once that feature is enabled changes nothing downstream of this line.
    mod emulation_group_conformance {
        use super::*;
        use openmls::ciphersuite::signature::SignaturePublicKey;
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::messages::group_info::VerifiableGroupInfo;
        use openmls::prelude::*;
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;
        use tls_codec::Deserialize as _;

        const AES: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        // Stand-in component label for the plain-exporter divergence documented above; not a wire value.
        const EMULATOR_EPOCH_SECRET_LABEL: &str =
            "virtual clients emulator epoch secret (v1 stand-in)";

        struct TestSigner {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for TestSigner {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .sign(self.scheme, payload, &self.key)
                    .map_err(|_| SignerError::SigningError)
            }
            fn signature_scheme(&self) -> SignatureScheme {
                self.scheme
            }
        }

        fn ident(user: &str) -> (TestSigner, CredentialWithKey, OpenMlsRustCrypto) {
            let provider = OpenMlsRustCrypto::default();
            let scheme = SignatureScheme::ED25519;
            let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
            let pk = SignaturePublicKey::try_from(pub_b).unwrap();
            let cwk = CredentialWithKey {
                credential: BasicCredential::new(user.as_bytes().to_vec()).into(),
                signature_key: pk,
            };
            (
                TestSigner {
                    key: priv_b,
                    scheme,
                },
                cwk,
                provider,
            )
        }

        fn keypackage(
            signer: &TestSigner,
            cwk: &CredentialWithKey,
            provider: &OpenMlsRustCrypto,
        ) -> KeyPackage {
            KeyPackage::builder()
                .build(AES, provider, signer, cwk.clone())
                .unwrap()
                .key_package()
                .clone()
        }

        fn welcome_in(out: MlsMessageOut) -> Welcome {
            let bytes = out.tls_serialize_detached().unwrap();
            match MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
                .unwrap()
                .extract()
            {
                MlsMessageBodyIn::Welcome(w) => w,
                other => panic!("expected a Welcome, got {other:?}"),
            }
        }

        fn protocol_in(out: MlsMessageOut) -> ProtocolMessage {
            let bytes = out.tls_serialize_detached().unwrap();
            let msg_in = MlsMessageIn::tls_deserialize(&mut bytes.as_slice()).unwrap();
            ProtocolMessage::try_from(msg_in).unwrap()
        }

        fn group_info_in(out: MlsMessageOut) -> VerifiableGroupInfo {
            let bytes = out.tls_serialize_detached().unwrap();
            match MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
                .unwrap()
                .extract()
            {
                MlsMessageBodyIn::GroupInfo(gi) => gi,
                other => panic!("expected a GroupInfo, got {other:?}"),
            }
        }

        /// The v1 stand-in for `emulator_epoch_secret = SafeExportSecret(virtual_clients_component_id)`
        /// (see the module-doc divergence note above this test module).
        fn emulator_epoch_secret(group: &MlsGroup, crypto: &impl OpenMlsCrypto) -> Vec<u8> {
            group
                .export_secret(crypto, EMULATOR_EPOCH_SECRET_LABEL, &[], 32)
                .unwrap()
        }

        #[test]
        fn two_emulator_clients_derive_identical_epoch_secrets_from_a_real_emulation_group() {
            // alice + bob are two emulator clients jointly emulating ONE virtual client (§5.1) - an
            // ordinary 2-member MLS group at the mechanism level.
            let (asig, acwk, aprov) = ident("alice-emulator-1");
            let (bsig, bcwk, bprov) = ident("alice-emulator-2");
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(AES)
                .use_ratchet_tree_extension(true)
                .build();
            let mut alice = MlsGroup::new(&aprov, &asig, &cfg, acwk).unwrap();
            let bob_kp = keypackage(&bsig, &bcwk, &bprov);
            let (_c, welcome, _gi) = alice.add_members(&aprov, &asig, &[bob_kp]).unwrap();
            alice.merge_pending_commit(&aprov).unwrap();
            let welcome = welcome_in(welcome);
            let bob = StagedWelcome::new_from_welcome(&bprov, cfg.join_config(), welcome, None)
                .unwrap()
                .into_group(&bprov)
                .unwrap();

            let alice_input = emulator_epoch_secret(&alice, aprov.crypto());
            let bob_input = emulator_epoch_secret(&bob, bprov.crypto());
            assert_eq!(
                alice_input, bob_input,
                "both emulator clients must derive the SAME emulator_epoch_secret from the shared epoch"
            );

            let alice_secrets = derive_epoch_secrets(aprov.crypto(), AES, &alice_input).unwrap();
            let bob_secrets = derive_epoch_secrets(bprov.crypto(), AES, &bob_input).unwrap();
            assert_eq!(alice_secrets.epoch_id, bob_secrets.epoch_id);
            assert_eq!(
                alice_secrets.epoch_base_secret,
                bob_secrets.epoch_base_secret
            );
            assert_eq!(
                alice_secrets.epoch_encryption_key,
                bob_secrets.epoch_encryption_key
            );
            assert_eq!(
                alice_secrets.generation_id_secret,
                bob_secrets.generation_id_secret
            );
            assert_eq!(
                alice_secrets.reuse_guard_secret,
                bob_secrets.reuse_guard_secret
            );

            // And the reuse_guard mechanism now works end-to-end between two REAL, independently-held
            // openmls group states, not just two calls in the same process over synthetic secrets.
            let nonce = [9u8, 9, 9, 9];
            let rg_alice = compute_reuse_guard(
                aprov.crypto(),
                AES,
                &alice_secrets.reuse_guard_secret,
                &nonce,
                0,
                2,
            )
            .unwrap();
            let recovered = recover_sender_leaf_index(
                bprov.crypto(),
                AES,
                &bob_secrets.reuse_guard_secret,
                &nonce,
                &rg_alice,
                2,
            )
            .unwrap();
            assert_eq!(
                recovered, 0,
                "bob recovers alice's real leaf index from her reuse_guard"
            );
        }

        #[test]
        fn removal_of_an_emulator_client_advances_the_epoch_and_all_derived_secrets_change() {
            // §6.3: "Commit a Remove proposal for the emulation client to be removed in the emulation
            // group, advancing it to a new epoch from which new virtual client secrets will be derived."
            // This is an ORDINARY in-group MLS Remove - no external operation involved.
            let (asig, acwk, aprov) = ident("alice-emulator-1");
            let (bsig, bcwk, bprov) = ident("alice-emulator-2");
            let (csig, ccwk, cprov) = ident("alice-emulator-3-to-be-removed");
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(AES)
                .use_ratchet_tree_extension(true)
                .build();
            let mut alice = MlsGroup::new(&aprov, &asig, &cfg, acwk).unwrap();
            let bob_kp = keypackage(&bsig, &bcwk, &bprov);
            let carol_kp = keypackage(&csig, &ccwk, &cprov);
            let (_c, welcome, _gi) = alice
                .add_members(&aprov, &asig, &[bob_kp, carol_kp])
                .unwrap();
            alice.merge_pending_commit(&aprov).unwrap();
            let welcome = welcome_in(welcome);
            let mut bob =
                StagedWelcome::new_from_welcome(&bprov, cfg.join_config(), welcome.clone(), None)
                    .unwrap()
                    .into_group(&bprov)
                    .unwrap();
            // carol joins too, only so she has a real leaf to be removed from (never used after removal).
            let mut carol =
                StagedWelcome::new_from_welcome(&cprov, cfg.join_config(), welcome, None)
                    .unwrap()
                    .into_group(&cprov)
                    .unwrap();
            let _ = &mut carol; // carol's group is discarded post-removal, matching the real protocol.

            let pre_removal_secrets = derive_epoch_secrets(
                aprov.crypto(),
                AES,
                &emulator_epoch_secret(&alice, aprov.crypto()),
            )
            .unwrap();

            // alice commits a Remove for carol's leaf index.
            let carol_leaf = bob
                .members()
                .find(|m| m.credential.serialized_content() == b"alice-emulator-3-to-be-removed")
                .expect("carol must be a member before removal")
                .index;
            let (commit, _w, _gi) = alice.remove_members(&aprov, &asig, &[carol_leaf]).unwrap();
            alice.merge_pending_commit(&aprov).unwrap();

            let commit_in = protocol_in(commit);
            let processed = bob.process_message(&bprov, commit_in).unwrap();
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    bob.merge_staged_commit(&bprov, *staged).unwrap();
                }
                other => panic!("expected a staged commit, got {other:?}"),
            }

            let post_removal_alice = derive_epoch_secrets(
                aprov.crypto(),
                AES,
                &emulator_epoch_secret(&alice, aprov.crypto()),
            )
            .unwrap();
            let post_removal_bob = derive_epoch_secrets(
                bprov.crypto(),
                AES,
                &emulator_epoch_secret(&bob, bprov.crypto()),
            )
            .unwrap();

            // Remaining members (alice, bob) still agree post-removal...
            assert_eq!(post_removal_alice.epoch_id, post_removal_bob.epoch_id);
            assert_eq!(
                post_removal_alice.reuse_guard_secret,
                post_removal_bob.reuse_guard_secret
            );
            // ...and the new epoch's secrets differ from the pre-removal epoch (advancement proven).
            assert_ne!(pre_removal_secrets.epoch_id, post_removal_alice.epoch_id);
            assert_ne!(
                pre_removal_secrets.reuse_guard_secret,
                post_removal_alice.reuse_guard_secret
            );
        }

        #[test]
        fn a_new_emulator_client_joining_externally_shares_the_emulation_groups_epoch_state() {
            // §6.2: a new emulator client with no online sibling to bootstrap from performs an external
            // commit into the emulation group. Per this module's INV-MLS-001a scope note, "dave" here is
            // a new, legitimate device of the SAME virtual client (alice's sibling emulator), never a
            // foreign/untrusted party - the trust relationship §7.1 of the draft describes.
            let (asig, acwk, aprov) = ident("alice-emulator-1");
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(AES)
                .use_ratchet_tree_extension(true)
                .build();
            let alice = MlsGroup::new(&aprov, &asig, &cfg, acwk).unwrap();

            let (dsig, dcwk, dprov) = ident("alice-emulator-2-joining-externally");
            let group_info = group_info_in(
                alice
                    .export_group_info(aprov.crypto(), &asig, true)
                    .unwrap(),
            );

            let (mut dave, commit_bundle) = ExternalCommitBuilder::new()
                .with_config(cfg.join_config().clone())
                .build_group(&dprov, group_info, dcwk)
                .unwrap()
                .leaf_node_parameters(LeafNodeParameters::default())
                .load_psks(dprov.storage())
                .unwrap()
                .build(dprov.rand(), dprov.crypto(), &dsig, |_| true)
                .unwrap()
                .finalize(&dprov)
                .unwrap();
            let (commit_out, _welcome, _group_info) = commit_bundle.into_contents();
            dave.merge_pending_commit(&dprov).unwrap();

            // alice processes dave's external-commit message to stay in sync.
            let mut alice = alice;
            let commit_in = protocol_in(commit_out);
            let processed = alice.process_message(&aprov, commit_in).unwrap();
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    alice.merge_staged_commit(&aprov, *staged).unwrap();
                }
                other => panic!("expected a staged commit, got {other:?}"),
            }

            // Both now derive IDENTICAL virtual-client secrets from the post-join epoch - dave (onboarded
            // via §6.2) shares the emulation group's state exactly as alice does.
            let alice_secrets = derive_epoch_secrets(
                aprov.crypto(),
                AES,
                &emulator_epoch_secret(&alice, aprov.crypto()),
            )
            .unwrap();
            let dave_secrets = derive_epoch_secrets(
                dprov.crypto(),
                AES,
                &emulator_epoch_secret(&dave, dprov.crypto()),
            )
            .unwrap();
            assert_eq!(alice_secrets.epoch_id, dave_secrets.epoch_id);
            assert_eq!(
                alice_secrets.reuse_guard_secret,
                dave_secrets.reuse_guard_secret
            );
        }
    }
}
