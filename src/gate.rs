//! The accept-gate for MLS objects that arrive from another provider.
//!
//! A MIMI provider takes KeyPackages, Welcomes and GroupInfos whose ciphersuite the sender chose. openmls follows the
//! suite on the wire: a self-consistent Welcome in any suite the crypto provider implements opens through that suite's
//! HPKE and AEAD, and `KeyPackageIn::validate()` verifies a signature under whatever scheme the KeyPackage names. A
//! deployment decides which suites it accepts; this module refuses every other suite **before** the bytes reach a
//! decoder or openmls, by reading the suite from its fixed wire position first. Each gate takes the accepted suites as a
//! list; [`default_mls_ciphersuites`] is every suite the crate's crypto provider implements.
//!
//! The module also holds the `identifierQuery` answer shape (one not-found for every miss, protocol-07 §5.8 and
//! DIVERGENCES DIV-4) and the KeyPackageRef the other modules key KeyPackages and Welcomes by.
//!
//! ## Joins
//! MIMI has two ways into a room on another provider: §5.2 keyMaterial (an existing member fetches the joiner's
//! KeyPackage, then Add and Welcome) and §5.6 groupInfo (the joiner fetches the room's GroupInfo and joins by external
//! commit). This crate implements the first. Serving a GroupInfo and accepting an external commit are not built yet
//! (DIVERGENCES DIV-1); when they are, a room's policy decides whether it takes one. [`mimi_gate_group_info`] gates a
//! GroupInfo's suite already, because a Commit bundle can carry one.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, RFC 9420's mandatory-to-implement suite, as its wire value.
pub const MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519: u16 = 0x0001;

/// Every ciphersuite the crate's crypto provider implements, as wire values in ascending order: what a gate accepts when
/// the deployment does not narrow it.
pub fn default_mls_ciphersuites() -> Vec<u16> {
    let mut suites: Vec<u16> = OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .into_iter()
        .map(u16::from)
        .collect();
    suites.sort_unstable();
    suites.dedup();
    suites
}

/// An object from another provider named a ciphersuite outside the accepted list. Callers log and drop it; the bytes
/// never reach openmls.
#[derive(Debug)]
pub struct ForeignCiphersuite {
    pub got: u16,
    /// The suites that would have been accepted.
    pub accepted: Vec<u16>,
}

impl std::fmt::Display for ForeignCiphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let accepted: Vec<String> = self
            .accepted
            .iter()
            .map(|suite| format!("0x{suite:04x}"))
            .collect();
        write!(
            f,
            "refusing an MLS object with ciphersuite 0x{:04x}; accepted: {}",
            self.got,
            accepted.join(", ")
        )
    }
}

/// Refuse `got` unless it is in `accepted`.
fn refuse_unless_accepted(got: u16, accepted: &[u16]) -> Result<(), GateError> {
    if accepted.contains(&got) {
        return Ok(());
    }
    Err(ForeignCiphersuite {
        got,
        accepted: accepted.to_vec(),
    }
    .into())
}

impl std::error::Error for ForeignCiphersuite {}

/// Typed errors for the accept-gates + ref derivation (`thiserror` per-module enum -
/// the library convention). The load-bearing [`ForeignCiphersuite`] refusal is surfaced transparently.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// An object from another provider named a ciphersuite outside the accepted list.
    #[error(transparent)]
    ForeignCiphersuite(#[from] ForeignCiphersuite),
    /// A KeyPackage could not be TLS-deserialized.
    #[error("undecodable KeyPackage: {0}")]
    UndecodableKeyPackage(String),
    /// A KeyPackage failed openmls validation (signature/structure) - no AEAD is instantiated.
    #[error("KeyPackage failed validation: {0}")]
    KeyPackageValidation(String),
    /// Computing the canonical `KeyPackageRef` (`hash_ref`) failed.
    #[error("KeyPackageRef hash failed: {0}")]
    HashRef(String),
    /// An `MlsMessage` (expected to carry a Welcome) could not be TLS-deserialized.
    #[error("undecodable MlsMessage: {0}")]
    UndecodableMlsMessage(String),
    /// The `MlsMessage` body was not a `Welcome`.
    #[error("MlsMessage body is not a Welcome")]
    NotAWelcome,
    /// Re-serializing the `Welcome` (to read its leading ciphersuite `u16`) failed.
    #[error("Welcome re-serialize failed: {0}")]
    WelcomeReserialize(String),
    /// The `Welcome` was too short to carry a ciphersuite.
    #[error("Welcome too short to carry a ciphersuite")]
    WelcomeTooShort,
    /// Bytes remained after a deserializer consumed one object -- a well-formed object plus
    /// trailer must be rejected, not silently accepted as if only the leading object mattered
    /// (Note: `valid_keypackage || 0xEE` must not pass the gate).
    #[error("{n} trailing byte(s) after {what}")]
    TrailingBytes { what: &'static str, n: usize },
    /// A `GroupInfo` (Full representation) could not be TLS-deserialized.
    #[error("undecodable GroupInfo: {0}")]
    UndecodableGroupInfo(String),
    /// A bare `Welcome` could not be TLS-deserialized.
    #[error("undecodable Welcome: {0}")]
    UndecodableWelcome(String),
}

/// `KeyPackageIn::tls_deserialize` can PANIC (not just return `Err`) on certain malformed
/// nested-length-prefix input -- an internal tls_codec assertion, confirmed empirically against a
/// different call site using the same underlying deserializer. The pinned tls_codec 0.5 still
/// debug-asserts when a length-prefixed byte string runs past the end of its input. Every gate
/// here runs on peer-controlled bytes, so catch_unwind turns a hostile/malformed KeyPackage into a decode
/// error instead of an unhandled panic in the request task, matching this crate's "hostile
/// input must never panic" discipline (see content.rs's module doc).
fn deserialize_keypackage_in_no_panic(
    key_package_bytes: &[u8],
) -> Result<(KeyPackageIn, usize), GateError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut slice = key_package_bytes;
        KeyPackageIn::tls_deserialize(&mut slice)
            .map(|kp| (kp, key_package_bytes.len() - slice.len()))
    }))
    .map_err(|_| GateError::UndecodableKeyPackage("decoder panicked".into()))?
    .map_err(|e| GateError::UndecodableKeyPackage(format!("{e:?}")))
}

/// The ciphersuite a serialized KeyPackage names, read from its fixed wire position without decoding anything else.
///
/// RFC 9420 §10.1: `struct { ProtocolVersion version; CipherSuite cipher_suite; ... } KeyPackageTBS`, so the suite is the
/// big-endian `u16` at bytes 2..4. Reading it here lets a foreign suite be refused before any structure is parsed and before
/// any signature is verified, so no suite-specific arithmetic runs on a peer's bytes.
fn keypackage_wire_suite(key_package_bytes: &[u8]) -> Result<u16, GateError> {
    key_package_bytes
        .get(2..4)
        .map(|suite| u16::from_be_bytes([suite[0], suite[1]]))
        .ok_or_else(|| GateError::UndecodableKeyPackage("too short to carry a ciphersuite".into()))
}

/// Refuse a KeyPackage whose wire suite is not in `accepted`, before it is decoded or verified.
fn refuse_foreign_keypackage_suite(
    key_package_bytes: &[u8],
    accepted: &[u16],
) -> Result<(), GateError> {
    refuse_unless_accepted(keypackage_wire_suite(key_package_bytes)?, accepted)
}

/// **K5 accept-gate - KeyPackage.** Call BEFORE `add_member` on any KeyPackage fetched from another provider (§5.2
/// keyMaterial). Returns `Ok(())` only for a suite in `accepted`.
///
/// Mechanism: read the suite from the KeyPackage's fixed wire position and refuse one outside `accepted` first; only
/// then deserialize and `validate()` (signature-only; this does NOT instantiate any AEAD) and confirm the validated suite
/// is the one the bytes named. Refusing first means a KeyPackage in a suite outside the list reaches neither signature
/// verification nor `add_member`'s HPKE-seal: the only signature schemes ever verified on a peer's KeyPackage are those
/// of the accepted suites.
pub fn mimi_gate_keypackage(key_package_bytes: &[u8], accepted: &[u16]) -> Result<(), GateError> {
    refuse_foreign_keypackage_suite(key_package_bytes, accepted)?;
    let provider = OpenMlsRustCrypto::default();
    let (kp_in, consumed) = deserialize_keypackage_in_no_panic(key_package_bytes)?;
    if consumed != key_package_bytes.len() {
        return Err(GateError::TrailingBytes {
            what: "KeyPackage",
            n: key_package_bytes.len() - consumed,
        });
    }
    let validated = kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| GateError::KeyPackageValidation(format!("{e:?}")))?;
    refuse_unless_accepted(u16::from(validated.ciphersuite()), accepted)
}

/// The credential in a KeyPackage's leaf and the leaf's signature key, after the checks [`mimi_gate_keypackage`] makes:
/// an accepted ciphersuite, no trailing bytes, a valid signature. Whatever its type: how a credential names a user is the
/// caller's reading, and some credentials name one only for a key they authorize.
pub fn keypackage_credential(
    key_package_bytes: &[u8],
    accepted: &[u16],
) -> Result<CredentialWithKey, GateError> {
    refuse_foreign_keypackage_suite(key_package_bytes, accepted)?;
    let provider = OpenMlsRustCrypto::default();
    let (kp_in, consumed) = deserialize_keypackage_in_no_panic(key_package_bytes)?;
    if consumed != key_package_bytes.len() {
        return Err(GateError::TrailingBytes {
            what: "KeyPackage",
            n: key_package_bytes.len() - consumed,
        });
    }
    let validated = kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| GateError::KeyPackageValidation(format!("{e:?}")))?;
    refuse_unless_accepted(u16::from(validated.ciphersuite()), accepted)?;
    Ok(CredentialWithKey {
        credential: validated.leaf_node().credential().clone(),
        signature_key: validated.leaf_node().signature_key().clone(),
    })
}

/// The identity in a KeyPackage's basic credential, after the checks [`keypackage_credential`] makes. A KeyPackage whose
/// leaf carries another credential type has no basic identity and is refused.
pub fn keypackage_basic_identity(
    key_package_bytes: &[u8],
    accepted: &[u16],
) -> Result<Vec<u8>, GateError> {
    let credential = keypackage_credential(key_package_bytes, accepted)?.credential;
    let basic = BasicCredential::try_from(credential).map_err(|_| {
        GateError::KeyPackageValidation("the leaf carries no basic credential".into())
    })?;
    Ok(basic.identity().to_vec())
}

/// Whether a KeyPackage meets what a `KeyMaterialRequest` asks of it (protocol-07 §5.2): its ciphersuite is one of
/// `acceptable` (any, when the list is empty), and its leaf supports every extension, proposal and credential type
/// `required` names. RFC 9420 §7.2: the default extension types (1-5) and proposal types (1-7) are supported without
/// being listed; a credential type is supported only when listed. A KeyPackage that does not decode or validate meets
/// nothing.
pub fn keypackage_meets(
    key_package_bytes: &[u8],
    acceptable: &[Ciphersuite],
    required: &RequiredCapabilitiesExtension,
) -> bool {
    let Ok((kp_in, consumed)) = deserialize_keypackage_in_no_panic(key_package_bytes) else {
        return false;
    };
    if consumed != key_package_bytes.len() {
        return false;
    }
    let provider = OpenMlsRustCrypto::default();
    let Ok(key_package) = kp_in.validate(provider.crypto(), ProtocolVersion::Mls10) else {
        return false;
    };
    if !acceptable.is_empty() && !acceptable.contains(&key_package.ciphersuite()) {
        return false;
    }
    let capabilities = key_package.leaf_node().capabilities();
    let extensions_met = required.extension_types().iter().all(|wanted| {
        (1..=5).contains(&u16::from(*wanted)) || capabilities.extensions().contains(wanted)
    });
    let proposals_met = required.proposal_types().iter().all(|wanted| {
        (1..=7).contains(&u16::from(*wanted)) || capabilities.proposals().contains(wanted)
    });
    let credentials_met = required
        .credential_types()
        .iter()
        .all(|wanted| capabilities.credentials().contains(wanted));
    extensions_met && proposals_met && credentials_met
}

/// The Welcome at the start of `bytes` (an `MLSMessage`, which may be followed by more, as in a §5.5 `FanoutMessage`'s
/// tail): its own bytes, and the `KeyPackageRef` of each new member its secrets are for (RFC 9420 §12.4.3.1). A provider
/// that keeps which KeyPackage it published for which user finds the Welcome's recipients this way.
pub fn welcome_new_members(bytes: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), GateError> {
    let (message, consumed) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut slice = bytes;
        MlsMessageIn::tls_deserialize(&mut slice)
            .map(|message| (message, bytes.len() - slice.len()))
    }))
    .map_err(|_| GateError::UndecodableMlsMessage("decoder panicked".into()))?
    .map_err(|e| GateError::UndecodableMlsMessage(format!("{e:?}")))?;
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(GateError::NotAWelcome);
    };
    let members = welcome
        .secrets()
        .iter()
        .map(|secret| secret.new_member().as_slice().to_vec())
        .collect();
    Ok((bytes[..consumed].to_vec(), members))
}

/// **K3/K4 routing key - canonical KeyPackageRef.** Compute the MLS `KeyPackageRef` (RFC 9420 §5.2,
/// `RefHash("MLS 1.0 KeyPackage Reference", KeyPackage)`) for a KeyPackage, via openmls so it is
/// BYTE-IDENTICAL to the ref a Welcome's `secrets[].new_member` carries. This is the stable handle the
/// two §5.2-para-16 association maps are keyed by: the hub associates it with the target *provider* (K3)
/// and the target provider associates it with the local *client* (K4).
///
/// Pure and portable: any MLS client can use the same ref computation. It refuses a wire suite outside `accepted` first,
/// as the gate does, then runs the same deserialize→`validate()` (signature-only, no AEAD) path and `hash_ref`. Callers
/// that store foreign objects still gate first (`mimi_gate_keypackage`); this derives the routing key over the object the
/// gate accepted, and cannot be used to verify a signature under a suite outside the list.
pub fn keypackage_ref(key_package_bytes: &[u8], accepted: &[u16]) -> Result<Vec<u8>, GateError> {
    refuse_foreign_keypackage_suite(key_package_bytes, accepted)?;
    let provider = OpenMlsRustCrypto::default();
    let (kp_in, consumed) = deserialize_keypackage_in_no_panic(key_package_bytes)?;
    if consumed != key_package_bytes.len() {
        return Err(GateError::TrailingBytes {
            what: "KeyPackage",
            n: key_package_bytes.len() - consumed,
        });
    }
    let validated = kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| GateError::KeyPackageValidation(format!("{e:?}")))?;
    let kpref = validated
        .hash_ref(provider.crypto())
        .map_err(|e| GateError::HashRef(format!("{e:?}")))?;
    Ok(kpref.as_slice().to_vec())
}

/// **K5 accept-gate - Welcome.** Call BEFORE `StagedWelcome::new_from_welcome` on any inbound Welcome from another
/// provider. Returns `Ok(())` only for a suite in `accepted`. Without this gate, an unvalidated Welcome in any suite the
/// crypto provider implements would reach and drive that suite's HPKE and AEAD.
///
/// Mechanism: deserialize the `MlsMessage`, extract the `Welcome`, and read its ciphersuite
/// from the wire. The gate re-serializes the `Welcome` and reads the leading `u16` rather than
/// calling `Welcome::ciphersuite()`, so it rests on the RFC 9420 layout and not on a library
/// accessor (the accessor was crate-private before openmls 0.9) - per RFC 9420 the
/// `Welcome` struct is `{ CipherSuite cipher_suite; EncryptedGroupSecrets secrets<V>; opaque
/// encrypted_group_info<V>; }`, so the first two bytes are the big-endian ciphersuite. The
/// test below pins this layout (accept 0x0001 / reject 0x0003) so an openmls wire change can't
/// silently defeat the gate.
pub fn mimi_gate_welcome(mls_message_bytes: &[u8], accepted: &[u16]) -> Result<(), GateError> {
    // Same tls_codec-internal panic risk as the KeyPackage gates above (peer-controlled bytes,
    // hostile input must never panic).
    let (msg, consumed) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut slice = mls_message_bytes;
        MlsMessageIn::tls_deserialize(&mut slice)
            .map(|msg| (msg, mls_message_bytes.len() - slice.len()))
    }))
    .map_err(|_| GateError::UndecodableMlsMessage("decoder panicked".into()))?
    .map_err(|e| GateError::UndecodableMlsMessage(format!("{e:?}")))?;
    if consumed != mls_message_bytes.len() {
        return Err(GateError::TrailingBytes {
            what: "MlsMessage",
            n: mls_message_bytes.len() - consumed,
        });
    }
    let welcome = match msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err(GateError::NotAWelcome),
    };
    let wire = welcome
        .tls_serialize_detached()
        .map_err(|e| GateError::WelcomeReserialize(format!("{e:?}")))?;
    if wire.len() < 2 {
        return Err(GateError::WelcomeTooShort);
    }
    refuse_unless_accepted(u16::from_be_bytes([wire[0], wire[1]]), accepted)
}

/// Refuse a bare `Welcome` whose ciphersuite is not in `accepted`, before it is decoded.
///
/// RFC 9420 §12.4.3.1: `struct { CipherSuite cipher_suite; EncryptedGroupSecrets secrets<V>; opaque encrypted_group_info<V>; }
/// Welcome`, so the suite is the big-endian `u16` at the front. Read first, a foreign-suite Welcome never reaches a decoder
/// or the HPKE-open path.
pub(crate) fn refuse_foreign_welcome_suite(
    welcome_bytes: &[u8],
    accepted: &[u16],
) -> Result<(), GateError> {
    let suite = welcome_bytes
        .get(..2)
        .map(|suite| u16::from_be_bytes([suite[0], suite[1]]))
        .ok_or(GateError::WelcomeTooShort)?;
    refuse_unless_accepted(suite, accepted)
}

/// **K5 accept-gate - bare Welcome.** The same refusal as [`mimi_gate_welcome`] for a `Welcome` that is not wrapped in an
/// `MLSMessage`, which is how §5.3's `HandshakeBundle` carries one. Refuses a foreign suite first, then requires the bytes
/// to be one `Welcome` and nothing after it.
pub fn mimi_gate_welcome_bare(welcome_bytes: &[u8], accepted: &[u16]) -> Result<(), GateError> {
    refuse_foreign_welcome_suite(welcome_bytes, accepted)?;
    let (_welcome, consumed) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut slice = welcome_bytes;
        Welcome::tls_deserialize(&mut slice).map(|w| (w, welcome_bytes.len() - slice.len()))
    }))
    .map_err(|_| GateError::UndecodableWelcome("decoder panicked".into()))?
    .map_err(|e| GateError::UndecodableWelcome(format!("{e:?}")))?;
    if consumed != welcome_bytes.len() {
        return Err(GateError::TrailingBytes {
            what: "Welcome",
            n: welcome_bytes.len() - consumed,
        });
    }
    Ok(())
}

/// **K5 accept-gate - GroupInfo (Full representation only).** Call BEFORE treating a `groupInfo`
/// (§5.6, or a Commit's Full-representation `groupInfoOption`) as viable join material. Returns
/// `Ok(())` only for a suite in `accepted`. This closes the same foreign-suite AEAD-reachability
/// class `mimi_gate_welcome` closes for Welcome, on a second live path:
/// `join_by_external_commit` derives its HPKE parameters from the GroupInfo's ciphersuite,
/// which a remote peer chooses.
///
/// Mechanism: `openmls::messages::group_info::VerifiableGroupInfo` derives `TlsDeserialize`
/// unconditionally (not behind a feature flag) and exposes `ciphersuite()` as the unverified
/// value read straight off the wire, the same "read before verify" order `mimi_gate_welcome`
/// uses for a Welcome. Only the `Full` representation is decodable this way; a `Partial` one
/// (`PartialGroupInfo`, ratchet-tree-options §4) carries no ciphersuite, so it cannot be gated
/// here: it becomes a GroupInfo only when its receiver rebuilds it from the group it tracks
/// (`crate::partial_group_info`), and callers must not treat an ungated `Partial` payload as
/// trusted join material.
pub fn mimi_gate_group_info(group_info_bytes: &[u8], accepted: &[u16]) -> Result<(), GateError> {
    use openmls::messages::group_info::VerifiableGroupInfo;

    let (info, consumed) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut slice = group_info_bytes;
        VerifiableGroupInfo::tls_deserialize(&mut slice)
            .map(|info| (info, group_info_bytes.len() - slice.len()))
    }))
    .map_err(|_| GateError::UndecodableGroupInfo("decoder panicked".into()))?
    .map_err(|e| GateError::UndecodableGroupInfo(format!("{e:?}")))?;
    if consumed != group_info_bytes.len() {
        return Err(GateError::TrailingBytes {
            what: "GroupInfo",
            n: group_info_bytes.len() - consumed,
        });
    }
    refuse_unless_accepted(u16::from(info.ciphersuite()), accepted)
}

// ===========================================================================
// Provider ingest logic - pure, testable, foreign-input-facing.
// These are the security-critical decision functions, separated from the HTTP transport
// and the durable persistence behind the storage traits. Built as traits + in-mem impls
// so the logic is pinned by tests now, and the real DB-backed store drops in later
// without changing the decision logic.
// ===========================================================================

/// Result of a MIMI `identifierQuery` (protocol-07 §5.8). `NotFound` is the one answer for every user the provider
/// does not answer for, whether the user does not exist or exists outside what the provider's discovery setting lets
/// it name, so the answer never says which.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentifierQueryResult {
    /// The provider answers for this user.
    Found,
    /// The provider does not answer for this user. Callers send one response for every case behind it.
    NotFound,
}

/// The `identifierQuery` answer. `answerable` is whether the provider's discovery setting lets it name this user; the
/// function takes only that bit, never whether the user exists, so the answer cannot depend on existence beyond it.
pub const fn identifier_query(answerable: bool) -> IdentifierQueryResult {
    if answerable {
        IdentifierQueryResult::Found
    } else {
        IdentifierQueryResult::NotFound
    }
}

#[cfg(test)]
#[path = "gate_suite_order_tests.rs"]
mod suite_order_tests;

#[cfg(test)]
#[path = "gate_capability_tests.rs"]
mod capability_tests;
#[cfg(test)]
#[path = "gate_grease_tests.rs"]
mod grease_tests;

// NOTE: the one-time KeyPackage store, /notify dedup, and enrollment state are DURABLE (SQLite),
// held by the consuming service - there is intentionally NO in-memory store type here (no residue).
// mimi-core is pure stateless logic: the gates above, `identifier_query`, and the content codec.

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::ciphersuite::signature::SignaturePublicKey;
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls_traits::signatures::{Signer, SignerError};

    /// Local test signer (self-contained - keeps this module independent of simple.rs).
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

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn lifetime(now_secs: u64) -> Lifetime {
        serde_json::from_value(serde_json::json!({
            "not_before": now_secs.saturating_sub(3600),
            "not_after": now_secs + 60 * 60 * 24 * 84,
        }))
        .unwrap()
    }

    /// Build (key_package_bytes, signer, credential, provider) under an arbitrary suite.
    fn ident(
        user: &str,
        suite: Ciphersuite,
    ) -> (Vec<u8>, TestSigner, CredentialWithKey, OpenMlsRustCrypto) {
        let provider = OpenMlsRustCrypto::default();
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(user.as_bytes().to_vec()).into(),
            signature_key: pk,
        };
        let signer = TestSigner {
            key: priv_b,
            scheme,
        };
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime(now()))
            .build(suite, &provider, &signer, cwk.clone())
            .unwrap();
        let kp_bytes = kpb.key_package().tls_serialize_detached().unwrap();
        (kp_bytes, signer, cwk, provider)
    }

    const AES: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    /// The gates asked to accept 0x0001 only.
    const ONLY_AES: &[u16] = &[MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519];
    // A suite the gates below are asked not to accept.
    const CHACHA: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    #[test]
    fn keypackage_gate_accepts_pinned_rejects_foreign() {
        let (kp_aes, _, _, _) = ident("alice_aes", AES);
        let (kp_cc, _, _, _) = ident("alice_cc", CHACHA);
        assert!(
            mimi_gate_keypackage(&kp_aes, ONLY_AES).is_ok(),
            "0x0001 KeyPackage must pass the accept-gate"
        );
        let err = mimi_gate_keypackage(&kp_cc, ONLY_AES).unwrap_err();
        assert!(
            err.to_string().contains("0x0003"),
            "0x0003 KeyPackage must be refused by the accept-gate, got: {err}"
        );
    }

    /// With no narrower list a deployment accepts every suite the crypto provider implements, and that list is what
    /// the provider reports, in order.
    #[test]
    fn the_default_list_is_every_suite_the_provider_implements() {
        let mut implemented: Vec<u16> = OpenMlsRustCrypto::default()
            .crypto()
            .supported_ciphersuites()
            .into_iter()
            .map(u16::from)
            .collect();
        implemented.sort_unstable();
        assert_eq!(default_mls_ciphersuites(), implemented);
        assert!(default_mls_ciphersuites().contains(&u16::from(CHACHA)));
    }

    /// The gate follows the list it is given: 0x0003 passes when it is listed, and a refusal names what was accepted.
    /// Revert check: compare with 0x0001 instead of the list, and the listed 0x0003 is refused.
    #[test]
    fn the_gate_accepts_exactly_the_suites_it_is_given() {
        let (kp_cc, _, _, _) = ident("carol_cc", CHACHA);
        assert!(
            mimi_gate_keypackage(&kp_cc, &[0x0001, 0x0003]).is_ok(),
            "PLANT-GATE-LIST: a listed suite is accepted"
        );
        assert!(mimi_gate_keypackage(&kp_cc, &default_mls_ciphersuites()).is_ok());
        let refused = mimi_gate_keypackage(&kp_cc, &[0x0001, 0x0002])
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("0x0003") && refused.contains("accepted: 0x0001, 0x0002"),
            "{refused}"
        );
    }

    #[test]
    fn keypackage_gate_rejects_trailing_bytes() {
        // A well-formed KeyPackage plus a trailing byte must not pass the gate.
        let (kp_aes, _, _, _) = ident("alice_aes", AES);
        let mut with_trailer = kp_aes.clone();
        with_trailer.push(0xEE);
        assert!(mimi_gate_keypackage(&with_trailer, ONLY_AES).is_err());
        assert!(keypackage_ref(&with_trailer, ONLY_AES).is_err());
    }

    #[test]
    fn keypackage_ref_is_deterministic_and_distinct() {
        let (kp_a, _, _, _) = ident("alice", AES);
        let (kp_b, _, _, _) = ident("bob", AES);
        let ref_a1 = keypackage_ref(&kp_a, ONLY_AES).unwrap();
        let ref_a2 = keypackage_ref(&kp_a, ONLY_AES).unwrap();
        let ref_b = keypackage_ref(&kp_b, ONLY_AES).unwrap();
        // SHA-256-based RefHash → 32 bytes for suite 0x0001.
        assert_eq!(
            ref_a1.len(),
            32,
            "KeyPackageRef is a 32-byte SHA-256 ref for 0x0001"
        );
        assert_eq!(
            ref_a1, ref_a2,
            "same KeyPackage bytes → same ref (stable association key)"
        );
        assert_ne!(
            ref_a1, ref_b,
            "distinct KeyPackages → distinct refs (no collision in routing key)"
        );
        // Tamper one byte → different ref (it really hashes the object, not a prefix).
        let mut tampered = kp_a.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01;
        // tampering breaks validation OR changes the ref - either way it is NOT the original ref.
        if let Ok(r) = keypackage_ref(&tampered, ONLY_AES) {
            assert_ne!(
                r, ref_a1,
                "a modified KeyPackage cannot map to the original's routing key"
            );
        }
        assert!(
            keypackage_ref(b"not a keypackage", ONLY_AES).is_err(),
            "garbage → error, never a bogus ref"
        );
    }

    /// Build a real Welcome (as MlsMessageOut bytes) under `suite` by creating a group and
    /// adding a freshly-built member - mirrors the cross-provider add we'd gate on receive.
    fn welcome_under(suite: Ciphersuite) -> Vec<u8> {
        // group creator (alice)
        let (_akp, asigner, acwk, aprov) = ident("alice", suite);
        let cfg = MlsGroupCreateConfig::builder().ciphersuite(suite).build();
        let mut group = MlsGroup::new(&aprov, &asigner, &cfg, acwk).unwrap();
        // member to add (bob), same suite
        let (bob_kp_bytes, _bsigner, _bcwk, _bprov) = ident("bob", suite);
        let mut s = bob_kp_bytes.as_slice();
        let bob_kp = KeyPackageIn::tls_deserialize(&mut s)
            .unwrap()
            .validate(aprov.crypto(), ProtocolVersion::Mls10)
            .unwrap();
        let (_commit, welcome, _gi) = group.add_members(&aprov, &asigner, &[bob_kp]).unwrap();
        group.merge_pending_commit(&aprov).unwrap();
        welcome.tls_serialize_detached().unwrap()
    }

    #[test]
    fn welcome_gate_accepts_pinned_rejects_foreign() {
        let w_aes = welcome_under(AES);
        let w_cc = welcome_under(CHACHA);
        assert!(
            mimi_gate_welcome(&w_aes, ONLY_AES).is_ok(),
            "0x0001 Welcome must pass the accept-gate"
        );
        let err = mimi_gate_welcome(&w_cc, ONLY_AES).unwrap_err();
        assert!(
            err.to_string().contains("0x0003"),
            "0x0003 Welcome must be refused BEFORE openmls processing (the OpenMlsRustCrypto ChaCha path), got: {err}"
        );
    }

    #[test]
    fn welcome_gate_rejects_trailing_bytes() {
        // Note: the same trailing-bytes class as the KeyPackage gate.
        let mut with_trailer = welcome_under(AES);
        with_trailer.push(0xEE);
        assert!(mimi_gate_welcome(&with_trailer, ONLY_AES).is_err());
    }

    /// Build a real GroupInfo (Full representation wire bytes) under `suite` by creating a group
    /// with `use_ratchet_tree_extension(true)` (the flag that makes `add_members` actually export
    /// one) and adding a freshly-built member.
    fn group_info_under(suite: Ciphersuite) -> Vec<u8> {
        let (_akp, asigner, acwk, aprov) = ident("alice", suite);
        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new(&aprov, &asigner, &cfg, acwk).unwrap();
        let (bob_kp_bytes, _bsigner, _bcwk, _bprov) = ident("bob", suite);
        let mut s = bob_kp_bytes.as_slice();
        let bob_kp = KeyPackageIn::tls_deserialize(&mut s)
            .unwrap()
            .validate(aprov.crypto(), ProtocolVersion::Mls10)
            .unwrap();
        let (_commit, _welcome, gi) = group.add_members(&aprov, &asigner, &[bob_kp]).unwrap();
        let gi = gi.expect("use_ratchet_tree_extension(true) must produce a GroupInfo");
        gi.tls_serialize_detached().unwrap()
    }

    #[test]
    fn group_info_gate_accepts_pinned_rejects_foreign() {
        let gi_aes = group_info_under(AES);
        let gi_cc = group_info_under(CHACHA);
        assert!(
            mimi_gate_group_info(&gi_aes, ONLY_AES).is_ok(),
            "0x0001 GroupInfo must pass the accept-gate"
        );
        let err = mimi_gate_group_info(&gi_cc, ONLY_AES).unwrap_err();
        assert!(
            err.to_string().contains("0x0003"),
            "0x0003 GroupInfo must be refused before any join_by_external_commit attempt, got: {err}"
        );
    }

    #[test]
    fn group_info_gate_rejects_trailing_bytes() {
        let mut with_trailer = group_info_under(AES);
        with_trailer.push(0xEE);
        assert!(mimi_gate_group_info(&with_trailer, ONLY_AES).is_err());
    }

    // --- hardening: the gate is the one security-load-bearing thing here, so it must
    //     fail CLOSED on every malformed / unexpected input, never panic. ---

    #[test]
    fn gates_fail_closed_on_garbage() {
        // The gate is the one security-load-bearing thing here: it must FAIL CLOSED on every
        // malformed / hostile / non-MLS input, and never panic.
        let garbage: [&[u8]; 5] = [
            b"",
            b"\x00",
            b"not an mls object at all",
            &[0xff; 64],
            &[0x00, 0x01, 0x02, 0x03, 0x04],
        ];
        for bad in garbage {
            assert!(
                mimi_gate_keypackage(bad, ONLY_AES).is_err(),
                "keypackage gate must reject garbage"
            );
            assert!(
                mimi_gate_welcome(bad, ONLY_AES).is_err(),
                "welcome gate must reject garbage"
            );
            assert!(
                mimi_gate_group_info(bad, ONLY_AES).is_err(),
                "group_info gate must reject garbage"
            );
        }
    }

    #[test]
    fn welcome_gate_rejects_wrong_message_type() {
        // A valid 0x0001 KeyPackage is NOT an MlsMessage/Welcome envelope; the welcome gate must
        // refuse it (covers the `_ => Err` arm) rather than mis-read bytes as a ciphersuite.
        let kp = ident("wrongtype", AES).0;
        assert!(
            mimi_gate_welcome(&kp, ONLY_AES).is_err(),
            "welcome gate must refuse non-Welcome bytes"
        );
    }

    // --- provider ingest logic ---

    #[test]
    fn identifier_query_is_optin_only_and_leak_free() {
        // DIV-4: only opt-in enrollees are Found; the NON-enrolled case is identical whether the
        // account exists or not (the function can't even see existence - only enrollment).
        assert_eq!(identifier_query(true), IdentifierQueryResult::Found);
        assert_eq!(identifier_query(false), IdentifierQueryResult::NotFound);
        // The leak-freedom property, stated as a test: an existing-but-not-enrolled account and a
        // non-existent account both map to the SAME input (is_mimi_enrolled=false) → SAME output.
        let existing_not_enrolled = identifier_query(false);
        let does_not_exist = identifier_query(false);
        assert_eq!(
            existing_not_enrolled, does_not_exist,
            "non-enrolled-but-real MUST be indistinguishable from non-existent"
        );
    }

    // (The one-time KeyPackage store + /notify dedup tests live with their DURABLE SQLite impl in
    // the consuming service - claim-once/expiry/byte-exact-dedup are asserted against real SQLite.)
}
