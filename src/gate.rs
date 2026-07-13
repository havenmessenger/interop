//! MIMI provider seam - the foreign-input accept-gate for cross-provider MLS objects.
//!
//! This module is a plain, dependency-free Rust boundary for MIMI (Messaging
//! Interoperability) provider work (`INV-MIMI-003`). It carries no binding-layer
//! integration and cannot be reached from Haven's own client-to-client MLS path, which
//! stays on its existing wire format regardless of anything here.
//!
//! ## What lives here
//! The ciphersuite accept-gate (`INV-MLS-002` accept-clause, conformance row K5), the
//! `identifierQuery` no-existence-oracle (DIV-4), and the KeyPackageRef/client correlation
//! this crate's other modules build on.
//!
//! ## Why the gate is load-bearing
//! Haven's real receive path **follows the wire's ciphersuite**: a
//! self-consistent suite-`0x0003` Welcome opens via `process_welcome`, driving the libcrux
//! ChaCha20-Poly1305 HPKE-open path (RUSTSEC-2026-0124, HIGH 8.2, panic-on-overlong, blocked
//! upstream). `KeyPackageIn::validate()` is suite-agnostic too. Native chat is safe ONLY
//! because we never *hold* a `0x0003` KeyPackage + openmls rejects cross-suite Adds - neither
//! protection applies to a MIMI path that ingests **foreign** objects whose suite the *remote*
//! chooses. So a MIMI provider MUST hard-reject any non-`0x0001` object **before** handing
//! bytes to openmls. That is `mimi_gate_keypackage` / `mimi_gate_welcome` below.
//!
//! ## MIMI join model vs INV-MLS-001a (successor of INV-MLS-001)
//! MIMI has two cross-provider join flows:
//!   - **§5.2 keyMaterial** → inviter fetches the remote KeyPackage → **Add + Welcome**.
//!     This is Haven's existing *add-driven* model - INV-MLS-001a-COMPATIBLE.
//!   - **§5.6 claim-group-key (GroupInfo)** → recipient self-joins via **external commit**.
//!     `openmls::MlsGroup::export_group_info(crypto, signer, ..)` signs GroupInfo with an
//!     ordinary member signer (no `ExternalSendersExtension` needed - so *producing* it calls
//!     no external-op API), BUT the exported GroupInfo embeds an `ExternalPub` extension whose
//!     sole purpose is to let the recipient call `join_by_external_commit`. That join IS the
//!     external-commit mechanism `INV-MLS-001a` closes (ETK, eprint 2025/229).
//!
//! **Design decision:** cross-provider joins use the **§5.2 KeyPackage+Welcome path only**.
//! The §5.6 GroupInfo-join is **permanently out, both lanes**. A provider can serve the
//! add-driven flow conformantly without implementing every optional join mechanism. This keeps
//! INV-MLS-001a
//! intact (no `export_group_info` / `join_by_external_commit` is called anywhere in this crate).
//! This is a two-sided, permanent posture - not a v1 scoping note - because the ETK concern
//! (eprint 2025/229) doesn't change with implementation effort.
//!
//! **External *proposals* are a separate mechanism, governed by its own invariant,
//! `INV-MLS-001b`** - RFC 9420 `Sender::External`,
//! validated against a group's `ExternalSendersExtension`, is cryptographically inert until an
//! existing member commits it, a materially smaller risk than an external commit). Unlike
//! external commits, this mechanism is NOT permanently banned in the mimi lane: a narrow,
//! pre-configured, `Remove`-only, explicit-inclusion-only acceptance path is designed, but not
//! yet implemented, as a later, separately gated piece of work with its own policy seam rather
//! than a hand-rolled check here. This module's own posture is unaffected today: nothing here
//! constructs, validates-and-acts-on, or exposes an API for `Sender::External` proposals, in
//! either lane.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

/// The single MLS ciphersuite Haven pins, as the u16 wire value (`INV-MLS-002`).
/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
pub const HAVEN_MLS_CIPHERSUITE_U16: u16 = 0x0001;

/// Error returned when a foreign MIMI object carries a non-pinned ciphersuite.
/// Surfaced as the explicit accept-gate refusal so callers can log + drop without
/// ever passing the bytes to openmls' AEAD/HPKE path.
#[derive(Debug)]
pub struct ForeignCiphersuite {
    pub got: u16,
}

impl std::fmt::Display for ForeignCiphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "INV-MLS-002 accept-gate: refusing MIMI object with ciphersuite 0x{:04x} (only 0x{:04x} accepted)",
            self.got, HAVEN_MLS_CIPHERSUITE_U16
        )
    }
}

impl std::error::Error for ForeignCiphersuite {}

/// Typed errors for the accept-gates + ref derivation (`thiserror` per-module enum -
/// the library convention). The load-bearing [`ForeignCiphersuite`] refusal is surfaced transparently.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// A foreign MIMI object carried a non-pinned ciphersuite (INV-MLS-002 accept-gate refusal).
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
}

/// `KeyPackageIn::tls_deserialize` can PANIC (not just return `Err`) on certain malformed
/// nested-length-prefix input -- an internal tls_codec 0.4.2 assertion, confirmed empirically
/// against a different call site using the same underlying deserializer. Every gate here runs
/// on peer-controlled bytes, so catch_unwind turns a hostile/malformed KeyPackage into a decode
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

/// **K5 accept-gate - KeyPackage.** Call BEFORE `add_member` on any KeyPackage fetched from a
/// foreign provider (MIMI §5.2 keyMaterial). Returns `Ok(())` only for the pinned suite.
///
/// Mechanism: deserialize → `validate()` (signature-only; this does NOT instantiate any AEAD,
/// so validating a foreign KeyPackage cannot trip the libcrux panic) →
/// read the validated `ciphersuite()` → refuse if it is not `0x0001`. Refusing HERE means the
/// foreign KeyPackage never reaches `add_member`'s HPKE-seal (where ChaCha would be driven).
pub fn mimi_gate_keypackage(key_package_bytes: &[u8]) -> Result<(), GateError> {
    let provider = OpenMlsRustCrypto::default();
    let (kp_in, consumed) = deserialize_keypackage_in_no_panic(key_package_bytes)?;
    if consumed != key_package_bytes.len() {
        return Err(GateError::TrailingBytes {
            what: "KeyPackage",
            n: key_package_bytes.len() - consumed,
        });
    }
    // validate() is signature-only (no AEAD) - safe to run on a foreign-suite object.
    let validated = kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| GateError::KeyPackageValidation(format!("{e:?}")))?;
    let suite = u16::from(validated.ciphersuite());
    if suite != HAVEN_MLS_CIPHERSUITE_U16 {
        return Err(ForeignCiphersuite { got: suite }.into());
    }
    Ok(())
}

/// **K3/K4 routing key - canonical KeyPackageRef.** Compute the MLS `KeyPackageRef` (RFC 9420 §5.2,
/// `RefHash("MLS 1.0 KeyPackage Reference", KeyPackage)`) for a KeyPackage, via openmls so it is
/// BYTE-IDENTICAL to the ref a Welcome's `secrets[].new_member` carries. This is the stable handle the
/// two §5.2-para-16 association maps are keyed by: the hub associates it with the target *provider* (K3)
/// and the target provider associates it with the local *client* (K4).
///
/// Pure + portable: production Haven MLS can reuse the same ref computation. Runs the same
/// deserialize→`validate()` (signature-only, no AEAD) path as the gate, then `hash_ref`. NOT a suite
/// gate - callers that store foreign objects gate first (`mimi_gate_keypackage`); this only derives the
/// routing key over the already-validated object.
pub fn keypackage_ref(key_package_bytes: &[u8]) -> Result<Vec<u8>, GateError> {
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

/// **K5 accept-gate - Welcome.** Call BEFORE `StagedWelcome::new_from_welcome` on any inbound
/// Welcome from a foreign provider (we are being added cross-provider). Returns `Ok(())` only
/// for the pinned suite. Without this gate, an unvalidated foreign-suite Welcome would reach
/// and drive openmls's libcrux ChaCha implementation.
///
/// Mechanism: deserialize the `MlsMessage`, extract the `Welcome`, and read its ciphersuite
/// from the wire. `Welcome::ciphersuite()` is `pub(crate)` in openmls 0.8.1 (not callable from
/// our crate), so we re-serialize the `Welcome` and read the leading `u16` - per RFC 9420 the
/// `Welcome` struct is `{ CipherSuite cipher_suite; EncryptedGroupSecrets secrets<V>; opaque
/// encrypted_group_info<V>; }`, so the first two bytes are the big-endian ciphersuite. The
/// test below pins this layout (accept 0x0001 / reject 0x0003) so an openmls wire change can't
/// silently defeat the gate.
pub fn mimi_gate_welcome(mls_message_bytes: &[u8]) -> Result<(), GateError> {
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
    let suite = u16::from_be_bytes([wire[0], wire[1]]);
    if suite != HAVEN_MLS_CIPHERSUITE_U16 {
        return Err(ForeignCiphersuite { got: suite }.into());
    }
    Ok(())
}

/// **K5 accept-gate - GroupInfo (Full representation only).** Call BEFORE treating a `groupInfo`
/// (§5.6, or a Commit's Full-representation `groupInfoOption`) as viable join material. Returns
/// `Ok(())` only for the pinned suite. This closes the same libcrux-reachability class
/// `mimi_gate_welcome` closes for Welcome, on a second live path: `join_by_external_commit` derives
/// its HPKE parameters from the GroupInfo's ciphersuite, which a remote peer chooses.
///
/// Mechanism: `openmls::messages::group_info::VerifiableGroupInfo` derives `TlsDeserialize`
/// unconditionally (not behind a feature flag) and exposes `ciphersuite()` as the unverified
/// value read straight off the wire, the same "read before verify" order `mimi_gate_welcome`
/// uses for a Welcome. Only the `Full` representation is decodable this way; `Partial`
/// (`PartialGroupInfo`, the sibling delta-encoding draft) has no decoder in this crate or in
/// openmls's public surface, so it cannot be gated here - callers must not treat an ungated
/// `Partial` payload as trusted join material.
pub fn mimi_gate_group_info(group_info_bytes: &[u8]) -> Result<(), GateError> {
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
    let suite = u16::from(info.ciphersuite());
    if suite != HAVEN_MLS_CIPHERSUITE_U16 {
        return Err(ForeignCiphersuite { got: suite }.into());
    }
    Ok(())
}

// ===========================================================================
// Gated newtypes - move the accept-gate from a per-call-site convention into the type
// system. Each type's only public constructor runs the corresponding `mimi_gate_*` check;
// a struct field typed as one of these cannot be populated with foreign wire bytes that
// skipped the gate, because there is no public way to construct the value otherwise. The
// `pub(crate)` trusted constructor exists for the encode side, which builds these from
// this crate's own already-suite-pinned local objects, never from foreign wire input.
// ===========================================================================

/// A KeyPackage that has passed [`mimi_gate_keypackage`]. The only public way to obtain one
/// from untrusted bytes is [`GatedKeyPackage::from_gated_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedKeyPackage(Vec<u8>);

impl GatedKeyPackage {
    /// Runs the K5 accept-gate before returning `Ok`. The only public constructor.
    pub fn from_gated_bytes(key_package_bytes: &[u8]) -> Result<Self, GateError> {
        mimi_gate_keypackage(key_package_bytes)?;
        Ok(Self(key_package_bytes.to_vec()))
    }

    /// Test-fixture construction that skips the gate - builds a round-trip or adversarial
    /// fixture from bytes that may deliberately fail `from_gated_bytes` (a foreign-suite
    /// object, to prove the DECODE-side gate rejects it). No non-test code anywhere in this
    /// crate or its workspace members constructs a `GatedKeyPackage` this way: even the
    /// reference hub binary (a separate crate, so it cannot see a `pub(crate)` item) calls
    /// the public gate-running constructor on its own already-published KeyPackage bytes.
    #[cfg(test)]
    pub(crate) fn trusted(key_package_bytes: Vec<u8>) -> Self {
        Self(key_package_bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// An `MlsMessage`-wrapped Welcome that has passed [`mimi_gate_welcome`]. The only public
/// way to obtain one from untrusted bytes is [`GatedWelcome::from_gated_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedWelcome(Vec<u8>);

impl GatedWelcome {
    /// Runs the K5 accept-gate before returning `Ok`. The only public constructor.
    pub fn from_gated_bytes(mls_message_bytes: &[u8]) -> Result<Self, GateError> {
        mimi_gate_welcome(mls_message_bytes)?;
        Ok(Self(mls_message_bytes.to_vec()))
    }

    /// Test-fixture construction that skips the gate - see [`GatedKeyPackage::trusted`]'s
    /// doc for why this is test-only.
    #[cfg(test)]
    pub(crate) fn trusted(mls_message_bytes: Vec<u8>) -> Self {
        Self(mls_message_bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A `GroupInfo` (Full representation) that has passed [`mimi_gate_group_info`]. The only
/// public way to obtain one from untrusted bytes is [`GatedGroupInfo::from_gated_bytes`].
/// `Partial` representation has no decoder anywhere in this crate or in openmls's public
/// surface (see `mimi_gate_group_info`'s own doc) and so has no constructor here either -
/// there is no way to gate a representation nothing can decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedGroupInfo(Vec<u8>);

impl GatedGroupInfo {
    /// Runs the K5 accept-gate before returning `Ok`. The only public constructor.
    pub fn from_gated_bytes(group_info_bytes: &[u8]) -> Result<Self, GateError> {
        mimi_gate_group_info(group_info_bytes)?;
        Ok(Self(group_info_bytes.to_vec()))
    }

    /// Test-fixture construction that skips the gate - see [`GatedKeyPackage::trusted`]'s
    /// doc for why this is test-only.
    #[cfg(test)]
    pub(crate) fn trusted(group_info_bytes: Vec<u8>) -> Self {
        Self(group_info_bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A consent grant's `clientKeyPackages` (§5.7), individually accept-gated. The only public ways
/// to obtain one from untrusted bytes are [`GatedKeyPackages::from_gated_bytes_vec`] (all-or-
/// nothing: the whole batch fails if any element fails the gate) and the `serde`
/// `Deserialize` impl below, which runs the same gate on every element during deserialization -
/// `serde_json::from_slice::<crate::consent::ConsentEntry>(attacker_json)` can no longer
/// construct an entry carrying an un-suite-checked KeyPackage, closing the class
/// `HandshakeBundle`'s Welcome/GroupInfo fields already close via `GatedWelcome`/
/// `GatedGroupInfo`. Deliberately does NOT derive `Serialize`/`Deserialize` on
/// [`GatedKeyPackage`] itself - that would reopen the same hole on that type instead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GatedKeyPackages(Vec<GatedKeyPackage>);

impl GatedKeyPackages {
    /// Gates every element; fails on the first ungated one.
    pub fn from_gated_bytes_vec(raw: Vec<Vec<u8>>) -> Result<Self, GateError> {
        raw.iter()
            .map(|bytes| GatedKeyPackage::from_gated_bytes(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// Test-fixture construction that skips the gate - see [`GatedKeyPackage::trusted`]'s doc
    /// for why this is test-only.
    #[cfg(test)]
    pub(crate) fn trusted(raw: Vec<Vec<u8>>) -> Self {
        Self(raw.into_iter().map(GatedKeyPackage::trusted).collect())
    }

    pub fn as_slice(&self) -> &[GatedKeyPackage] {
        &self.0
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }
}

/// Bundle already-gated elements. Safe unconditionally: each `GatedKeyPackage` was already
/// gated at its own construction (there is no other way to obtain one), so collecting them into
/// a batch adds no new ungated bytes.
impl From<Vec<GatedKeyPackage>> for GatedKeyPackages {
    fn from(gated: Vec<GatedKeyPackage>) -> Self {
        Self(gated)
    }
}

impl serde::Serialize for GatedKeyPackages {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw: Vec<&[u8]> = self.0.iter().map(GatedKeyPackage::as_slice).collect();
        raw.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for GatedKeyPackages {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: Vec<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
        Self::from_gated_bytes_vec(raw).map_err(serde::de::Error::custom)
    }
}

// ===========================================================================
// Provider ingest logic - pure, testable, foreign-input-facing.
// These are the security-critical decision functions, separated from the HTTP transport
// and the durable persistence behind the storage traits. Built as traits + in-mem impls
// so the logic is pinned by tests now, and the real DB-backed store drops in later
// without changing the decision logic.
// ===========================================================================

/// Result of a MIMI `identifierQuery` (§5.7 / DIV-4). The privacy-critical contract:
/// `NotFound` is returned for BOTH "no such account" AND "account exists but has not opted into
/// MIMI" - they MUST be indistinguishable, so a query can never reveal the existence of a
/// non-enrolled Haven user. Only opt-in (Standards-Testing-Page) enrollees are ever `Found`.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentifierQueryResult {
    /// The identifier belongs to a MIMI-opted-in account; safe to expose for federation.
    Found,
    /// Either non-existent OR existent-but-not-opted-in. Caller MUST emit an identical response
    /// for both - do not branch the wire response on which it was.
    NotFound,
}

/// DIV-4 opt-in-only identifierQuery. `is_mimi_enrolled` is true ONLY for accounts that opted in
/// via the Standards Testing Page (which also gates send + portal - INV-MIMI-001). The function
/// deliberately takes ONLY the enrollment bit, never an "account exists" bit, so it is structurally
/// impossible to leak existence of a non-enrolled account: the answer depends solely on enrollment.
pub const fn identifier_query(is_mimi_enrolled: bool) -> IdentifierQueryResult {
    if is_mimi_enrolled {
        IdentifierQueryResult::Found
    } else {
        IdentifierQueryResult::NotFound
    }
}

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
    // INV-MLS-002-ALLOW: test-only foreign suite for the accept-gate (never a prod path).
    const CHACHA: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519; // INV-MLS-002-ALLOW (test-only)

    #[test]
    fn keypackage_gate_accepts_pinned_rejects_foreign() {
        let (kp_aes, _, _, _) = ident("alice_aes", AES);
        let (kp_cc, _, _, _) = ident("alice_cc", CHACHA);
        assert!(
            mimi_gate_keypackage(&kp_aes).is_ok(),
            "0x0001 KeyPackage must pass the accept-gate"
        );
        let err = mimi_gate_keypackage(&kp_cc).unwrap_err();
        assert!(
            err.to_string().contains("0x0003"),
            "0x0003 KeyPackage must be refused by the accept-gate, got: {err}"
        );
    }

    #[test]
    fn keypackage_gate_rejects_trailing_bytes() {
        // A well-formed KeyPackage plus a trailing byte must not pass the gate.
        let (kp_aes, _, _, _) = ident("alice_aes", AES);
        let mut with_trailer = kp_aes.clone();
        with_trailer.push(0xEE);
        assert!(mimi_gate_keypackage(&with_trailer).is_err());
        assert!(keypackage_ref(&with_trailer).is_err());
    }

    #[test]
    fn keypackage_ref_is_deterministic_and_distinct() {
        let (kp_a, _, _, _) = ident("alice", AES);
        let (kp_b, _, _, _) = ident("bob", AES);
        let ref_a1 = keypackage_ref(&kp_a).unwrap();
        let ref_a2 = keypackage_ref(&kp_a).unwrap();
        let ref_b = keypackage_ref(&kp_b).unwrap();
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
        if let Ok(r) = keypackage_ref(&tampered) {
            assert_ne!(
                r, ref_a1,
                "a modified KeyPackage cannot map to the original's routing key"
            );
        }
        assert!(
            keypackage_ref(b"not a keypackage").is_err(),
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
            mimi_gate_welcome(&w_aes).is_ok(),
            "0x0001 Welcome must pass the accept-gate"
        );
        let err = mimi_gate_welcome(&w_cc).unwrap_err();
        assert!(
            err.to_string().contains("0x0003"),
            "0x0003 Welcome must be refused BEFORE openmls processing (the libcrux ChaCha path), got: {err}"
        );
    }

    #[test]
    fn welcome_gate_rejects_trailing_bytes() {
        // Note: the same trailing-bytes class as the KeyPackage gate.
        let mut with_trailer = welcome_under(AES);
        with_trailer.push(0xEE);
        assert!(mimi_gate_welcome(&with_trailer).is_err());
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
            mimi_gate_group_info(&gi_aes).is_ok(),
            "0x0001 GroupInfo must pass the accept-gate"
        );
        let err = mimi_gate_group_info(&gi_cc).unwrap_err();
        assert!(
            err.to_string().contains("0x0003"),
            "0x0003 GroupInfo must be refused before any join_by_external_commit attempt, got: {err}"
        );
    }

    #[test]
    fn group_info_gate_rejects_trailing_bytes() {
        let mut with_trailer = group_info_under(AES);
        with_trailer.push(0xEE);
        assert!(mimi_gate_group_info(&with_trailer).is_err());
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
                mimi_gate_keypackage(bad).is_err(),
                "keypackage gate must reject garbage"
            );
            assert!(
                mimi_gate_welcome(bad).is_err(),
                "welcome gate must reject garbage"
            );
            assert!(
                mimi_gate_group_info(bad).is_err(),
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
            mimi_gate_welcome(&kp).is_err(),
            "welcome gate must refuse non-Welcome bytes"
        );
    }

    // --- Gated newtypes: the only-public-ctor-runs-the-gate property ---

    #[test]
    fn gated_keypackage_accepts_pinned_rejects_foreign() {
        let (kp_aes, _, _, _) = ident("alice_aes", AES);
        let (kp_cc, _, _, _) = ident("alice_cc", CHACHA);
        let gated = GatedKeyPackage::from_gated_bytes(&kp_aes).expect("pinned suite must gate");
        assert_eq!(gated.as_slice(), kp_aes.as_slice());
        let err = GatedKeyPackage::from_gated_bytes(&kp_cc).unwrap_err();
        assert!(err.to_string().contains("0x0003"));
    }

    #[test]
    fn gated_welcome_accepts_pinned_rejects_foreign() {
        let w_aes = welcome_under(AES);
        let w_cc = welcome_under(CHACHA);
        let gated = GatedWelcome::from_gated_bytes(&w_aes).expect("pinned suite must gate");
        assert_eq!(gated.as_slice(), w_aes.as_slice());
        let err = GatedWelcome::from_gated_bytes(&w_cc).unwrap_err();
        assert!(err.to_string().contains("0x0003"));
    }

    #[test]
    fn gated_group_info_accepts_pinned_rejects_foreign() {
        let gi_aes = group_info_under(AES);
        let gi_cc = group_info_under(CHACHA);
        let gated = GatedGroupInfo::from_gated_bytes(&gi_aes).expect("pinned suite must gate");
        assert_eq!(gated.as_slice(), gi_aes.as_slice());
        let err = GatedGroupInfo::from_gated_bytes(&gi_cc).unwrap_err();
        assert!(err.to_string().contains("0x0003"));
    }

    #[test]
    fn gated_newtypes_reject_garbage() {
        assert!(GatedKeyPackage::from_gated_bytes(b"not a keypackage").is_err());
        assert!(GatedWelcome::from_gated_bytes(b"not a welcome").is_err());
        assert!(GatedGroupInfo::from_gated_bytes(b"not a group info").is_err());
    }

    #[test]
    fn gated_trusted_ctor_bypasses_the_gate_for_local_objects() {
        // The encode-side escape hatch: a foreign-suite object is never legitimately what this
        // crate encodes locally, but `trusted` exists precisely because the encode side builds
        // from already-suite-pinned local objects rather than re-running the gate on its own
        // output - proven here by constructing a Gated* from bytes that would fail the public
        // ctor, showing `trusted` genuinely skips the check rather than silently re-deriving it.
        let (kp_cc, _, _, _) = ident("would_fail_the_gate", CHACHA);
        assert!(GatedKeyPackage::from_gated_bytes(&kp_cc).is_err());
        let trusted = GatedKeyPackage::trusted(kp_cc.clone());
        assert_eq!(trusted.into_bytes(), kp_cc);
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
