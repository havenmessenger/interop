//! mimi-bot's own MLS client identity: a signing keypair + `BasicCredential` whose identity bytes
//! are this bot's own `mimi://` URI (Haven's credential<->URI convention - see
//! `protocol_wire.rs::requester_credential_identity`'s doc in mimi-core), and the one real
//! `KeyPackage` construction path this daemon uses to publish itself.
//!
//! Deliberate simplification (disclosed, not silent - matches this repo's DIVERGENCES.md
//! convention): the signing keypair is regenerated fresh on every process start, and MLS group
//! state lives only in this process's memory (`OpenMlsRustCrypto`'s own storage backend is
//! `MemoryStorage` - the same backend `mimi-hubd`'s own tests use, not something this crate
//! downgrades from). A restart forgets any room mimi-bot had joined; the external tester simply
//! re-invites it. This is the right tradeoff for a disposable interop test partner (no message-
//! history or long-term-identity expectation), and avoids implementing a full durable
//! `openmls_traits::StorageProvider` (a large trait) under Vienna's timeline. If mimi-bot ever
//! needs to survive a restart with live rooms intact, that is a real follow-up, not this dispatch.

use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::{
    Ciphersuite, Extensions, KeyPackage, Lifetime, OpenMlsCrypto, SignatureScheme,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer as SignerTrait, SignerError};
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize as _;

/// Haven's pinned suite (INV-MLS-002) - the only ciphersuite mimi-bot generates or accepts,
/// same as every other component in this repo.
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// A minimal `openmls_traits::signatures::Signer` over a raw private key + scheme, the same shape
/// every test helper in this repo (`mimi-hubd`, `mimi-core`) already uses to sign with
/// `OpenMlsRustCrypto`'s crypto backend directly.
pub struct Signer {
    key: Vec<u8>,
    scheme: SignatureScheme,
}

impl SignerTrait for Signer {
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

/// mimi-bot's own MLS identity: the crypto provider (holds openmls's in-process key/group state -
/// see the module doc for why this is memory-only), the signer, and the credential this identity
/// presents in every KeyPackage/Commit/message it produces.
pub struct Identity {
    pub provider: OpenMlsRustCrypto,
    signer: Signer,
    credential: openmls::prelude::Credential,
    signature_key: SignaturePublicKey,
    /// Needed for self-echo loop prevention (a second gutcheck pass, once `submit_room_event`
    /// stopped excluding a caller-hinted sender - see `main.rs`): mimi-bot must recognize its OWN
    /// prior echo arriving back in its inbox and not reply to it, since it is now delivered a copy
    /// of everything it submits, same as any other room member.
    own_uri: String,
}

impl Identity {
    /// Generate a fresh signing identity for `own_uri` (mimi-bot's own `mimi://<domain>/u/<name>`).
    pub fn generate(own_uri: &str) -> anyhow::Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let scheme = SignatureScheme::ED25519;
        let (priv_key, pub_key) = provider
            .crypto()
            .signature_key_gen(scheme)
            .map_err(|e| anyhow::anyhow!("signature key generation failed: {e:?}"))?;
        let signature_key: SignaturePublicKey = pub_key.into();
        let credential = BasicCredential::new(own_uri.as_bytes().to_vec()).into();
        Ok(Self {
            provider,
            signer: Signer {
                key: priv_key,
                scheme,
            },
            credential,
            signature_key,
            own_uri: own_uri.to_string(),
        })
    }

    pub fn own_uri(&self) -> &str {
        &self.own_uri
    }

    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    pub fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.credential.clone(),
            signature_key: self.signature_key.clone(),
        }
    }

    /// Build one real, canonical 0x0001 KeyPackage for this identity and return its TLS-serialized
    /// bytes - exactly the body `POST /mimi/v1/keyMaterial/ingest?user=<bot_username>` expects
    /// (bare `KeyPackage` bytes, no `MlsMessage` envelope - confirmed against `mimi-provider`'s own
    /// `key_material`/`add_key_package` round-trip and `mimi-hubd`'s `real_keypackage` test helper).
    /// Each call consumes fresh key material (a KeyPackage is one-time by protocol design, K1/K2),
    /// so this is called once at startup and again on the republish cadence.
    pub fn fresh_key_package_bytes(&self, now_unix: u64) -> anyhow::Result<Vec<u8>> {
        let lifetime = Lifetime::new(60 * 60 * 24 * 84); // 84 days, matches this repo's other issuers
        let _ = now_unix; // Lifetime::new is relative-to-now internally; kept for call-site clarity
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(
                SUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key(),
            )
            .map_err(|e| anyhow::anyhow!("KeyPackage build failed: {e:?}"))?;
        kpb.key_package()
            .tls_serialize_detached()
            .map_err(|e| anyhow::anyhow!("KeyPackage serialize failed: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_real_keypackage_that_round_trips() {
        use openmls::prelude::KeyPackageIn;
        use tls_codec::Deserialize as _;

        let id = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();
        let bytes = id.fresh_key_package_bytes(0).unwrap();
        assert!(!bytes.is_empty());
        // A real, decodable 0x0001 KeyPackage - not a mock payload.
        let mut slice = bytes.as_slice();
        let kp_in =
            KeyPackageIn::tls_deserialize(&mut slice).expect("must decode as a KeyPackageIn");
        assert!(
            slice.is_empty(),
            "no trailing bytes after a full KeyPackage"
        );
        let validated = kp_in
            .validate(
                id.provider.crypto(),
                openmls::versions::ProtocolVersion::Mls10,
            )
            .expect("KeyPackage must pass openmls's own validation");
        assert_eq!(
            validated.ciphersuite(),
            SUITE,
            "must be the pinned 0x0001 suite"
        );
    }

    #[test]
    fn two_key_packages_from_the_same_identity_are_distinct() {
        // Each call consumes fresh HPKE init key material (K1/K2 one-time-use) - two calls must
        // not silently reuse the same bytes.
        let id = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();
        let a = id.fresh_key_package_bytes(0).unwrap();
        let b = id.fresh_key_package_bytes(0).unwrap();
        assert_ne!(
            a, b,
            "each published KeyPackage must use fresh key material"
        );
    }
}
