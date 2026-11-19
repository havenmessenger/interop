//! The signature on a `KeyMaterialRequest` (protocol-07 §5.2):
//!
//! ```text
//! key_material_request_signature = SignWithLabel(requesterSignatureKey,
//!                       "KeyMaterialRequestTBS", KeyMaterialRequestTBS)
//! ```
//!
//! `KeyMaterialRequestTBS` is every field of the request before the signature, in order; `SignWithLabel` is RFC 9420
//! §5.1.2's, over `SignContent { "MLS 1.0 " + label, content }`. A requester signs with the key whose public half it
//! names in `requesterSignatureKey`, so a provider can check the request was made by the holder of that key, and that
//! the key's credential names the user the request is made for.

use openmls::prelude::SignatureScheme;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto as _;
use openmls_traits::signatures::Signer;
use openmls_traits::OpenMlsProvider as _;
use tls_codec::{Serialize as _, Size as _, VLBytes};

use crate::protocol_wire::{KeyMaterialRequest, WireError};

const LABEL: &[u8] = b"MLS 1.0 KeyMaterialRequestTBS";

impl KeyMaterialRequest {
    /// `KeyMaterialRequestTBS`: the encoded request without its trailing signature.
    pub fn to_be_signed(&self) -> Result<Vec<u8>, WireError> {
        let mut whole = self.encode()?;
        let signature_len =
            VLBytes::new(self.key_material_request_signature.clone()).tls_serialized_len();
        whole.truncate(whole.len() - signature_len);
        Ok(whole)
    }

    /// The bytes `SignWithLabel` signs: `SignContent { label, content }`.
    fn sign_content(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        for field in [LABEL.to_vec(), self.to_be_signed()?] {
            VLBytes::new(field)
                .tls_serialize(&mut out)
                .map_err(|error| WireError::Codec {
                    what: "SignContent",
                    detail: error.to_string(),
                })?;
        }
        Ok(out)
    }

    /// Set `key_material_request_signature` by signing with `signer`, whose public half is `requesterSignatureKey`.
    pub fn sign(&mut self, signer: &impl Signer) -> Result<(), WireError> {
        self.key_material_request_signature =
            signer
                .sign(&self.sign_content()?)
                .map_err(|error| WireError::Codec {
                    what: "key_material_request_signature",
                    detail: format!("{error:?}"),
                })?;
        Ok(())
    }

    /// Whether `key_material_request_signature` verifies under `requesterSignatureKey` (Ed25519, the scheme of every
    /// ciphersuite this crate accepts).
    pub fn signature_verifies(&self) -> bool {
        let Ok(content) = self.sign_content() else {
            return false;
        };
        OpenMlsRustCrypto::default()
            .crypto()
            .verify_signature(
                SignatureScheme::ED25519,
                &content,
                self.requester_signature_key.as_slice(),
                &self.key_material_request_signature,
            )
            .is_ok()
    }
}

#[cfg(test)]
#[path = "key_material_signature_tests.rs"]
mod tests;
