//! Files for seeding a hub with test state, used by `examples/seed_table.sh`.
//!
//! ```text
//! cargo run --example seed_fixtures -- keypackages <dir> <user-uri> <count>
//! cargo run --example seed_fixtures -- keymaterial-request <file> <requesting-user-uri> <target-user-uri>
//! cargo run --example seed_fixtures -- keymaterial-answer <file>
//! cargo run --example seed_fixtures -- identifier-request <file> <handle>
//! ```
//!
//! `keypackages` writes `<count>` KeyPackages to `<dir>/kp-NNN.bin`, each under ciphersuite 0x0001 with a
//! `BasicCredential` whose identity is the user URI: a hub that reads an `Add` takes that identity as the user the
//! client belongs to (DIVERGENCES.md, DIV-10). Every KeyPackage has its own keys, and the private halves are dropped
//! when this returns. Nobody can open a Welcome made for one of them, which is what a hub test needs and no more.
//!
//! `keymaterial-request` writes a protocol-07 §5.2 `KeyMaterialRequest` naming the two users, and
//! `keymaterial-answer` prints what a `KeyMaterialResponse` says in one word: `success`, `exhausted`, `denied` or
//! `other`. Together they ask a hub the question a peer provider asks, so a seeded consent grant can be checked on
//! the wire lane.
//!
//! `identifier-request` writes a §5.8 `IdentifierRequest` with one element, a search for `<handle>` as a handle.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use mimi_core::protocol_wire::{
    IdentifierRequest, KeyMaterialRequest, KeyMaterialResponse, QueryElement, SearchIdentifierType,
};
use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize as _;

type Failure = Box<dyn std::error::Error>;

/// How long a seeded KeyPackage is valid for. A hub keeps a published KeyPackage for its own time-to-live, which is
/// shorter.
const VALID_FOR_SECS: u64 = 60 * 60 * 24 * 84;

/// Signs with one key held in memory.
struct MemorySigner {
    key: Vec<u8>,
    scheme: SignatureScheme,
}

impl Signer for MemorySigner {
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

/// One KeyPackage for a client of `user_uri`, valid from an hour ago.
fn key_package(user_uri: &str, now: u64) -> Result<Vec<u8>, Failure> {
    let provider = OpenMlsRustCrypto::default();
    let scheme = SignatureScheme::ED25519;
    let (private_key, public_key) = provider.crypto().signature_key_gen(scheme)?;
    let credential = CredentialWithKey {
        credential: BasicCredential::new(user_uri.as_bytes().to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let bundle = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .key_package_lifetime(Lifetime::init(
            now.saturating_sub(3600),
            now + VALID_FOR_SECS,
        ))
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            &provider,
            &MemorySigner {
                key: private_key,
                scheme,
            },
            credential,
        )?;
    Ok(bundle.key_package().tls_serialize_detached()?)
}

fn write_key_packages(dir: &str, user_uri: &str, count: &str) -> Result<(), Failure> {
    let count: usize = count.parse()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    std::fs::create_dir_all(dir)?;
    for n in 1..=count {
        let path = Path::new(dir).join(format!("kp-{n:03}.bin"));
        std::fs::write(path, key_package(user_uri, now)?)?;
    }
    Ok(())
}

fn write_key_material_request(file: &str, requesting: &str, target: &str) -> Result<(), Failure> {
    let request = KeyMaterialRequest::minimal(requesting, target)?.encode()?;
    std::fs::write(file, request)?;
    Ok(())
}

fn say_key_material_answer(file: &str) -> Result<(), Failure> {
    let word = match KeyMaterialResponse::decode(&std::fs::read(file)?)? {
        KeyMaterialResponse::Success { .. } => "success",
        KeyMaterialResponse::Exhausted { .. } => "exhausted",
        KeyMaterialResponse::Denied { .. } => "denied",
        KeyMaterialResponse::Clients { .. } => "other",
    };
    println!("{word}");
    Ok(())
}

fn write_identifier_request(file: &str, handle: &str) -> Result<(), Failure> {
    let request = IdentifierRequest {
        query_elements: vec![QueryElement {
            search_type: SearchIdentifierType::Handle,
            qualifier: Vec::new(),
            search_value: handle.as_bytes().to_vec(),
        }],
    };
    std::fs::write(file, request.encode()?)?;
    Ok(())
}

fn main() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["keypackages", dir, user_uri, count] => write_key_packages(dir, user_uri, count),
        ["keymaterial-request", file, requesting, target] => {
            write_key_material_request(file, requesting, target)
        }
        ["keymaterial-answer", file] => say_key_material_answer(file),
        ["identifier-request", file, handle] => write_identifier_request(file, handle),
        _ => Err("usage: seed_fixtures keypackages <dir> <user-uri> <count> \
                  | keymaterial-request <file> <requesting-user-uri> <target-user-uri> \
                  | keymaterial-answer <file> \
                  | identifier-request <file> <handle>"
            .into()),
    }
}
