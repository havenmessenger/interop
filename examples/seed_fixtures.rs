//! Files for seeding a hub with test state, used by `examples/seed_table.sh`.
//!
//! ```text
//! cargo run --example seed_fixtures -- keypackages <dir> <user-uri> <count> [<component-id>,... [<safe-aad-id>,...]]
//! cargo run --example seed_fixtures -- keymaterial-request <file> <requesting-user-uri> <target-user-uri>
//! cargo run --example seed_fixtures -- keymaterial-answer <file>
//! cargo run --example seed_fixtures -- identifier-request <file> <handle>
//! ```
//!
//! `keypackages` writes `<count>` KeyPackages to `<dir>/kp-NNN.bin`, each under ciphersuite 0x0001 with a
//! `BasicCredential` whose identity is the user URI: a hub that reads an `Add` takes that identity as the user the
//! client belongs to (DIVERGENCES.md, DIV-10). Its leaf declares what a protocol-07 room requires of a member, so
//! a peer can add the client to one: its `app_components` names `app_components` and `participant_list`, or the
//! component ids given (hex, comma-separated), to which `app_components` is added when it is missing. A second list
//! names the components the client protects as safe AAD: it goes into the leaf's `safe_aad` entry
//! (draft-ietf-mls-extensions §5), which a room that requires safe AAD components reads. Every KeyPackage
//! has its own keys, and the private halves are dropped
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

/// `app_data_dictionary` (draft-ietf-mls-extensions §4.6): the extension a protocol-07 room's GroupContext carries.
const APP_DATA_DICTIONARY: u16 = 0x0006;
/// `app_components` (draft-ietf-mls-extensions §5): the component listing what a member supports.
const APP_COMPONENTS: u16 = 0x0001;
/// `safe_aad` (draft-ietf-mls-extensions §5): the component listing what a member protects as safe AAD.
const SAFE_AAD: u16 = 0x0002;
/// `participant_list` (draft-ietf-mimi-protocol §7.5): the component a protocol-07 room keeps its participants in.
const PARTICIPANT_LIST: u16 = 0x0022;

/// What a client must support to be added to a protocol-07 room: the `app_data_dictionary` extension, the
/// `AppDataUpdate` proposal that changes it, and the basic credential its own identity uses.
fn room_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]),
        Some(&[ExtensionType::Unknown(APP_DATA_DICTIONARY)]),
        // `AppDataUpdate` (draft-ietf-mls-extensions §4.7); this build of openmls names it only as a custom type.
        Some(&[ProposalType::Custom(0x0008)]),
        Some(&[CredentialType::Basic]),
    )
}

/// The components a client says it supports when none are given: `app_components` itself, which the extension makes
/// mandatory, and `participant_list`.
const DEFAULT_COMPONENTS: [u16; 2] = [APP_COMPONENTS, PARTICIPANT_LIST];

/// Component ids from a comma-separated list of hex values.
fn parse_ids(list: &str) -> Result<Vec<u16>, Failure> {
    let mut ids = Vec::new();
    for item in list
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let id = u16::from_str_radix(item.trim_start_matches("0x"), 16)?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Component ids for `app_components`, with `app_components` itself first when the list leaves it out.
fn parse_components(list: &str) -> Result<Vec<u16>, Failure> {
    let mut ids = vec![APP_COMPONENTS];
    for id in parse_ids(list)? {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// One `ComponentData` of the dictionary: a component id and a `ComponentsList` of ids as its data.
fn components_entry(component: u16, ids: &[u16]) -> Result<Vec<u8>, Failure> {
    let ids: Vec<u8> = ids.iter().flat_map(|id| id.to_be_bytes()).collect();
    let list = VLBytes::new(ids).tls_serialize_detached()?;
    Ok([
        component.to_be_bytes().to_vec(),
        VLBytes::new(list).tls_serialize_detached()?,
    ]
    .concat())
}

/// The leaf's `app_data_dictionary`: `app_components` naming the components this client supports and, when there are
/// any, `safe_aad` naming those it protects as safe AAD. The entries are in component-id order, as the dictionary
/// requires.
fn room_leaf_extensions(
    components: &[u16],
    safe_aad: &[u16],
) -> Result<Extensions<LeafNode>, Failure> {
    let mut component_data = components_entry(APP_COMPONENTS, components)?;
    if !safe_aad.is_empty() {
        component_data.extend(components_entry(SAFE_AAD, safe_aad)?);
    }
    let dictionary = VLBytes::new(component_data).tls_serialize_detached()?;
    Ok(Extensions::single(Extension::Unknown(
        APP_DATA_DICTIONARY,
        UnknownExtension(dictionary),
    ))?)
}

/// One KeyPackage for a client of `user_uri`, valid from an hour ago, able to join a protocol-07 room.
fn key_package(
    user_uri: &str,
    components: &[u16],
    safe_aad: &[u16],
    now: u64,
) -> Result<Vec<u8>, Failure> {
    let provider = OpenMlsRustCrypto::default();
    let scheme = SignatureScheme::ED25519;
    let (private_key, public_key) = provider.crypto().signature_key_gen(scheme)?;
    let credential = CredentialWithKey {
        credential: BasicCredential::new(user_uri.as_bytes().to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(room_capabilities())
        .leaf_node_extensions(room_leaf_extensions(components, safe_aad)?)
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

fn write_key_packages(
    dir: &str,
    user_uri: &str,
    count: &str,
    components: &[u16],
    safe_aad: &[u16],
) -> Result<(), Failure> {
    let count: usize = count.parse()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    std::fs::create_dir_all(dir)?;
    for n in 1..=count {
        let path = Path::new(dir).join(format!("kp-{n:03}.bin"));
        std::fs::write(path, key_package(user_uri, components, safe_aad, now)?)?;
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
        ["keypackages", dir, user_uri, count] => {
            write_key_packages(dir, user_uri, count, &DEFAULT_COMPONENTS, &[])
        }
        ["keypackages", dir, user_uri, count, components] => {
            write_key_packages(dir, user_uri, count, &parse_components(components)?, &[])
        }
        ["keypackages", dir, user_uri, count, components, safe_aad] => write_key_packages(
            dir,
            user_uri,
            count,
            &parse_components(components)?,
            &parse_ids(safe_aad)?,
        ),
        ["keymaterial-request", file, requesting, target] => {
            write_key_material_request(file, requesting, target)
        }
        ["keymaterial-answer", file] => say_key_material_answer(file),
        ["identifier-request", file, handle] => write_identifier_request(file, handle),
        _ => Err(
            "usage: seed_fixtures keypackages <dir> <user-uri> <count> [<component-id>,... [<safe-aad-id>,...]] \
                  | keymaterial-request <file> <requesting-user-uri> <target-user-uri> \
                  | keymaterial-answer <file> \
                  | identifier-request <file> <handle>"
                .into(),
        ),
    }
}
