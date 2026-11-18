//! The request bodies a peer probe sends to a MIMI hub, made fresh each time with real openmls objects:
//! `cargo run -p mimi-hubd --example probe_bodies -- <command> …`.
//!
//! A probe checks a live hub from outside, as another provider would: that it takes a message its peer submits as the
//! peer's own user, refuses one submitted as the hub's own user, and queues a Welcome a room's hub notifies for a
//! local user's KeyPackage. Each body is encoded here with the same `mimi_core::protocol_wire` types the hub decodes,
//! decoded back before it is written, and never reused, so a rerun is not mistaken for a replay.
//!
//! Commands (every body is written to `<out>`; nothing is printed but its length):
//! - `submit <sender> <out>`: a `SubmitMessageRequest` from `sender`, carrying a real MLS application message (the room
//!   is the request's path, not part of the body).
//! - `keypackage <user> <out>`: a ciphersuite 0x0001 KeyPackage whose credential names `user`.
//! - `notify-welcome <keypackage-file> <out>`: the `FanoutMessage` a room's hub sends with the Welcome that adds the
//!   KeyPackage's holder to a new group.
//!
//! `unwrap`/`panic` are fine here (a command-line example, not the library): the crate's own `unwrap_used`/`panic`
//! clippy lints apply to the `--lib --bins` surface only.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::time::{SystemTime, UNIX_EPOCH};

use mimi_core::protocol_wire::{
    FanoutMessage, IdentifierUri, SubmitMessageRequest, PROTOCOL_MLS10,
};
use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _};

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// A KeyPackage lifetime: from an hour ago, so a clock a little behind the hub's still accepts it, for 84 days.
const NOT_BEFORE_SLACK_SECS: u64 = 60 * 60;
const LIFETIME_SECS: u64 = 60 * 60 * 24 * 84;

struct MemorySigner(Vec<u8>);

impl Signer for MemorySigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        OpenMlsRustCrypto::default()
            .crypto()
            .sign(SignatureScheme::ED25519, payload, &self.0)
            .map_err(|_| SignerError::SigningError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// A new client with its own signing key and a credential naming `identity`.
fn client(identity: &[u8]) -> (OpenMlsRustCrypto, MemorySigner, CredentialWithKey) {
    let provider = OpenMlsRustCrypto::default();
    let (private, public) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity.to_vec()).into(),
        signature_key: SignaturePublicKey::from(public),
    };
    (provider, MemorySigner(private), credential)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A `SubmitMessageRequest` from `sender`: a real MLS application message from a one-member group of its own.
fn submit(sender: &str) -> Vec<u8> {
    let (provider, signer, credential) = client(sender.as_bytes());
    let config = MlsGroupCreateConfig::builder().ciphersuite(SUITE).build();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let app_message = group
        .create_message(&provider, &signer, b"peer probe")
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let body = SubmitMessageRequest {
        protocol: PROTOCOL_MLS10,
        app_message,
        sending_uri: IdentifierUri(sender.into()),
    }
    .encode()
    .unwrap();
    let decoded = SubmitMessageRequest::decode(&body).unwrap();
    assert_eq!(decoded.sending_uri.0, sender, "the body names its sender");
    body
}

/// A ciphersuite 0x0001 KeyPackage whose credential names `user`.
fn keypackage(user: &str) -> Vec<u8> {
    let (provider, signer, credential) = client(user.as_bytes());
    let now = now_unix();
    let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
        "not_before": now.saturating_sub(NOT_BEFORE_SLACK_SECS),
        "not_after": now + LIFETIME_SECS,
    }))
    .unwrap();
    let bundle = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .key_package_lifetime(lifetime)
        .build(SUITE, &provider, &signer, credential)
        .unwrap();
    let bytes = bundle.key_package().tls_serialize_detached().unwrap();
    KeyPackageIn::tls_deserialize_exact(bytes.as_slice()).unwrap();
    bytes
}

/// The `FanoutMessage` a room's hub notifies with: the Welcome that adds the holder of `key_package` to a new group of
/// another provider's member.
fn notify_welcome(key_package: &[u8]) -> Vec<u8> {
    let (provider, signer, credential) = client(b"mimi://probe.invalid/u/carol");
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let key_package = KeyPackageIn::tls_deserialize_exact(key_package)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let (_commit, welcome, _group_info) = group
        .add_members(&provider, &signer, &[key_package])
        .unwrap();
    let body = FanoutMessage {
        protocol: PROTOCOL_MLS10,
        timestamp: now_unix(),
        message_and_tail: welcome.tls_serialize_detached().unwrap(),
    }
    .encode()
    .unwrap();
    FanoutMessage::decode(&body).unwrap();
    body
}

fn write(out: &str, body: &[u8]) {
    std::fs::write(out, body).unwrap_or_else(|e| panic!("writing {out}: {e}"));
    println!("{} bytes", body.len());
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["submit", sender, out] => write(out, &submit(sender)),
        ["keypackage", user, out] => write(out, &keypackage(user)),
        ["notify-welcome", key_package, out] => {
            let key_package =
                std::fs::read(key_package).unwrap_or_else(|e| panic!("reading {key_package}: {e}"));
            write(out, &notify_welcome(&key_package));
        }
        _ => {
            eprintln!(
                "usage: probe_bodies submit <sender> <out> | keypackage <user> <out> | \
                 notify-welcome <keypackage-file> <out>"
            );
            std::process::exit(64);
        }
    }
}
