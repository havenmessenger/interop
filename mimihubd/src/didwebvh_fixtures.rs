//! did:webvh logs for the hub's tests: written by the `mls-didwebvh` crate's controller where it can, and, for what it
//! does not write (a `portable` DID and a move to another domain), by [`PortableLog`] here, following did:webvh v1.0's
//! entry construction as that controller does. Every log is checked by `mls_didwebvh::verify_credential` before it is
//! handed out, so a test never runs on a log the crate would refuse.

use mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mls_didwebvh::{DidWebvhCredential, PublicKey};
use openmls::prelude::{Credential, CredentialType};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::credential::DID_WEBVH;

/// An MLS credential of the `did_webvh` type this hub reads, carrying `credential`.
pub(crate) fn mls_credential(credential: &DidWebvhCredential) -> Credential {
    Credential::new(
        CredentialType::Other(DID_WEBVH.credential_type()),
        credential.encode().unwrap(),
    )
}

/// A one-entry log at `example.com/<path>` authorizing `devices`, naming `also_known_as`, written by the crate's
/// controller under an update key from `seed`.
pub(crate) fn log(path: &str, seed: u8, devices: &[PublicKey], also_known_as: &[&str]) -> DidLog {
    let key = UpdateKey::from_seed(&[seed; 32]);
    DidLog::create_also_known_as(
        "example.com",
        path,
        "2026-11-26T10:00:00Z",
        &Parameters {
            update_keys: Some(vec![key.multikey()]),
            next_key_hashes: None,
        },
        &key,
        devices,
        &also_known_as
            .iter()
            .map(|uri| uri.to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

/// A did:webvh log whose first entry sets `portable: true`, so its DID may later move to another domain, written entry by
/// entry under one update key.
pub(crate) struct PortableLog {
    key: Ed25519KeyPair,
    lines: Vec<String>,
    scid: String,
    path: String,
}

impl PortableLog {
    /// The first entry: the DID at `<domain>/<path>`, authorizing `devices`, naming `also_known_as`.
    pub(crate) fn create(
        domain: &str,
        path: &str,
        seed: u8,
        devices: &[PublicKey],
        also_known_as: &[String],
    ) -> Self {
        let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let multikey = update_multikey(&key);
        let placeholder = format!("did:webvh:{{SCID}}:{domain}:{path}");
        let preliminary = json!({
            "versionId": "{SCID}",
            "versionTime": "2026-11-26T10:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "{SCID}",
                "updateKeys": [multikey],
                "portable": true,
            },
            "state": document(&placeholder, devices, also_known_as),
        });
        // did:webvh v1.0 §Generate SCID, then the placeholder replaced everywhere.
        let scid = multihash(jcs(&preliminary).as_bytes());
        let text = serde_json::to_string(&preliminary)
            .unwrap()
            .replace("{SCID}", &scid);
        let mut entry: Value = serde_json::from_str(&text).unwrap();
        // §Generate Entry Hash: the first entry's predecessor is the SCID.
        entry["versionId"] = Value::String(scid.clone());
        let hash = multihash(jcs(&entry).as_bytes());
        entry["versionId"] = Value::String(format!("1-{hash}"));
        let mut log = Self {
            key,
            lines: Vec::new(),
            scid,
            path: path.to_owned(),
        };
        log.push(entry, "2026-11-26T10:00:00Z");
        log
    }

    /// The DID as it stands at `domain`.
    pub(crate) fn did_at(&self, domain: &str) -> String {
        format!("did:webvh:{}:{domain}:{}", self.scid, self.path)
    }

    /// The next entry: the DID at `domain` (another domain than the head's moves it), authorizing `devices`, naming
    /// `also_known_as`.
    pub(crate) fn append(&mut self, domain: &str, devices: &[PublicKey], also_known_as: &[String]) {
        let n = self.lines.len() + 1;
        let time = format!("2026-11-26T10:00:{n:02}Z");
        let previous: Value = serde_json::from_str(self.lines.last().unwrap()).unwrap();
        let mut entry = json!({
            "versionId": previous["versionId"],
            "versionTime": time,
            "parameters": {},
            "state": document(&self.did_at(domain), devices, also_known_as),
        });
        let hash = multihash(jcs(&entry).as_bytes());
        entry["versionId"] = Value::String(format!("{n}-{hash}"));
        self.push(entry, &time);
    }

    fn push(&mut self, mut entry: Value, created: &str) {
        let multikey = update_multikey(&self.key);
        let mut proof = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("did:key:{multikey}#{multikey}"),
            "created": created,
            "proofPurpose": "assertionMethod",
        });
        let mut hash_data = Sha256::digest(jcs(&proof).as_bytes()).to_vec();
        hash_data.extend_from_slice(&Sha256::digest(jcs(&entry).as_bytes()));
        let signature = self.key.sign(&hash_data);
        proof["proofValue"] = Value::String(format!("z{}", base58(signature.as_ref())));
        entry["proof"] = json!([proof]);
        self.lines.push(serde_json::to_string(&entry).unwrap());
    }

    /// The log as a credential, or `None` when the crate's verification refuses it.
    pub(crate) fn credential(&self) -> Option<DidWebvhCredential> {
        let bytes: Vec<u8> = self
            .lines
            .iter()
            .flat_map(|line| [line.as_bytes(), b"\n"].concat())
            .collect();
        let credential = DidWebvhCredential::new(bytes, Vec::new()).unwrap();
        mls_didwebvh::verify_credential(&credential)
            .is_ok()
            .then_some(credential)
    }
}

fn update_multikey(key: &Ed25519KeyPair) -> String {
    mls_didwebvh::ed25519_multikey(&key.public_key().as_ref().try_into().unwrap())
}

/// A DID document listing `devices`, each a `Multikey` verification method referenced from `authentication`, as the
/// crate's controller writes one.
fn document(did: &str, devices: &[PublicKey], also_known_as: &[String]) -> Value {
    let methods: Vec<Value> = devices
        .iter()
        .enumerate()
        .map(|(i, key)| {
            json!({
                "id": format!("{did}#device-{}", i + 1),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": mls_didwebvh::ed25519_multikey(key),
            })
        })
        .collect();
    let authentication: Vec<Value> = (1..=devices.len())
        .map(|i| Value::String(format!("#device-{i}")))
        .collect();
    let mut document = json!({
        "@context": ["https://www.w3.org/ns/did/v1.1"],
        "id": did,
        "verificationMethod": methods,
        "authentication": authentication,
    });
    if !also_known_as.is_empty() {
        document["alsoKnownAs"] = json!(also_known_as);
    }
    document
}

/// `base58btc(multihash(SHA-256(data)))`.
fn multihash(data: &[u8]) -> String {
    let mut bytes = vec![0x12, 0x20];
    bytes.extend_from_slice(&Sha256::digest(data));
    base58(&bytes)
}

fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = u8::try_from(carry % 58).unwrap();
            carry /= 58;
        }
        while carry > 0 {
            digits.push(u8::try_from(carry % 58).unwrap());
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|&d| char::from(ALPHABET[usize::from(d)])),
        )
        .collect()
}

/// RFC 8785 canonical JSON for the values a log holds: strings, integers, booleans, arrays and objects, members sorted
/// by their UTF-16 code units.
fn jcs(value: &Value) -> String {
    match value {
        Value::Object(members) => {
            let mut members: Vec<(&String, &Value)> = members.iter().collect();
            members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            let body: Vec<String> = members
                .into_iter()
                .map(|(name, item)| {
                    format!("{}:{}", serde_json::to_string(name).unwrap(), jcs(item))
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => {
            let body: Vec<String> = items.iter().map(jcs).collect();
            format!("[{}]", body.join(","))
        }
        other => serde_json::to_string(other).unwrap(),
    }
}
