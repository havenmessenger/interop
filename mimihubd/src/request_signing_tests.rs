//! The signer against draft-atwood-mimi-provider-auth-00 Appendix A, and against this hub's own verifier.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use super::*;
use crate::signature::{verify, PeerKeys, SignedRequest};

/// RFC 9421 Appendix B.1.4, test-key-ed25519 (JWK `d`, base64url).
const TEST_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const A_URL: &str = "https://b.example/v1/notify/a.example/r/clubhouse";
const A_FROM: &str = "mimi@a.example";
const A_DIGEST: &str = "sha-256=:ltvFi/ijqMH79/ThrwZ/JykItjIYFA06v8rfqBdj7dY=:";
const A_INPUT: &str = r#"mimi=("@method" "@target-uri" "content-digest" "from");created=1794700800;keyid="s1";tag="mimi""#;
const A_SIG: &str = "mimi=:OBXnNmTPY+Gcxbn+BKcfqCpK7GrkCGO+Ab0/PS956byMzzcArSVEeJWA95WiYjfLJ9vMsEaCRab3geIFr5FpCw==:";
const A_PUB: &str = "JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";

fn test_signer(keyid: &str) -> RequestSigner {
    RequestSigner::from_seed(&URL_SAFE_NO_PAD.decode(TEST_D).unwrap(), keyid).unwrap()
}

/// Appendix A is reproduced byte for byte: the body whose digest the draft prints, signed at its `created` with no
/// nonce, gives its `Content-Digest`, `Signature-Input` and `Signature`.
#[test]
fn appendix_a_is_reproduced_byte_for_byte() {
    let signer = test_signer("s1");
    assert_eq!(signer.public_key_b64(), A_PUB);
    let body = [
        &b"example MIMI notify body"[..],
        b"example MIMI notify body\n",
        b"example MIMI notify body\r\n",
    ]
    .into_iter()
    .find(|body| format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body))) == A_DIGEST)
    .expect("one reading of Appendix A's body gives its digest");
    let headers = signer.sign_with("POST", A_URL, A_FROM, body, 1_794_700_800, None);
    assert_eq!(headers.content_digest, A_DIGEST);
    assert_eq!(headers.signature_input, A_INPUT, "PLANT-SIGN-APPENDIX-A");
    assert_eq!(headers.signature, A_SIG);
}

fn keys_file(record: &str, public: &str) -> (tempdir::Dir, PeerKeys) {
    let dir = tempdir::Dir::new();
    let path = dir.path().join("peer-keys.json");
    std::fs::write(&path, format!(r#"{{"{record}": "{public}"}}"#)).unwrap();
    (dir, PeerKeys::from_file(Some(path)))
}

/// What the signer makes, with a nonce and with an empty body, is what this hub's verifier accepts, for the domain the
/// `From` names; a changed body or URI is refused.
#[test]
fn this_hubs_verifier_accepts_what_the_signer_makes() {
    let signer = test_signer("haven1");
    let (_dir, keys) = keys_file("haven1._mimi.a.example", &signer.public_key_b64());
    for body in [&b"a fan-out"[..], b""] {
        let headers = signer.sign("POST", A_URL, A_FROM, body).unwrap();
        assert!(headers.signature_input.contains(";nonce=\""));
        let check = |uri: &str, body: &[u8]| {
            let header = |name: &str| match name {
                "signature-input" => Some(headers.signature_input.clone()),
                "signature" => Some(headers.signature.clone()),
                "content-digest" => Some(headers.content_digest.clone()),
                "from" => Some(A_FROM.to_string()),
                _ => None,
            };
            verify(
                &SignedRequest {
                    method: "POST",
                    target_uri: uri,
                    authority: "b.example",
                    path: "/v1/notify/a.example/r/clubhouse",
                    query: None,
                    header: &header,
                    body,
                },
                std::time::SystemTime::now(),
                &keys,
            )
        };
        assert_eq!(check(A_URL, body), Ok("a.example".to_string()));
        assert!(check("https://b.example/v1/notify/elsewhere", body).is_err());
        assert!(check(A_URL, b"another body").is_err());
    }
}

#[test]
fn a_seed_must_be_32_bytes_and_a_selector_a_label() {
    assert!(RequestSigner::from_seed(&[0u8; 31], "haven1").is_err());
    assert!(RequestSigner::from_seed(&[0u8; 32], "").is_err());
    assert!(RequestSigner::from_seed(&[0u8; 32], "a.b").is_err());
    let signer = RequestSigner::from_seed(&[7u8; 32], "haven1").unwrap();
    assert!(signer.dns_record().starts_with("v=MIMI1; k=ed25519; p="));
    assert!(
        !format!("{signer:?}").contains("[7, 7"),
        "the seed reached Debug"
    );
}

/// A temporary directory, removed when dropped.
mod tempdir {
    pub struct Dir(std::path::PathBuf);

    impl Dir {
        pub fn new() -> Self {
            let mut bytes = [0u8; 8];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).unwrap();
            let path = std::env::temp_dir().join(format!(
                "mimihubd-signing-{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
