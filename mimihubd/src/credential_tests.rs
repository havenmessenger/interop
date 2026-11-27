use openmls::prelude::{BasicCredential, Credential, CredentialType};

use super::{is_successor, stated_uri, user_uri};

const ALICE: &str = "mimi://example.com/u/alice";

fn basic(identity: &[u8]) -> Credential {
    BasicCredential::new(identity.to_vec()).into()
}

/// A credential of a type this hub does not read, carrying `content` (here, the bytes of a user URI).
fn other(content: &[u8]) -> Credential {
    Credential::new(CredentialType::Other(0xF0F0), content.to_vec())
}

#[test]
fn a_basic_credential_names_its_identity() {
    assert_eq!(stated_uri(&basic(ALICE.as_bytes())), Some(ALICE));
    assert_eq!(
        user_uri(&basic(b"mimi://EXAMPLE.com/u/alice")),
        Some(mimi_core::uri::canonical("mimi://EXAMPLE.com/u/alice"))
    );
    assert_eq!(
        user_uri(&basic(&[0xff, 0xfe])),
        None,
        "an identity that is not UTF-8 names no user"
    );
}

/// A credential of another type names no user, even when its content is the bytes of a user URI: it is never read as a
/// Basic credential. Revert check: read the content whatever the type, and Alice is named.
#[test]
fn a_credential_of_another_type_names_no_user() {
    assert_eq!(
        user_uri(&other(ALICE.as_bytes())),
        None,
        "PLANT-CREDENTIAL-TYPE: a credential of another type was read as a URI"
    );
    assert_eq!(
        user_uri(&Credential::new(
            CredentialType::X509,
            ALICE.as_bytes().to_vec()
        )),
        None
    );
}

#[test]
fn a_basic_credential_succeeds_one_with_the_same_identity_only() {
    assert!(is_successor(
        &basic(ALICE.as_bytes()),
        &basic(ALICE.as_bytes())
    ));
    assert!(!is_successor(
        &basic(ALICE.as_bytes()),
        &basic(b"mimi://example.com/u/bob")
    ));
    assert!(
        !is_successor(&basic(ALICE.as_bytes()), &other(ALICE.as_bytes())),
        "a change of credential type is not a successor"
    );
    assert!(!is_successor(
        &other(ALICE.as_bytes()),
        &other(ALICE.as_bytes())
    ));
}

/// Nothing outside this module reads a credential's content or the Basic-only helpers that do: every read of a user
/// from a credential goes through `credential`, so a credential type is handled in one place. Revert check: read
/// `serialized_content()` in another hub module, and this fails naming it.
#[test]
fn no_other_module_reads_a_credential() {
    const READS: [&str; 4] = [
        "serialized_content(",
        "BasicCredential::try_from",
        "keypackage_basic_identity",
        "requester_credential_identity",
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    let mut scanned = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        // Test code builds and inspects credentials freely; the rule is for the hub's own code.
        if name == "credential.rs" || name.ends_with("_tests.rs") || name == "mls_fixtures.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // The hub's code is what comes before an inline test module, if the file has one.
        let code = text.split("#[cfg(test)]\nmod tests").next().unwrap();
        let squeezed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        for read in READS {
            if squeezed.contains(read) {
                found.push(format!("{name}: {read}"));
            }
        }
        scanned += 1;
    }
    assert!(
        scanned > 40,
        "the scan found only {scanned} hub source files in {}",
        dir.display()
    );
    assert!(
        found.is_empty(),
        "PLANT-CREDENTIAL-GUARD: credential reads outside credential.rs: {found:?}"
    );
}
