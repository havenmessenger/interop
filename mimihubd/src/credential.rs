//! The one place the hub reads a user from an MLS credential.
//!
//! The hub binds each member's leaf to a user URI, to check a Commit's participant-list change against the clients it
//! adds and removes (protocol-07 §7.5) and to know which provider a member's client belongs to. RFC 9420 leaves how a
//! credential names a user to the application, so this module decides it, credential type by credential type, and no
//! other module reads a credential's content. A credential type this hub cannot read names no user: it is refused
//! wherever the hub must know the user, and it is never read as if it were another type.
//!
//! Read today: a Basic credential, whose identity is the user's URI.

use openmls::prelude::{Credential, CredentialType};

/// Whether this hub reads credentials of `credential`'s type at all: one it does not read names no user, whatever it
/// carries.
pub(crate) fn is_read(credential: &Credential) -> bool {
    credential.credential_type() == CredentialType::Basic
}

/// The user URI `credential` names, as it states it: a Basic credential's identity, when it is UTF-8. `None` for every
/// other credential type, so the bytes of a credential of another type are never read as a URI.
pub(crate) fn stated_uri(credential: &Credential) -> Option<&str> {
    match credential.credential_type() {
        CredentialType::Basic => std::str::from_utf8(credential.serialized_content()).ok(),
        _ => None,
    }
}

/// The user `credential` names, in canonical form (`mimi_core::uri::canonical`): [`stated_uri`], canonicalized.
pub(crate) fn user_uri(credential: &Credential) -> Option<String> {
    stated_uri(credential).map(mimi_core::uri::canonical)
}

/// Whether a client's leaf may carry `new` in place of `old` (RFC 9420 §5.3.1, "a valid successor"): both name the
/// same user, by a credential type this hub reads. For a Basic credential the identity bytes are the same, exactly,
/// as the group's clients require.
pub(crate) fn is_successor(old: &Credential, new: &Credential) -> bool {
    match (old.credential_type(), new.credential_type()) {
        (CredentialType::Basic, CredentialType::Basic) => {
            old.serialized_content() == new.serialized_content()
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod tests;
