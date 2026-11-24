//! Which enrolled name an `identifierQuery` search names (protocol-07 §5.8).
//!
//! A `handle` search matches the entire handle URI; a `nick` search matches the nickname or handle user part. This hub
//! knows its users by name, so a search resolves to at most one name, which the caller then looks up among the enrolled.
//! Two handle URI forms name a user here, each only with this hub's own domain as its authority or host:
//!
//! - `mimi://<domain>/u/<name>`, compared in its canonical form (RFC 3986 §6.2.2, an IRI mapped to its URI per RFC 3987
//!   §3.1), so case in the scheme and host, a percent-encoded unreserved character, and a name written raw or
//!   percent-encoded from its UTF-8 all match;
//! - `im:<name>@<domain>`, the form of the draft's own example, the scheme and the host compared without case.
//!
//! Names are kept as plain text, so the user part of either form is percent-decoded before it is looked up; one that does
//! not decode to UTF-8 names nobody.
//!
//! A `nick` is a bare name. Anything else names nobody, and the caller answers it with the one `notFound` (DIV-4).

use mimi_core::protocol_wire::SearchIdentifierType;
use mimi_core::uri::{canonical, percent_decode_utf8, MimiKind, MimiUri};

/// The enrolled name `value` searches for under `search_type` on the hub of `domain`, or `None` when it names nobody here.
pub fn enrolled_name(
    search_type: SearchIdentifierType,
    value: &str,
    domain: &str,
) -> Option<String> {
    match search_type {
        SearchIdentifierType::Nick => bare_name(value),
        SearchIdentifierType::Handle => handle_name(value, domain),
        _ => None,
    }
}

/// A nick is the name itself: no scheme, path or host in it.
fn bare_name(value: &str) -> Option<String> {
    let plain = !value.is_empty() && !value.contains([':', '/', '@']);
    plain.then(|| value.to_string())
}

/// The user part of a handle URI on this hub, in either form it accepts.
fn handle_name(value: &str, domain: &str) -> Option<String> {
    if value
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("mimi://"))
    {
        let uri = MimiUri::parse(&canonical(value)).ok()?;
        let own_user = uri.kind == Some(MimiKind::User) && uri.is_local_to(domain);
        return (own_user && !uri.path.contains('/'))
            .then_some(uri.path)
            .and_then(|path| percent_decode_utf8(&path))
            .and_then(|name| bare_name(&name));
    }
    let rest = value
        .get(..3)
        .filter(|scheme| scheme.eq_ignore_ascii_case("im:"))
        .map(|_| &value[3..])?;
    let (name, host) = rest.rsplit_once('@')?;
    host.eq_ignore_ascii_case(domain)
        .then(|| percent_decode_utf8(name))
        .flatten()
        .and_then(|name| bare_name(&name))
}

#[cfg(test)]
#[path = "identifier_search_tests.rs"]
mod tests;
