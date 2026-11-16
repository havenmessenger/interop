//! The peer map, a directory's endpoints, and how a room fills a template.

use super::*;

/// The operator's map gives a provider another base; any other provider is at `https://<domain>`. A base outside the
/// provider's domain is refused when the map is read.
#[test]
fn the_peer_map_sets_a_base_within_the_providers_domain() {
    let bases = PeerBases::parse(
        r#"
"a.example" = "https://mimi.a.example/"
"#,
    )
    .unwrap();
    assert_eq!(bases.base("a.example"), "https://mimi.a.example");
    assert_eq!(bases.base("b.example"), "https://b.example");
    assert!(PeerBases::parse(r#""a.example" = "https://elsewhere.example""#).is_err());
    assert!(PeerBases::parse(r#""a.example" = "http://mimi.a.example""#).is_err());
    assert!(PeerBases::parse(r#""a.example" = 3"#).is_err());
}

/// A directory's endpoint is its URL template with the room URI percent-encoded into one path segment, and it must
/// name the provider's domain or a subdomain. Revert check: take the URL as given, and the endpoint on another host is
/// sent to.
#[test]
fn an_endpoint_is_filled_and_must_name_the_provider() {
    let directory = Directory::parse(
        br#"{
            "notify": "https://mimi.a.example/v1/notify/{roomId}",
            "update": "https://elsewhere.example/v1/update/{roomId}",
            "wire": {"notify": "/mimi/pl/notify/{roomId}"}
        }"#,
    )
    .unwrap();
    let notify = directory
        .endpoint(
            "notify",
            "roomId",
            "mimi://a.example/r/room one",
            "a.example",
        )
        .unwrap();
    assert_eq!(notify.host(), "mimi.a.example");
    assert_eq!(
        notify,
        crate::outbound::PeerUrl::parse(
            "https://mimi.a.example/v1/notify/mimi%3A%2F%2Fa.example%2Fr%2Froom%20one",
            "a.example"
        )
        .unwrap()
    );
    assert!(
        matches!(
            directory.endpoint("update", "roomId", "mimi://a.example/r/x", "a.example"),
            Err(DirectoryError::Endpoint { .. })
        ),
        "PLANT-DIRECTORY-HOST: an endpoint on another host was taken"
    );
    assert!(matches!(
        directory.endpoint("keyMaterial", "targetUser", "x", "a.example"),
        Err(DirectoryError::NoEndpoint("keyMaterial"))
    ));
    assert!(Directory::parse(b"[]").is_err());
    assert!(Directory::parse(b"not json").is_err());
}

#[test]
fn percent_encoding_keeps_only_the_unreserved_bytes() {
    assert_eq!(percent_encode("aZ09-._~"), "aZ09-._~");
    assert_eq!(percent_encode("mimi://a/r"), "mimi%3A%2F%2Fa%2Fr");
    assert_eq!(percent_encode("é"), "%C3%A9");
}
