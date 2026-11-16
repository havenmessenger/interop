//! The outbound gate: which addresses and URLs are refused before anything connects, and what a request that is made
//! carries. The servers here are local, reached through a test resolver that maps a test domain to them, with the
//! loopback range allowlisted where a request is meant to go through.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::tls::tests::{issue, make_ca};

pub(crate) const PEER: &str = "peer.example";
const HUB: &str = "hub.example";

/// Maps names to fixed addresses, so a test domain reaches a local server.
pub(crate) struct MapResolver(HashMap<String, Vec<SocketAddr>>);

impl Resolve for MapResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        let found = self.0.get(host).cloned();
        Box::pin(async move {
            found.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such test host"))
        })
    }
}

pub(crate) fn resolver(host: &str, addrs: &[SocketAddr]) -> Arc<dyn Resolve> {
    Arc::new(MapResolver(HashMap::from([(
        host.to_string(),
        addrs.to_vec(),
    )])))
}

pub(crate) struct Pki {
    ca: rcgen::Issuer<'static, rcgen::KeyPair>,
    ca_pem: String,
}

impl Pki {
    pub(crate) fn new() -> Self {
        let (ca, ca_pem) = make_ca();
        Self { ca, ca_pem }
    }

    /// A client for `HUB` presenting a certificate from this CA, trusting this CA only.
    pub(crate) fn client(
        &self,
        addresses: AddressPolicy,
        proxy: Option<ProxyAddr>,
        resolve: Arc<dyn Resolve>,
    ) -> PeerClient {
        self.client_with(addresses, proxy, resolve, true, None)
    }

    /// A client for `HUB`, with or without a client certificate from this CA, and signing with `signer` if given.
    pub(crate) fn client_with(
        &self,
        addresses: AddressPolicy,
        proxy: Option<ProxyAddr>,
        resolve: Arc<dyn Resolve>,
        certificate: bool,
        signer: Option<Arc<crate::request_signing::RequestSigner>>,
    ) -> PeerClient {
        let (cert, key) = issue(&self.ca, vec![HUB.into()], HUB);
        PeerClient::new(
            OutboundSettings {
                own_domain: HUB.into(),
                client_certificate: certificate.then(|| (cert.into_bytes(), key.into_bytes())),
                signer,
                peer_bundle_pem: Some(self.ca_pem.clone().into_bytes()),
                trust: PeerTrust::BundleOnly,
                addresses,
                proxy,
            },
            resolve,
        )
        .unwrap()
    }
}

pub(crate) fn loopback_allowed() -> AddressPolicy {
    AddressPolicy::with_allowlist(vec![Cidr::v4(127, 0, 0, 0, 8)])
}

/// What a test server saw of one request.
#[derive(Debug, Default, Clone)]
pub(crate) struct Seen {
    pub(crate) head: String,
    pub(crate) body: Vec<u8>,
    pub(crate) client_certificate: bool,
}

/// A TLS server for `name` that answers each request with `answer`, recording what it saw.
pub(crate) async fn server(
    pki: &Pki,
    name: &str,
    answer: Vec<u8>,
) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    server_with(pki, name, move |_| answer.clone()).await
}

/// A TLS server for `name` that answers each request with what `respond` makes of it, recording what it saw.
pub(crate) async fn server_with(
    pki: &Pki,
    name: &str,
    respond: impl Fn(&Seen) -> Vec<u8> + Send + Sync + 'static,
) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let (cert, key) = issue(&pki.ca, vec![name.into()], name);
    let config = crate::tls::build_mtls_server_config(
        cert.as_bytes(),
        key.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                continue;
            };
            let client_certificate = tls.get_ref().1.peer_certificates().is_some();
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                let read = tls.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    break None;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(at + 4);
                }
            };
            let Some(head_end) = head_end else { continue };
            let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            while buffer.len() < head_end + length {
                let read = tls.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let seen = Seen {
                head,
                body: buffer[head_end..].to_vec(),
                client_certificate,
            };
            let answer = respond(&seen);
            record.lock().unwrap().push(seen);
            let _ = tls.write_all(&answer).await;
            let _ = tls.shutdown().await;
        }
    });
    (addr, seen)
}

pub(crate) fn answer(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    [
        format!(
            "HTTP/1.1 {status}\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
        body,
    ]
    .concat()
}

fn url(path: &str, port: u16) -> PeerUrl {
    PeerUrl::parse(&format!("https://{PEER}:{port}{path}"), PEER).unwrap()
}

// ---------------------------------------------------------------- addresses

/// Every special range is refused by default, an IPv4 address inside an IPv6 one included, and the addresses just
/// outside a range are not.
#[test]
fn the_special_ranges_are_refused() {
    let policy = AddressPolicy::default();
    let refused: Vec<IpAddr> = vec![
        Ipv4Addr::new(127, 0, 0, 1).into(),
        Ipv4Addr::new(10, 1, 2, 3).into(),
        Ipv4Addr::new(172, 16, 0, 1).into(),
        Ipv4Addr::new(172, 31, 255, 255).into(),
        Ipv4Addr::new(192, 168, 1, 1).into(),
        Ipv4Addr::new(100, 64, 0, 1).into(),
        Ipv4Addr::new(100, 127, 255, 255).into(),
        Ipv4Addr::new(169, 254, 169, 254).into(),
        Ipv4Addr::new(0, 0, 0, 0).into(),
        Ipv4Addr::new(224, 0, 0, 1).into(),
        Ipv4Addr::new(192, 0, 2, 1).into(),
        Ipv4Addr::new(198, 51, 100, 7).into(),
        Ipv4Addr::new(203, 0, 113, 7).into(),
        Ipv4Addr::new(198, 18, 0, 1).into(),
        Ipv4Addr::new(240, 0, 0, 1).into(),
        Ipv4Addr::new(255, 255, 255, 255).into(),
        Ipv6Addr::LOCALHOST.into(),
        Ipv6Addr::UNSPECIFIED.into(),
        "fc00::1".parse().unwrap(),
        "fd12:3456::1".parse().unwrap(),
        "fe80::1".parse().unwrap(),
        "ff02::1".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped()),
        IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped()),
        "64:ff9b::7f00:1".parse().unwrap(),
        "::7f00:1".parse().unwrap(),
    ];
    for addr in refused {
        assert!(policy.check(addr).is_err(), "{addr} was let through");
    }
    let allowed: Vec<IpAddr> = vec![
        Ipv4Addr::new(9, 9, 9, 9).into(),
        Ipv4Addr::new(172, 15, 255, 255).into(),
        Ipv4Addr::new(172, 32, 0, 0).into(),
        Ipv4Addr::new(100, 63, 255, 255).into(),
        Ipv4Addr::new(100, 128, 0, 0).into(),
        "2606:4700::1111".parse().unwrap(),
    ];
    for addr in allowed {
        assert!(policy.check(addr).is_ok(), "{addr} was refused");
    }
}

/// The allowlist takes a range out of the refused ones and no other.
#[test]
fn the_allowlist_admits_only_what_it_names() {
    let policy =
        AddressPolicy::with_allowlist(AddressPolicy::parse_allowlist("127.0.0.0/8, ::1").unwrap());
    assert!(policy.check(Ipv4Addr::new(127, 0, 0, 1).into()).is_ok());
    assert!(policy.check(Ipv6Addr::LOCALHOST.into()).is_ok());
    assert!(policy.check(Ipv4Addr::new(10, 0, 0, 1).into()).is_err());
    assert!(AddressPolicy::parse_allowlist("127.0.0.0/33").is_err());
    assert!(AddressPolicy::parse_allowlist("loopback").is_err());
}

// ---------------------------------------------------------------- URLs

/// Only an https URL whose host is the peer's domain or a subdomain of it is sent to.
#[test]
fn a_url_must_be_https_and_name_the_peer() {
    assert!(matches!(
        PeerUrl::parse("http://peer.example/notify", PEER),
        Err(OutboundError::NotHttps)
    ));
    assert!(matches!(
        PeerUrl::parse("https://elsewhere.example/notify", PEER),
        Err(OutboundError::HostNotPeer { .. })
    ));
    assert!(matches!(
        PeerUrl::parse("https://evilpeer.example/notify", PEER),
        Err(OutboundError::HostNotPeer { .. })
    ));
    for literal in ["https://127.0.0.1/notify", "https://[::1]/notify"] {
        assert!(
            matches!(PeerUrl::parse(literal, PEER), Err(OutboundError::BadUrl(_))),
            "{literal}"
        );
    }
    assert!(PeerUrl::parse("https://user@peer.example/", PEER).is_err());
    assert!(PeerUrl::parse("https://peer.example/#top", PEER).is_err());

    let same = PeerUrl::parse("HTTPS://Peer.Example./v1/notify/r", PEER).unwrap();
    assert_eq!((same.host(), same.port()), (PEER, 443));
    assert_eq!(same.path_and_query, "/v1/notify/r");
    let sub = PeerUrl::parse("https://mimi.peer.example:8443?x=1", PEER).unwrap();
    assert_eq!((sub.host(), sub.port()), ("mimi.peer.example", 8443));
    assert_eq!(sub.path_and_query, "/?x=1");
}

// ---------------------------------------------------------------- the 127.0.0.1 test

/// A peer whose host resolves to 127.0.0.1 is refused before anything connects: a listener bound there sees no
/// connection. One refused address among others refuses too. Revert check: skip the address check, and the listener
/// is connected to.
#[tokio::test]
async fn a_peer_resolving_to_loopback_is_refused_before_connecting() {
    let pki = Pki::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = pki.client(AddressPolicy::default(), None, resolver(PEER, &[addr]));
    let refused = client
        .post(
            &url("/notify/r", addr.port()),
            "application/mimi-protocol",
            b"x".to_vec(),
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(OutboundError::Refused {
                range: "loopback",
                ..
            })
        ),
        "PLANT-OUTBOUND-LOOPBACK: {refused:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "the listener on 127.0.0.1 was connected to"
    );

    let public: SocketAddr = (Ipv4Addr::new(9, 9, 9, 9), addr.port()).into();
    let mixed = pki.client(
        AddressPolicy::default(),
        None,
        resolver(PEER, &[public, addr]),
    );
    assert!(matches!(
        mixed.vetted_addresses(&url("/", addr.port())).await,
        Err(OutboundError::Refused { .. })
    ));
}

// ---------------------------------------------------------------- requests that are made

/// A request that passes goes over TLS with the hub's client certificate, carries `From` and `Host`, and returns the
/// peer's answer.
#[tokio::test]
async fn a_request_carries_the_client_certificate_from_and_host() {
    let pki = Pki::new();
    let (addr, seen) = server(&pki, PEER, answer("201 Created", "", b"")).await;
    let client = pki.client(loopback_allowed(), None, resolver(PEER, &[addr]));
    let response = client
        .post(
            &url("/v1/notify/mimi%3A%2F%2Fpeer.example%2Fr%2Fx", addr.port()),
            "application/mimi-protocol",
            b"fanout".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 201);
    let seen = seen.lock().unwrap()[0].clone();
    assert!(
        seen.client_certificate,
        "PLANT-OUTBOUND-CLIENT-CERT: no client certificate"
    );
    assert!(seen
        .head
        .starts_with("POST /v1/notify/mimi%3A%2F%2Fpeer.example%2Fr%2Fx HTTP/1.1\r\n"));
    let head = seen.head.to_ascii_lowercase();
    assert!(head.contains(&format!("host: {PEER}:{}\r\n", addr.port())));
    assert!(head.contains(&format!("from: mimi@{HUB}\r\n")));
    assert!(head.contains("content-type: application/mimi-protocol\r\n"));
    assert_eq!(seen.body, b"fanout");
}

/// A host with several addresses is tried address by address: one that refuses the connection is passed over for the
/// next. Revert check: connect to the first address only, and the request fails.
#[tokio::test]
async fn each_checked_address_is_tried_in_turn() {
    let pki = Pki::new();
    let (addr, seen) = server(&pki, PEER, answer("201 Created", "", b"")).await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let client = pki.client(loopback_allowed(), None, resolver(PEER, &[dead, addr]));
    let response = client.get(&url("/", addr.port())).await;
    assert!(
        matches!(&response, Ok(response) if response.status == 201),
        "PLANT-OUTBOUND-EACH-ADDRESS: {response:?}"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
}

/// A hub with a signing key signs each request: the peer gets `Content-Digest`, `Signature-Input` and `Signature`
/// that verify, by this hub's own verifier, for the hub's domain; with no client certificate configured, none is
/// presented. Revert check: do not sign, and the request carries no signature.
#[tokio::test]
async fn a_signing_hub_signs_each_request_and_need_present_no_certificate() {
    let pki = Pki::new();
    let (addr, seen) = server(&pki, PEER, answer("201 Created", "", b"")).await;
    let signer =
        Arc::new(crate::request_signing::RequestSigner::from_seed(&[9u8; 32], "haven1").unwrap());
    let client = pki.client_with(
        loopback_allowed(),
        None,
        resolver(PEER, &[addr]),
        false,
        Some(signer.clone()),
    );
    let url = url("/v1/notify/r", addr.port());
    client
        .post(&url, "application/mimi-protocol", b"fanout".to_vec())
        .await
        .unwrap();
    let seen = seen.lock().unwrap()[0].clone();
    assert!(
        !seen.client_certificate,
        "a client certificate was presented"
    );
    let header = |name: &str| {
        seen.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    };
    assert!(
        header("signature").is_some(),
        "PLANT-OUTBOUND-SIGN: the request is not signed"
    );
    let dir = std::env::temp_dir().join(format!("mimi-outbound-sign-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let keys_path = dir.join("keys.json");
    std::fs::write(
        &keys_path,
        format!(r#"{{"haven1._mimi.{HUB}": "{}"}}"#, signer.public_key_b64()),
    )
    .unwrap();
    let keys = crate::signature::PeerKeys::from_file(Some(keys_path));
    let host = format!("{PEER}:{}", addr.port());
    let verdict = crate::signature::verify(
        &crate::signature::SignedRequest {
            method: "POST",
            target_uri: &format!("https://{host}/v1/notify/r"),
            authority: &host,
            path: "/v1/notify/r",
            query: None,
            header: &header,
            body: &seen.body,
        },
        std::time::SystemTime::now(),
        &keys,
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(verdict, Ok(HUB.to_string()));
}

/// A server certificate that is not for the host connected to fails the handshake.
#[tokio::test]
async fn a_server_certificate_for_another_name_is_refused() {
    let pki = Pki::new();
    let (addr, seen) = server(&pki, "other.example", answer("201 Created", "", b"")).await;
    let client = pki.client(loopback_allowed(), None, resolver(PEER, &[addr]));
    let result = client.get(&url("/", addr.port())).await;
    assert!(matches!(result, Err(OutboundError::Tls(_))), "{result:?}");
    assert!(seen.lock().unwrap().is_empty());
}

/// A redirect is not followed: its status is the answer, and the server sees one request.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let pki = Pki::new();
    let (addr, seen) = server(
        &pki,
        PEER,
        answer(
            "302 Found",
            "location: https://peer.example/elsewhere\r\n",
            b"",
        ),
    )
    .await;
    let client = pki.client(loopback_allowed(), None, resolver(PEER, &[addr]));
    let response = client.get(&url("/", addr.port())).await.unwrap();
    assert_eq!(response.status, 302);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(seen.lock().unwrap().len(), 1);
}

/// An answer larger than the cap is refused, and `Retry-After` is returned as sent.
#[tokio::test]
async fn a_large_answer_is_refused_and_retry_after_is_returned() {
    let pki = Pki::new();
    let big = vec![b'x'; MAX_RESPONSE_BYTES + 1];
    let (addr, _) = server(&pki, PEER, answer("200 OK", "", &big)).await;
    let client = pki.client(loopback_allowed(), None, resolver(PEER, &[addr]));
    assert!(matches!(
        client.get(&url("/", addr.port())).await,
        Err(OutboundError::TooLarge)
    ));

    let (addr, _) = server(
        &pki,
        PEER,
        answer("503 Service Unavailable", "retry-after: 120\r\n", b""),
    )
    .await;
    let client = pki.client(loopback_allowed(), None, resolver(PEER, &[addr]));
    let response = client.get(&url("/", addr.port())).await.unwrap();
    assert_eq!(
        (response.status, response.retry_after.as_deref()),
        (503, Some("120"))
    );
}

// ---------------------------------------------------------------- the proxy

/// A `CONNECT` proxy that records each target and tunnels to it.
async fn proxy() -> (ProxyAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let record = targets.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if client.read(&mut byte).await.unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let line = String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
            record.lock().unwrap().push(target.clone());
            let Ok(mut upstream) = TcpStream::connect(&target).await else {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                continue;
            };
            let _ = client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await;
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (
        ProxyAddr::parse(&format!("http://{addr}")).unwrap(),
        targets,
    )
}

/// Through a proxy, the `CONNECT` names the checked address, never the peer's name, and TLS with the client
/// certificate runs end to end inside the tunnel. A refused destination is refused before the proxy is contacted.
/// Revert check: tunnel to the name, and the proxy records `peer.example`.
#[tokio::test]
async fn a_proxy_tunnel_names_the_checked_address() {
    let pki = Pki::new();
    let (addr, seen) = server(&pki, PEER, answer("201 Created", "", b"")).await;
    let (proxy_addr, targets) = proxy().await;
    let client = pki.client(
        loopback_allowed(),
        Some(proxy_addr.clone()),
        resolver(PEER, &[addr]),
    );
    let response = client.get(&url("/", addr.port())).await;
    assert_eq!(
        targets.lock().unwrap().as_slice(),
        [addr.to_string()],
        "PLANT-OUTBOUND-PROXY-ADDRESS: the CONNECT did not name the checked address"
    );
    assert_eq!(response.unwrap().status, 201);
    assert!(seen.lock().unwrap()[0].client_certificate);

    let refusing = pki.client(
        AddressPolicy::default(),
        Some(proxy_addr),
        resolver(PEER, &[addr]),
    );
    assert!(matches!(
        refusing.get(&url("/", addr.port())).await,
        Err(OutboundError::Refused { .. })
    ));
    assert_eq!(
        targets.lock().unwrap().len(),
        1,
        "the proxy was asked for a refused destination"
    );
}

#[test]
fn proxy_and_trust_settings_parse() {
    assert!(ProxyAddr::parse("http://proxy.example:3128").is_ok());
    assert!(ProxyAddr::parse("https://proxy.example:3128").is_err());
    assert!(ProxyAddr::parse("http://proxy.example").is_err());
    assert_eq!(PeerTrust::parse("system"), Ok(PeerTrust::SystemAndBundle));
    assert_eq!(PeerTrust::parse("bundle"), Ok(PeerTrust::BundleOnly));
    assert!(PeerTrust::parse("none").is_err());
}
