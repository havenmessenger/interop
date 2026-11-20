//! The hub's one way out to another provider: every outbound request goes through [`PeerClient`], and nothing else in
//! this crate opens a connection.
//!
//! Before anything connects:
//!
//! - The URL is `https`, and its host is the peer provider's domain or a subdomain of it ([`PeerUrl::parse`]). An IP
//!   literal, a userinfo part, a fragment, or any other host is refused.
//! - The host is resolved once, and every address it resolves to is checked against [`AddressPolicy`]: loopback,
//!   unspecified, link-local, private (RFC 1918), shared (RFC 6598), unique-local, multicast, documentation and the other
//!   special ranges are refused unless the operator's allowlist names them. One refused address refuses the request.
//! - The connection is made to a checked address itself, so no second lookup can name another one: each address the
//!   host resolved to is tried in turn until one connects, as a host with both an IPv6 and an IPv4 address needs.
//!   Through a proxy ([`ProxyAddr`]) the `CONNECT` names that address too, and the proxy never resolves the peer's
//!   name.
//!
//! Each request is signed with the provider's DNS-published key when the hub has one (`request_signing.rs`,
//! draft-atwood-mimi-provider-auth §5), and a client certificate is presented when one is configured; either proves to
//! the peer which provider sends it. Then TLS is run, and the peer's server certificate must be valid for the host
//! connected to: a `dNSName` subject alternative name matching it exactly or by a leftmost
//! wildcard label, the same test the inbound listener applies (DIVERGENCES, DIV-16). The trust anchors are the system's
//! roots plus the configured peer bundle, or the bundle alone ([`PeerTrust`]). Each request carries `From:
//! mimi@<own domain>` and the URL's `Host` (protocol-07 §4.1). Redirects are not followed: a `3xx` is returned as the
//! answer it is. Connect, handshake and request each have a deadline, and an answer's body is capped.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// How long a TCP connect (to the peer, or to the proxy) may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the TLS handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request may take from sending it to the last byte of the answer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest answer body read from a peer.
pub const MAX_RESPONSE_BYTES: usize = crate::store::MAX_ITEM_BYTES;
/// The largest header block read from a proxy's answer to `CONNECT`.
const MAX_PROXY_HEADER_BYTES: usize = 8 * 1024;

/// Why an outbound request was not made, or failed. The peer's body never appears in it.
#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error("the URL is not https")]
    NotHttps,
    #[error("the URL is not one this client sends to: {0}")]
    BadUrl(&'static str),
    #[error("the URL's host {host} is not the peer's domain {peer} or a subdomain of it")]
    HostNotPeer { host: String, peer: String },
    #[error("{host} resolves to {addr}, in a {range} range, which is refused")]
    Refused {
        host: String,
        addr: IpAddr,
        range: &'static str,
    },
    #[error("{0} resolves to no address")]
    NoAddress(String),
    #[error("resolving {host}: {error}")]
    Resolve { host: String, error: io::Error },
    #[error("connecting: {0}")]
    Connect(io::Error),
    #[error("the proxy: {0}")]
    Proxy(String),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("HTTP: {0}")]
    Http(String),
    #[error("the answer is larger than {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error("timed out while {0}")]
    Timeout(&'static str),
}

// ============================ addresses ============================

/// A network: an address and a prefix length, written `addr/len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub const fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Self {
        Self {
            network: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefix,
        }
    }

    pub const fn v6(segments: [u16; 8], prefix: u8) -> Self {
        let [a, b, c, d, e, f, g, h] = segments;
        Self {
            network: IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
            prefix,
        }
    }

    /// Parse `addr/len`, or a bare address as a single host.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = addr
            .parse()
            .map_err(|_| format!("{text:?} is not an address or a network"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max)
                .ok_or_else(|| format!("{text:?} has no valid prefix length"))?,
            None => max,
        };
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(addr) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(addr) & mask
            }
            _ => false,
        }
    }
}

/// The ranges a peer's address may not be in, each with the name a refusal gives it.
const REFUSED: &[(Cidr, &str)] = &[
    (Cidr::v4(0, 0, 0, 0, 8), "unspecified (this network)"),
    (Cidr::v4(127, 0, 0, 0, 8), "loopback"),
    (Cidr::v4(10, 0, 0, 0, 8), "private (RFC 1918)"),
    (Cidr::v4(172, 16, 0, 0, 12), "private (RFC 1918)"),
    (Cidr::v4(192, 168, 0, 0, 16), "private (RFC 1918)"),
    (
        Cidr::v4(100, 64, 0, 0, 10),
        "shared address space (RFC 6598)",
    ),
    (Cidr::v4(169, 254, 0, 0, 16), "link-local"),
    (Cidr::v4(192, 0, 0, 0, 24), "IETF protocol assignments"),
    (Cidr::v4(192, 0, 2, 0, 24), "documentation"),
    (Cidr::v4(198, 51, 100, 0, 24), "documentation"),
    (Cidr::v4(203, 0, 113, 0, 24), "documentation"),
    (Cidr::v4(198, 18, 0, 0, 15), "benchmarking"),
    (Cidr::v4(224, 0, 0, 0, 4), "multicast"),
    (Cidr::v4(240, 0, 0, 0, 4), "reserved"),
    (Cidr::v6([0, 0, 0, 0, 0, 0, 0, 0], 128), "unspecified"),
    (Cidr::v6([0, 0, 0, 0, 0, 0, 0, 1], 128), "loopback"),
    (Cidr::v6([0x0100, 0, 0, 0, 0, 0, 0, 0], 64), "discard-only"),
    (Cidr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7), "unique local"),
    (Cidr::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), "link-local"),
    (Cidr::v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10), "site-local"),
    (Cidr::v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8), "multicast"),
    (
        Cidr::v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
        "documentation",
    ),
];

/// Which addresses a peer may be reached at: any but the special ranges, unless the operator's allowlist names it.
#[derive(Debug, Clone, Default)]
pub struct AddressPolicy {
    allow: Vec<Cidr>,
}

impl AddressPolicy {
    /// The policy with `allow` (from `MIMI_OUTBOUND_ALLOW`) taken out of the refused ranges. For test deployments.
    pub fn with_allowlist(allow: Vec<Cidr>) -> Self {
        Self { allow }
    }

    /// Parse a comma-separated allowlist (`addr/len,addr/len`).
    pub fn parse_allowlist(text: &str) -> Result<Vec<Cidr>, String> {
        text.split(',')
            .filter(|part| !part.trim().is_empty())
            .map(Cidr::parse)
            .collect()
    }

    /// `Err(range)` when `addr` is in a refused range and the allowlist does not name it. An IPv4 address written as
    /// IPv6 (`::ffff:a.b.c.d`, the deprecated `::a.b.c.d`, or `64:ff9b::a.b.c.d`) is checked as the IPv4 address it names.
    pub fn check(&self, addr: IpAddr) -> Result<(), &'static str> {
        let addr = embedded_v4(addr).map_or(addr, IpAddr::V4);
        if self.allow.iter().any(|cidr| cidr.contains(addr)) {
            return Ok(());
        }
        match REFUSED.iter().find(|(cidr, _)| cidr.contains(addr)) {
            Some((_, range)) => Err(range),
            None => Ok(()),
        }
    }
}

/// The IPv4 address an IPv6 address carries: IPv4-mapped, IPv4-compatible, or NAT64 well-known prefix.
fn embedded_v4(addr: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = addr else {
        return None;
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let segments = v6.segments();
    let low = || Ipv4Addr::from((u128::from(v6) & 0xffff_ffff) as u32);
    // `::a.b.c.d` (but not `::` or `::1`, which are their own ranges) and `64:ff9b::a.b.c.d`.
    if segments[..6] == [0; 6] && (segments[6] != 0 || segments[7] > 1) {
        return Some(low());
    }
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(low());
    }
    None
}

// ============================ URLs ============================

/// An `https` URL whose host is a peer's domain or a subdomain of it, ready to send to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerUrl {
    host: String,
    port: u16,
    path_and_query: String,
}

impl PeerUrl {
    /// Check `url` for a request to the provider `peer_domain`. The host is compared in lowercase without a trailing
    /// dot; a host that is not ASCII is refused rather than converted.
    pub fn parse(url: &str, peer_domain: &str) -> Result<Self, OutboundError> {
        let rest = url
            .get(..8)
            .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
            .map(|_| &url[8..])
            .ok_or(OutboundError::NotHttps)?;
        if rest.contains('#') {
            return Err(OutboundError::BadUrl("it has a fragment"));
        }
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path_and_query) = rest.split_at(split);
        if authority.contains('@') {
            return Err(OutboundError::BadUrl("it has a userinfo part"));
        }
        if authority.starts_with('[') {
            return Err(OutboundError::BadUrl("its host is an IP literal"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or(OutboundError::BadUrl("its port is not a port"))?,
            ),
            None => (authority, 443),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || !host.is_ascii() {
            return Err(OutboundError::BadUrl("its host is empty or not ASCII"));
        }
        if host.parse::<IpAddr>().is_ok() {
            return Err(OutboundError::BadUrl("its host is an IP literal"));
        }
        if !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        {
            return Err(OutboundError::BadUrl("its host is not a DNS name"));
        }
        let peer = peer_domain.trim_end_matches('.').to_ascii_lowercase();
        if host != peer && !host.ends_with(&format!(".{peer}")) {
            return Err(OutboundError::HostNotPeer { host, peer });
        }
        let path_and_query = if path_and_query.is_empty() {
            "/".to_string()
        } else if path_and_query.starts_with('?') {
            format!("/{path_and_query}")
        } else {
            path_and_query.to_string()
        };
        Ok(Self {
            host,
            port,
            path_and_query,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The `Host` header: the host, and the port when it is not 443.
    fn host_header(&self) -> String {
        match self.port {
            443 => self.host.clone(),
            port => format!("{}:{port}", self.host),
        }
    }
}

// ============================ resolving ============================

/// Name resolution, so a test can map a test domain to a local server. Production uses [`SystemResolver`].
pub trait Resolve: Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;
}

/// The system resolver.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

// ============================ the client ============================

/// Which roots a peer's server certificate may chain to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerTrust {
    /// The system's roots (the web PKI) plus the configured peer bundle.
    #[default]
    SystemAndBundle,
    /// The configured peer bundle only.
    BundleOnly,
}

impl PeerTrust {
    /// `system` or `bundle` (`MIMI_PEER_TRUST`).
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim() {
            "system" => Ok(Self::SystemAndBundle),
            "bundle" => Ok(Self::BundleOnly),
            other => Err(format!(
                "MIMI_PEER_TRUST is {other:?}; it is `system` or `bundle`"
            )),
        }
    }
}

/// An HTTP proxy that tunnels with `CONNECT` (`MIMI_OUTBOUND_PROXY`, `http://host:port`, or `http://user:secret@host:port`
/// for a proxy that requires credentials). The connection to it is plain TCP; TLS to the peer runs inside the tunnel,
/// with the hub's client certificate, end to end. Credentials are sent as `Proxy-Authorization: Basic` on each
/// `CONNECT` and never appear in `Debug`, an error or the startup line.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyAddr {
    host: String,
    port: u16,
    /// `user:secret`, as given.
    credentials: Option<String>,
}

impl std::fmt::Debug for ProxyAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyAddr")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ProxyAddr {
    /// Parse `MIMI_OUTBOUND_PROXY`. An error never quotes the value, since it may carry a secret.
    pub fn parse(text: &str) -> Result<Self, String> {
        const SHAPE: &str =
            "MIMI_OUTBOUND_PROXY is not http://host:port or http://user:secret@host:port";
        let rest = text
            .trim()
            .strip_prefix("http://")
            .ok_or(SHAPE)?
            .trim_end_matches('/');
        let (credentials, rest) = match rest.rsplit_once('@') {
            Some((userinfo, rest)) => {
                let well_formed = userinfo
                    .split_once(':')
                    .is_some_and(|(user, secret)| !user.is_empty() && !secret.is_empty())
                    && userinfo
                        .chars()
                        .all(|c| c.is_ascii_graphic() && c != '/' && c != '@');
                if !well_formed {
                    return Err(SHAPE.to_string());
                }
                (Some(userinfo.to_string()), rest)
            }
            None => (None, rest),
        };
        let (host, port) = rest
            .rsplit_once(':')
            .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
            .filter(|(host, _)| !host.is_empty() && !host.contains(['/', '@']))
            .ok_or(SHAPE)?;
        Ok(Self {
            host: host.trim_matches(['[', ']']).to_string(),
            port,
            credentials,
        })
    }

    /// The `Proxy-Authorization` header line for a `CONNECT`, empty without credentials.
    fn authorization_line(&self) -> String {
        use base64::Engine;
        match &self.credentials {
            Some(credentials) => format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64::engine::general_purpose::STANDARD.encode(credentials)
            ),
            None => String::new(),
        }
    }
}

/// What the client is built from.
pub struct OutboundSettings {
    /// This provider's domain, for `From: mimi@<domain>`.
    pub own_domain: String,
    /// A certificate chain and key presented as the client certificate on every request, if any.
    pub client_certificate: Option<(Vec<u8>, Vec<u8>)>,
    /// The signer every request is signed with, if any.
    pub signer: Option<Arc<crate::request_signing::RequestSigner>>,
    /// Extra trust anchors for peers' server certificates (the peer CA bundle).
    pub peer_bundle_pem: Option<Vec<u8>>,
    pub trust: PeerTrust,
    pub addresses: AddressPolicy,
    pub proxy: Option<ProxyAddr>,
}

/// An answer from a peer.
#[derive(Debug)]
pub struct PeerResponse {
    pub status: u16,
    /// The `Retry-After` header as sent, if there was one.
    pub retry_after: Option<String>,
    pub body: Vec<u8>,
}

/// The outbound client. See the module documentation for what it checks.
pub struct PeerClient {
    own_domain: String,
    posture: String,
    signer: Option<Arc<crate::request_signing::RequestSigner>>,
    tls: TlsConnector,
    addresses: AddressPolicy,
    proxy: Option<ProxyAddr>,
    resolver: Arc<dyn Resolve>,
    telemetry: crate::telemetry::Telemetry,
}

impl PeerClient {
    pub fn new(settings: OutboundSettings, resolver: Arc<dyn Resolve>) -> anyhow::Result<Self> {
        let mut roots = RootCertStore::empty();
        if settings.trust == PeerTrust::SystemAndBundle {
            let native = rustls_native_certs::load_native_certs();
            let (added, _ignored) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                eprintln!("[mimi-hubd] outbound: no system root certificate could be loaded");
            }
        }
        if let Some(bundle) = &settings.peer_bundle_pem {
            for anchor in crate::tls::certs_from_pem(bundle)? {
                roots.add(anchor)?;
            }
        }
        if roots.is_empty() {
            anyhow::bail!("outbound: no trust anchor for peers' server certificates");
        }
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots);
        let mut config = match &settings.client_certificate {
            Some((cert_pem, key_pem)) => builder.with_client_auth_cert(
                crate::tls::certs_from_pem(cert_pem)?,
                crate::tls::key_from_pem(key_pem)?,
            )?,
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let proof = match (&settings.signer, &settings.client_certificate) {
            (Some(signer), Some(_)) => format!(
                "signed with selector {} and a client certificate",
                signer.keyid()
            ),
            (Some(signer), None) => format!("signed with selector {}", signer.keyid()),
            (None, Some(_)) => "a client certificate, not signed".to_string(),
            (None, None) => "UNAUTHENTICATED (no signing key, no client certificate)".to_string(),
        };
        let posture = format!(
            "https only, {proof}, trust {}, special ranges refused{}, {}",
            match settings.trust {
                PeerTrust::SystemAndBundle => "the system roots plus the client CA bundle",
                PeerTrust::BundleOnly => "the client CA bundle only",
            },
            match settings.addresses.allow.len() {
                0 => String::new(),
                n => format!(" except {n} allowlisted range(s)"),
            },
            match &settings.proxy {
                Some(proxy) => format!(
                    "through the CONNECT proxy {}:{}{}",
                    proxy.host,
                    proxy.port,
                    if proxy.credentials.is_some() {
                        " with credentials"
                    } else {
                        ""
                    }
                ),
                None => "direct".to_string(),
            }
        );
        Ok(Self {
            own_domain: settings.own_domain,
            posture,
            signer: settings.signer,
            tls: TlsConnector::from(Arc::new(config)),
            addresses: settings.addresses,
            proxy: settings.proxy,
            resolver,
            telemetry: crate::telemetry::Telemetry::off(),
        })
    }

    /// Record this client's requests to `telemetry` (`crate::telemetry`).
    pub fn with_telemetry(mut self, telemetry: crate::telemetry::Telemetry) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Where this client's requests are recorded.
    pub fn telemetry(&self) -> &crate::telemetry::Telemetry {
        &self.telemetry
    }

    /// One line saying how this client reaches peers, for the startup log.
    pub fn describe(&self) -> &str {
        &self.posture
    }

    pub async fn get(&self, url: &PeerUrl) -> Result<PeerResponse, OutboundError> {
        self.send(url, hyper::Method::GET, None).await
    }

    pub async fn post(
        &self,
        url: &PeerUrl,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<PeerResponse, OutboundError> {
        self.send(url, hyper::Method::POST, Some((content_type, body)))
            .await
    }

    /// The addresses `url`'s host resolves to, in the resolver's order without repeats, once every one has passed the
    /// policy.
    pub async fn vetted_addresses(&self, url: &PeerUrl) -> Result<Vec<SocketAddr>, OutboundError> {
        let addresses = self
            .resolver
            .resolve(&url.host, url.port)
            .await
            .map_err(|error| OutboundError::Resolve {
                host: url.host.clone(),
                error,
            })?;
        for addr in &addresses {
            self.addresses
                .check(addr.ip())
                .map_err(|range| OutboundError::Refused {
                    host: url.host.clone(),
                    addr: addr.ip(),
                    range,
                })?;
        }
        let mut unique = Vec::with_capacity(addresses.len());
        for addr in addresses {
            if !unique.contains(&addr) {
                unique.push(addr);
            }
        }
        if unique.is_empty() {
            return Err(OutboundError::NoAddress(url.host.clone()));
        }
        Ok(unique)
    }

    /// A connection to the first of `addresses` that answers, directly or through the proxy; the last failure if none
    /// does.
    async fn connect_any(&self, addresses: &[SocketAddr]) -> Result<TcpStream, OutboundError> {
        let mut last = OutboundError::NoAddress(String::new());
        for addr in addresses {
            let attempt = match &self.proxy {
                None => {
                    deadline(CONNECT_TIMEOUT, "connecting", async {
                        TcpStream::connect(addr)
                            .await
                            .map_err(OutboundError::Connect)
                    })
                    .await
                }
                Some(proxy) => self.tunnel(proxy, *addr).await,
            };
            match attempt {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    async fn send(
        &self,
        url: &PeerUrl,
        method: hyper::Method,
        body: Option<(&str, Vec<u8>)>,
    ) -> Result<PeerResponse, OutboundError> {
        let addresses = self.vetted_addresses(url).await?;
        let tcp = self.connect_any(&addresses).await?;
        let name = ServerName::try_from(url.host.clone())
            .map_err(|_| OutboundError::BadUrl("its host is not a DNS name"))?;
        let tls = deadline(HANDSHAKE_TIMEOUT, "in the TLS handshake", async {
            self.tls
                .connect(name, tcp)
                .await
                .map_err(|error| OutboundError::Tls(error.to_string()))
        })
        .await?;
        deadline(REQUEST_TIMEOUT, "waiting for the answer", async {
            self.exchange(tls, url, method, body).await
        })
        .await
    }

    /// Open a `CONNECT` tunnel through `proxy` to `addr`, the checked address, never a name.
    async fn tunnel(
        &self,
        proxy: &ProxyAddr,
        addr: SocketAddr,
    ) -> Result<TcpStream, OutboundError> {
        let mut stream = deadline(CONNECT_TIMEOUT, "connecting to the proxy", async {
            TcpStream::connect((proxy.host.as_str(), proxy.port))
                .await
                .map_err(OutboundError::Connect)
        })
        .await?;
        deadline(CONNECT_TIMEOUT, "opening the proxy tunnel", async {
            let target = addr.to_string();
            let authorization = proxy.authorization_line();
            stream
                .write_all(
                    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{authorization}\r\n")
                        .as_bytes(),
                )
                .await
                .map_err(|error| OutboundError::Proxy(error.to_string()))?;
            let status = read_proxy_status(&mut stream).await?;
            if status != 200 {
                return Err(OutboundError::Proxy(format!("CONNECT answered {status}")));
            }
            Ok(())
        })
        .await?;
        Ok(stream)
    }

    async fn exchange<S>(
        &self,
        stream: S,
        url: &PeerUrl,
        method: hyper::Method,
        body: Option<(&str, Vec<u8>)>,
    ) -> Result<PeerResponse, OutboundError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| OutboundError::Http(error.to_string()))?;
        let driver = tokio::spawn(connection);
        let method_name = method.as_str().to_string();
        let method_name = method_name.as_str();
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(url.path_and_query.as_str())
            .header(hyper::header::HOST, url.host_header())
            .header(hyper::header::FROM, format!("mimi@{}", self.own_domain));
        let payload = match body {
            Some((content_type, bytes)) => {
                request = request.header(hyper::header::CONTENT_TYPE, content_type);
                Bytes::from(bytes)
            }
            None => Bytes::new(),
        };
        if let Some(signer) = &self.signer {
            // The target URI as the receiver rebuilds it from what it got: `https://`, the Host header, the path.
            let target_uri = format!("https://{}{}", url.host_header(), url.path_and_query);
            let headers = signer
                .sign(
                    method_name,
                    &target_uri,
                    &format!("mimi@{}", self.own_domain),
                    &payload,
                )
                .map_err(|error| OutboundError::Http(error.to_string()))?;
            request = request
                .header("content-digest", headers.content_digest)
                .header("signature-input", headers.signature_input)
                .header("signature", headers.signature);
        }
        let request = request
            .body(Full::new(payload))
            .map_err(|error| OutboundError::Http(error.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| OutboundError::Http(error.to_string()))?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(hyper::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|error| {
                if error.is::<http_body_util::LengthLimitError>() {
                    OutboundError::TooLarge
                } else {
                    OutboundError::Http(error.to_string())
                }
            })?
            .to_bytes()
            .to_vec();
        driver.abort();
        Ok(PeerResponse {
            status,
            retry_after,
            body,
        })
    }
}

/// Read a proxy's answer to `CONNECT` up to the end of its header block, one byte at a time so nothing of the tunnel
/// is read past it, and return its status code.
async fn read_proxy_status(stream: &mut TcpStream) -> Result<u16, OutboundError> {
    let mut header = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_PROXY_HEADER_BYTES {
            return Err(OutboundError::Proxy(
                "its answer to CONNECT is too long".into(),
            ));
        }
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| OutboundError::Proxy(error.to_string()))?;
        if read == 0 {
            return Err(OutboundError::Proxy("it closed the connection".into()));
        }
        header.push(byte[0]);
    }
    let line = header.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
    std::str::from_utf8(line)
        .ok()
        .filter(|line| line.starts_with("HTTP/1."))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| OutboundError::Proxy("its answer to CONNECT is not HTTP".into()))
}

async fn deadline<T>(
    limit: Duration,
    while_: &'static str,
    work: impl Future<Output = Result<T, OutboundError>>,
) -> Result<T, OutboundError> {
    tokio::time::timeout(limit, work)
        .await
        .unwrap_or(Err(OutboundError::Timeout(while_)))
}

#[cfg(test)]
#[path = "outbound_tests.rs"]
pub(crate) mod tests;
