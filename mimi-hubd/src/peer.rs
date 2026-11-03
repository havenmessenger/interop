//! Who is on the other end of a connection.
//!
//! Protocol-07 §4.1: the TLS connection between providers is mutually authenticated, and the certificates presented in
//! the handshake "MUST authenticate the source and target provider domains, according to [RFC6125]". The server
//! configuration (`tls`) already refuses a client certificate that does not chain to the configured client CA. This
//! module carries the certificate that passed to the request handlers, and answers the one question they ask of it:
//! does it authenticate this provider domain?
//!
//! A certificate authenticates a domain when it is valid for it as a DNS name: a `dNSName` subject alternative name
//! that matches exactly or by a leftmost wildcard label. The common name is not read, as RFC 6125 has it. The check is
//! rustls's own (`verify_server_name`), so this crate parses no certificate itself.
//!
//! This answers "which names does this certificate carry?", and nothing about whether the CA that issued it may
//! name them: any CA in the configured client CA bundle can issue a certificate for any name. See DIVERGENCES.md.

use std::future::Future;
use std::io;
use std::pin::Pin;

use axum::middleware::AddExtension;
use axum::Extension;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::ParsedCertificate;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Layer;

/// The end-entity certificate a peer presented in the TLS handshake.
#[derive(Clone, Debug)]
pub struct PeerIdentity {
    end_entity: CertificateDer<'static>,
}

impl PeerIdentity {
    pub fn new(end_entity: CertificateDer<'static>) -> Self {
        Self { end_entity }
    }

    /// True when the certificate is valid for `domain` as a DNS name. An IP address is never a provider domain.
    pub fn authenticates(&self, domain: &str) -> bool {
        let Ok(name) = ServerName::try_from(domain.to_owned()) else {
            return false;
        };
        if !matches!(name, ServerName::DnsName(_)) {
            return false;
        }
        let Ok(parsed) = ParsedCertificate::try_from(&self.end_entity) else {
            return false;
        };
        rustls::client::verify_server_name(&parsed, &name).is_ok()
    }
}

/// What the acceptor puts on every request of a connection: the peer's certificate, or `None` where the connection
/// presented none (the server configuration requires one, so a served connection always has it). A router that is
/// not behind this acceptor has no `PeerCert` at all, and its handlers treat that as an unauthenticated peer.
#[derive(Clone, Debug)]
pub struct PeerCert(pub Option<PeerIdentity>);

/// Wraps the rustls acceptor and hands each request the peer's certificate as a [`PeerCert`] extension.
#[derive(Clone)]
pub struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
}

impl PeerIdentityAcceptor {
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, PeerCert>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let peer = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|cert| PeerIdentity::new(cert.clone().into_owned()));
            Ok((stream, Extension(PeerCert(peer)).layer(service)))
        })
    }
}

/// The provider domain a `From` header names (§4.1): the addr-spec `mimi@<domain>`, lowercased. Anything else, a
/// display name or a different local part included, names no provider.
pub fn provider_of_from_header(value: &str) -> Option<String> {
    let (local, domain) = value.split_once('@')?;
    if local != "mimi" || domain.is_empty() || domain.contains(['@', '<', '>', ' ', ',', ';']) {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}
