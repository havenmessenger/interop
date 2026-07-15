//! mTLS termination for the hub. Builds a rustls `ServerConfig` that requires a client certificate
//! signed by the configured client CA (peer-trust allowlist), using the ring crypto provider
//! (aws-lc-rs needs cmake, not assumed present). The server certificate is the hub's own TLS
//! certificate; the client CA is whatever certificate authority signs certificates for the peers
//! this hub chooses to trust (see README.md for how to generate a throwaway CA for local testing).

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

/// Parse a PEM cert chain (one or more certificates).
pub fn certs_from_pem(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut rd = std::io::BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut rd).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in PEM");
    }
    Ok(certs)
}

/// Parse a single PEM private key (PKCS#8 / PKCS#1 / SEC1).
pub fn key_from_pem(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut rd = std::io::BufReader::new(pem);
    rustls_pemfile::private_key(&mut rd)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))
}

/// Build the mTLS `ServerConfig`:
///   - server identity = (`server_cert_pem`, `server_key_pem`), this hub's own TLS certificate
///   - require a client cert chaining to `client_ca_pem`, the configured peer-trust allowlist
///
/// Uses the ring crypto provider explicitly so it works regardless of process-default provider.
pub fn build_mtls_server_config(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> anyhow::Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // Trust anchor for client certs = the configured client CA. This is the peer-trust allowlist:
    // only a peer presenting a cert signed by this CA can complete the handshake.
    let mut roots = RootCertStore::empty();
    for ca in certs_from_pem(client_ca_pem)? {
        roots.add(ca)?;
    }
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;

    let server_certs = certs_from_pem(server_cert_pem)?;
    let server_key = key_from_pem(server_key_pem)?;

    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)?;

    Ok(Arc::new(config))
}

/// Serve `router` over mTLS on `addr`. mTLS terminates here; only clients presenting a cert signed
/// by the CA baked into `config` complete the handshake.
pub async fn serve(
    addr: std::net::SocketAddr,
    router: axum::Router,
    config: Arc<ServerConfig>,
) -> std::io::Result<()> {
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(config);
    axum_server::bind_rustls(addr, tls)
        .serve(router.into_make_service())
        .await
}

/// Same as [`serve`], but drains in-flight requests on SIGTERM (what `systemctl stop` sends) or
/// Ctrl+C/SIGINT instead of dropping connections mid-response. `grace_period` bounds how long a
/// slow in-flight request gets before the process exits regardless.
pub async fn serve_with_graceful_shutdown(
    addr: std::net::SocketAddr,
    router: axum::Router,
    config: Arc<ServerConfig>,
    grace_period: std::time::Duration,
) -> std::io::Result<()> {
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(config);
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        eprintln!(
            "[mimi-hubd] shutdown signal received, draining in-flight requests (grace period {grace_period:?})"
        );
        shutdown_handle.graceful_shutdown(Some(grace_period));
    });
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(router.into_make_service())
        .await
}

/// Waits for either SIGTERM (the signal `systemctl stop` sends) or Ctrl+C/SIGINT (interactive
/// use). SIGTERM handling is unix-only - the shipped systemd unit and .deb both only target
/// Linux, and `tokio::signal::unix` is unix-only by construction.
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install the Ctrl+C (SIGINT) handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install the SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway CA (rcgen 0.14 Issuer) + leaf cert/key issuance for handshake tests.
    pub(crate) fn make_ca() -> (rcgen::Issuer<'static, rcgen::KeyPair>, String) {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-ca");
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        let issuer = rcgen::Issuer::new(params, key); // owns params + signing key
        (issuer, pem)
    }

    /// Issue a leaf cert (server or client) signed by `ca`. Returns (cert_pem, key_pem).
    pub(crate) fn issue(
        ca: &rcgen::Issuer<'_, rcgen::KeyPair>,
        subject_alt_names: Vec<String>,
        common_name: &str,
    ) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(subject_alt_names).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = params.signed_by(&leaf_key, ca).unwrap();
        (leaf.pem(), leaf_key.serialize_pem())
    }

    #[test]
    fn server_config_builds_from_valid_pem() {
        let (ca, ca_pem) = make_ca();
        let (server_cert, server_key) = issue(&ca, vec!["localhost".into()], "mimi-server");
        let cfg = build_mtls_server_config(
            server_cert.as_bytes(),
            server_key.as_bytes(),
            ca_pem.as_bytes(),
        );
        assert!(
            cfg.is_ok(),
            "valid PEM must build an mTLS ServerConfig: {:?}",
            cfg.err()
        );
    }

    #[test]
    fn rejects_empty_pem() {
        assert!(certs_from_pem(b"").is_err());
        assert!(key_from_pem(b"").is_err());
    }

    // ---- REAL end-to-end mTLS handshake proof ----
    // Spins up the actual provider router behind the real mTLS ServerConfig and proves:
    //   (1) a client presenting a cert signed by our CA completes the handshake + gets the directory;
    //   (2) a client presenting NO client cert is REJECTED at the handshake (mTLS is enforced).
    // This is the "no cut corners" verification that mTLS actually works, not just compiles.

    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client_config(
        ca_pem: &str,
        client_identity: Option<(&str, &str)>, // (cert_pem, key_pem)
    ) -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        for ca in certs_from_pem(ca_pem.as_bytes()).unwrap() {
            roots.add(ca).unwrap();
        }
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        match client_identity {
            Some((cert, key)) => builder
                .with_client_auth_cert(
                    certs_from_pem(cert.as_bytes()).unwrap(),
                    key_from_pem(key.as_bytes()).unwrap(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        }
    }

    #[tokio::test]
    async fn mtls_handshake_requires_client_cert() {
        use crate::{http::build_router, Provider};

        // CA + server cert (SAN localhost) + a valid client cert, all from the same CA.
        let (ca, ca_pem) = make_ca();
        let (server_cert, server_key) = issue(&ca, vec!["localhost".into()], "mimi-server");
        let (client_cert, client_key) = issue(&ca, vec![], "test-client");

        let server_cfg = build_mtls_server_config(
            server_cert.as_bytes(),
            server_key.as_bytes(),
            ca_pem.as_bytes(),
        )
        .unwrap();

        // Bind a std listener to grab a free port, then hand it to axum-server.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let provider = Arc::new(Mutex::new(
            Provider::in_memory("havenmessenger.com").unwrap(),
        ));
        let router = build_router(provider);
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(server_cfg);
        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(listener, tls)
                .serve(router.into_make_service())
                .await;
        });
        // give the server a moment to start accepting
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        // (1) WITH a valid client cert → handshake succeeds + directory served.
        {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(
                &ca_pem,
                Some((&client_cert, &client_key)),
            )));
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let mut tls_stream = connector
                .connect(server_name.clone(), tcp)
                .await
                .expect("handshake with a valid client cert must succeed");
            tls_stream
                .write_all(
                    b"GET /.well-known/mimi-protocol-directory HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let mut resp = Vec::new();
            tls_stream.read_to_end(&mut resp).await.unwrap();
            let text = String::from_utf8_lossy(&resp);
            assert!(text.contains("200 OK"), "expected 200, got:\n{text}");
            assert!(
                text.contains("mls_ciphersuites"),
                "directory body must be served over mTLS"
            );
        }

        // (2) WITHOUT a client cert → server REQUIRES one → handshake/exchange fails.
        {
            let connector =
                tokio_rustls::TlsConnector::from(Arc::new(client_config(&ca_pem, None)));
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let result = connector.connect(server_name, tcp).await;
            let rejected = match result {
                Err(_) => true, // handshake refused
                Ok(mut s) => {
                    // Some stacks complete connect() then fail on first I/O; treat no-response as rejected.
                    let _ = s
                        .write_all(b"GET /.well-known/mimi-protocol-directory HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        .await;
                    let mut buf = Vec::new();
                    matches!(s.read_to_end(&mut buf).await, Err(_)) || buf.is_empty()
                }
            };
            assert!(
                rejected,
                "a client WITHOUT a cert must be rejected (mTLS enforced)"
            );
        }
    }
}
