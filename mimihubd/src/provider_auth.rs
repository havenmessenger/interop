//! Every request to the peer-facing listener is from an authenticated provider (protocol-07 §4.1,
//! draft-atwood-mimi-provider-auth §4 and §10): by the client certificate it presented in the TLS handshake, or, with no
//! certificate, by a signature from a key its provider publishes in DNS ([`crate::signature`]). A request with neither
//! is answered 403 and nothing more (§11). This is the one place the listener decides that, for every route but the
//! directory, which §5.1 has fetched before there is a peer to authenticate.
//!
//! Every request but the directory's names its provider in `From` (`mimi@<domain>`), and the proof must authenticate
//! that domain: a certificate must carry it, and a signature covers it. A signed request's nonce is remembered for the
//! signature's window and a second use refused; a keyMaterial request must carry one when the hub's policy says so.
//!
//! A signature that verifies makes the request's [`PeerCert`] the signed domain, so each route's own question ("does
//! this peer speak for domain X?") is answered the same way for both proofs.

use std::sync::Arc;
use std::time::SystemTime;

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;

use crate::peer::{PeerCert, PeerIdentity};
use crate::signature::{verify_signed, NonceLedger, PeerKeys, Refusal, SignedRequest};

/// The most body a signed request may carry; the routes' own limits are smaller.
const MAX_SIGNED_BODY: usize = 16 * 1024 * 1024;

/// The one route open without a proof.
const DIRECTORY: &str = "/.well-known/mimi-protocol-directory";

/// What the gate checks a signature against: the peers' keys, the nonces already used, and whether a keyMaterial request
/// must carry one (the hub policy's `require_nonce_on_key_material`).
pub struct ProviderAuth {
    pub keys: Arc<PeerKeys>,
    pub nonces: NonceLedger,
    pub require_nonce_on_key_material: bool,
}

/// `router` behind the provider-auth gate, with signatures checked against `keys` and the drafts' default (a nonce is
/// not required, a repeated one is refused).
pub fn with_provider_auth(router: Router, keys: Arc<PeerKeys>) -> Router {
    with_provider_auth_settings(
        router,
        Arc::new(ProviderAuth {
            keys,
            nonces: NonceLedger::default(),
            require_nonce_on_key_material: false,
        }),
    )
}

/// `router` behind the provider-auth gate, with `auth`.
pub fn with_provider_auth_settings(router: Router, auth: Arc<ProviderAuth>) -> Router {
    router
        .layer(axum::middleware::from_fn(
            move |request: Request, next: Next| {
                let auth = auth.clone();
                async move { gate(&auth, request, next).await }
            },
        ))
        // A refusal by the gate itself is answered from outside the router, so it gets the Server header and a problem
        // body here too.
        .layer(axum::middleware::map_response(crate::problem::fallback))
        .layer(axum::middleware::map_response(crate::http::server_header))
}

async fn gate(auth: &ProviderAuth, request: Request, next: Next) -> Response {
    let has_certificate = matches!(
        request.extensions().get::<PeerCert>(),
        Some(PeerCert(Some(_)))
    );
    if request.uri().path() == DIRECTORY {
        return next.run(request).await;
    }
    // A certificate proves the peer; `From` must name a domain it carries (draft-atwood-mimi-provider-auth -01's
    // direction: what the proof binds to is required on every request). A signature checks `From` itself.
    if has_certificate {
        let peer = request
            .extensions()
            .get::<PeerCert>()
            .and_then(|PeerCert(identity)| identity.as_ref());
        let named = request
            .headers()
            .get(axum::http::header::FROM)
            .and_then(|value| value.to_str().ok())
            .and_then(crate::peer::provider_of_from_header);
        if !matches!((named.as_deref(), peer), (Some(domain), Some(peer)) if peer.authenticates(domain))
        {
            eprintln!(
                "[mimihubd] provider auth refused {} {}: no From naming a domain the certificate carries",
                request.method(),
                request.uri().path()
            );
            return crate::problem::NOT_AUTHENTICATED.response();
        }
        let authenticated = named;
        let mut response = next.run(request).await;
        if let Some(domain) = authenticated {
            response
                .extensions_mut()
                .insert(crate::telemetry::AuthenticatedPeer(domain));
        }
        return response;
    }
    let (mut parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_SIGNED_BODY).await else {
        return crate::problem::NOT_AUTHENTICATED.response();
    };
    // Decided before anything is awaited, so no borrow of the request crosses an await.
    let verdict = {
        let host = parts
            .uri
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                parts
                    .headers
                    .get(axum::http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let target_uri = format!("https://{host}{path_and_query}");
        let headers = parts.headers.clone();
        let header = move |name: &str| -> Option<String> {
            let values: Vec<&str> = headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(str::trim)
                .collect();
            (!values.is_empty()).then(|| values.join(", "))
        };
        let signed = SignedRequest {
            method: parts.method.as_str(),
            target_uri: &target_uri,
            authority: &host,
            path: parts.uri.path(),
            query: parts.uri.query(),
            header: &header,
            body: &body,
        };
        let now = SystemTime::now();
        let key_material = parts.uri.path().contains("/keyMaterial");
        verify_signed(&signed, now, &auth.keys).and_then(|verified| {
            if key_material && auth.require_nonce_on_key_material && verified.nonce.is_none() {
                return Err(Refusal::NoNonce);
            }
            let seconds = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |since| {
                    i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
                });
            auth.nonces.record(&verified, seconds)?;
            Ok(verified.domain)
        })
    };
    match verdict {
        Ok(domain) => {
            parts
                .extensions
                .insert(PeerCert(Some(PeerIdentity::signed(&domain))));
            let mut response = next.run(Request::from_parts(parts, Body::from(body))).await;
            response
                .extensions_mut()
                .insert(crate::telemetry::AuthenticatedPeer(domain));
            response
        }
        Err(refusal) => {
            eprintln!(
                "[mimihubd] provider auth refused {} {}: {refusal:?}",
                parts.method,
                parts.uri.path()
            );
            crate::problem::NOT_AUTHENTICATED.response()
        }
    }
}

#[cfg(test)]
#[path = "provider_auth_tests.rs"]
mod tests;
