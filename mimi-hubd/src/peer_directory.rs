//! Where another provider's endpoints are (protocol-07 §5.1): its directory document, fetched through the outbound client
//! and kept for an hour.
//!
//! A provider's directory is at `<base>/.well-known/mimi-protocol-directory`. The base is `https://<domain>` unless the
//! operator's peer map (`MIMI_PEERS`) gives another for that domain, as a provider that serves its endpoints on a
//! subdomain needs. The base and every endpoint URL taken from a directory go through [`PeerUrl::parse`] for the
//! provider's domain, so a directory can only point at that domain or a subdomain of it. A directory is the top-level
//! JSON object's string values, each an endpoint's URL template; other values are ignored.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::outbound::{OutboundError, PeerClient, PeerUrl};

/// How long a fetched directory is used before it is fetched again.
pub const DIRECTORY_TTL: Duration = Duration::from_secs(3600);

/// Why a provider's endpoint could not be found.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("fetching the directory: {0}")]
    Outbound(#[from] OutboundError),
    #[error("the directory answered {0}")]
    Status(u16),
    #[error("the directory is not a JSON object")]
    NotADirectory,
    #[error("the directory names no {0} endpoint")]
    NoEndpoint(&'static str),
    #[error("the directory's {endpoint} URL: {error}")]
    Endpoint {
        endpoint: &'static str,
        error: OutboundError,
    },
}

/// The operator's peer map: a TOML table of `"<domain>" = "https://<base>"`.
#[derive(Debug, Clone, Default)]
pub struct PeerBases(HashMap<String, String>);

impl PeerBases {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?;
        Self::parse(&text).map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let table: toml::Table = text.parse()?;
        let mut bases = HashMap::new();
        for (domain, base) in table {
            let base = base
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("the base for {domain} is not a string"))?
                .trim_end_matches('/')
                .to_string();
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            PeerUrl::parse(&format!("{base}/"), &domain)
                .map_err(|error| anyhow::anyhow!("the base for {domain}: {error}"))?;
            bases.insert(domain, base);
        }
        Ok(Self(bases))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The base for `domain`: the operator's, or `https://<domain>`.
    pub fn base(&self, domain: &str) -> String {
        self.0
            .get(domain)
            .cloned()
            .unwrap_or_else(|| format!("https://{domain}"))
    }
}

/// A provider's directory: endpoint name to URL template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    endpoints: HashMap<String, String>,
}

impl Directory {
    pub fn parse(body: &[u8]) -> Result<Self, DirectoryError> {
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| DirectoryError::NotADirectory)?;
        let object = value.as_object().ok_or(DirectoryError::NotADirectory)?;
        Ok(Self {
            endpoints: object
                .iter()
                .filter_map(|(name, url)| Some((name.clone(), url.as_str()?.to_string())))
                .collect(),
        })
    }

    /// The URL of `endpoint` for `domain`, with `{variable}` filled with `value` percent-encoded.
    pub fn endpoint(
        &self,
        endpoint: &'static str,
        variable: &str,
        value: &str,
        domain: &str,
    ) -> Result<PeerUrl, DirectoryError> {
        let template = self
            .endpoints
            .get(endpoint)
            .ok_or(DirectoryError::NoEndpoint(endpoint))?;
        let url = template.replace(&format!("{{{variable}}}"), &percent_encode(value));
        PeerUrl::parse(&url, domain).map_err(|error| DirectoryError::Endpoint { endpoint, error })
    }
}

/// Every byte outside RFC 3986's unreserved set as `%XX`, so a `mimi://` URI fills one path segment.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The directories of the providers this hub sends to, fetched on first use and kept for [`DIRECTORY_TTL`].
pub struct Directories {
    bases: PeerBases,
    cache: Mutex<HashMap<String, (Arc<Directory>, Instant)>>,
}

impl Directories {
    pub fn new(bases: PeerBases) -> Self {
        Self {
            bases,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// `domain`'s directory, from the cache while it is fresh, else fetched.
    pub async fn get(
        &self,
        client: &PeerClient,
        domain: &str,
    ) -> Result<Arc<Directory>, DirectoryError> {
        if let Some((directory, fetched)) = self.cached(domain) {
            if fetched.elapsed() < DIRECTORY_TTL {
                return Ok(directory);
            }
        }
        let url = PeerUrl::parse(
            &format!(
                "{}/.well-known/mimi-protocol-directory",
                self.bases.base(domain)
            ),
            domain,
        )?;
        let response = client.get(&url).await?;
        if response.status != 200 {
            return Err(DirectoryError::Status(response.status));
        }
        let directory = Arc::new(Directory::parse(&response.body)?);
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(domain.to_string(), (directory.clone(), Instant::now()));
        Ok(directory)
    }

    /// Drop `domain`'s directory, so the next delivery fetches it again.
    pub fn forget(&self, domain: &str) {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(domain);
    }

    fn cached(&self, domain: &str) -> Option<(Arc<Directory>, Instant)> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(domain)
            .cloned()
    }
}

#[cfg(test)]
#[path = "peer_directory_tests.rs"]
mod tests;
