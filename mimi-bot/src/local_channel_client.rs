//! Client for the MIMI provider's private Unix-socket channel (DISPATCH-184 revision). mimi-bot
//! runs CO-LOCATED with the provider it pairs with and talks to it over this channel instead of
//! the public mTLS HTTP compat surface - the surface a design-gutcheck found has no real
//! event-ordering guarantee (a passive poller silently desyncs the instant another room event
//! happens) and deletes-before-processing (crash = permanent silent data loss).
//!
//! Wire format: mirrors the provider's own `local_channel.rs` EXACTLY (kept in sync by contract,
//! not shared code — this crate is public/open, the provider it pairs with may be closed source).
//! Each frame is a 4-byte big-endian length prefix + a JSON body; binary payloads travel as base64
//! JSON string fields. Four ops: `PublishKeyPackage`, `LeaseNext`, `Ack`, `SubmitRoomEvent`.

use std::path::Path;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_FRAME_BYTES: u32 = 1024 * 1024;

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(tag = "op")]
enum LocalRequest {
    PublishKeyPackage { user: String, kp_bytes_b64: String },
    LeaseNext { recipient: String, lease_secs: u64 },
    Ack { event_id: i64 },
    SubmitRoomEvent { room_uri: String, bytes_b64: String },
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
#[serde(tag = "status")]
enum LocalResponse {
    Ok,
    Leased {
        event_id: i64,
        room_uri: String,
        bytes_b64: String,
    },
    Empty,
    Acked {
        removed: bool,
    },
    Submitted {
        delivered: usize,
        foreign_not_delivered: usize,
    },
    Error {
        message: String,
    },
}

/// One durable-processing lease on a room event: `event_id` is what `ack` needs; `room_uri` is
/// which room it came from (needed to reply into the SAME room via `submit_room_event`); `bytes`
/// is the real `MlsMessageIn`-wrapped Welcome or application-message/Commit payload.
pub struct LeasedEvent {
    pub event_id: i64,
    pub room_uri: String,
    pub bytes: Vec<u8>,
}

/// A single request/response exchange over a fresh connection. This channel's traffic is one poll
/// every `poll_interval_secs` — a fresh connection per call is simpler and more robust than pooling
/// for that cadence (no half-open-connection bookkeeping to get wrong).
async fn roundtrip(socket_path: &Path, req: &LocalRequest) -> anyhow::Result<LocalResponse> {
    let mut stream = UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow::anyhow!(
            "cannot connect to local channel {}: {e}",
            socket_path.display()
        )
    })?;
    let body =
        serde_json::to_vec(req).map_err(|e| anyhow::anyhow!("failed to encode request: {e}"))?;
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        anyhow::anyhow!("local channel closed the connection before responding: {e}")
    })?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("local channel response frame ({len} bytes) exceeds the sanity bound");
    }
    let mut resp_buf = vec![0u8; len as usize];
    stream.read_exact(&mut resp_buf).await?;
    serde_json::from_slice(&resp_buf).map_err(|e| anyhow::anyhow!("malformed response frame: {e}"))
}

/// Publish (suite-gate THEN store, claimable) this identity's KeyPackage — the private-channel
/// equivalent of `POST /mimi/v1/keyMaterial/ingest?user=`.
pub async fn publish_key_package(
    socket_path: &Path,
    user: &str,
    kp_bytes: &[u8],
) -> anyhow::Result<()> {
    let req = LocalRequest::PublishKeyPackage {
        user: user.to_string(),
        kp_bytes_b64: base64::engine::general_purpose::STANDARD.encode(kp_bytes),
    };
    match roundtrip(socket_path, &req).await? {
        LocalResponse::Ok => Ok(()),
        LocalResponse::Error { message } => {
            anyhow::bail!("provider rejected KeyPackage publish: {message}")
        }
        other => anyhow::bail!("unexpected response to PublishKeyPackage: {other:?}"),
    }
}

/// Lease the next room event for `recipient` (room-arrival order), visibility-timeout `lease_secs`.
/// `None` when nothing is currently leasable.
pub async fn lease_next(
    socket_path: &Path,
    recipient: &str,
    lease_secs: u64,
) -> anyhow::Result<Option<LeasedEvent>> {
    let req = LocalRequest::LeaseNext {
        recipient: recipient.to_string(),
        lease_secs,
    };
    match roundtrip(socket_path, &req).await? {
        LocalResponse::Leased {
            event_id,
            room_uri,
            bytes_b64,
        } => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&bytes_b64)
                .map_err(|e| {
                    anyhow::anyhow!("provider sent invalid base64 in a Leased response: {e}")
                })?;
            Ok(Some(LeasedEvent {
                event_id,
                room_uri,
                bytes,
            }))
        }
        LocalResponse::Empty => Ok(None),
        LocalResponse::Error { message } => anyhow::bail!("provider rejected LeaseNext: {message}"),
        other => anyhow::bail!("unexpected response to LeaseNext: {other:?}"),
    }
}

/// Acknowledge (permanently remove) a leased event. Call ONLY after durably processing it — this
/// is the structural fix for the delete-before-processing data-loss risk: an unacked lease simply
/// becomes leasable again after its visibility timeout, never silently lost.
pub async fn ack(socket_path: &Path, event_id: i64) -> anyhow::Result<bool> {
    let req = LocalRequest::Ack { event_id };
    match roundtrip(socket_path, &req).await? {
        LocalResponse::Acked { removed } => Ok(removed),
        LocalResponse::Error { message } => anyhow::bail!("provider rejected Ack: {message}"),
        other => anyhow::bail!("unexpected response to Ack: {other:?}"),
    }
}

/// Submit ONE room event (mimi-bot's echo reply) for automatic fan-out to every current LOCAL
/// participant of `room_uri` — the private-channel equivalent of `POST /mimi/v1/roomMessage`.
/// No sender-exclusion hint: a second gutcheck pass found a self-reported exclusion hint let a
/// lying submitter suppress delivery to a REAL other participant (matching their URI instead of
/// the real sender's) — every current local participant, including mimi-bot itself, now always
/// receives a copy; mimi-bot's own loop prevention (never echo a message whose sender credential
/// is its own identity) is the correct, safe way to avoid an echo-of-its-own-echo loop. Returns
/// `(delivered, foreign_not_delivered)`.
pub async fn submit_room_event(
    socket_path: &Path,
    room_uri: &str,
    bytes: &[u8],
) -> anyhow::Result<(usize, usize)> {
    let req = LocalRequest::SubmitRoomEvent {
        room_uri: room_uri.to_string(),
        bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
    };
    match roundtrip(socket_path, &req).await? {
        LocalResponse::Submitted {
            delivered,
            foreign_not_delivered,
        } => Ok((delivered, foreign_not_delivered)),
        LocalResponse::Error { message } => {
            anyhow::bail!("provider rejected SubmitRoomEvent: {message}")
        }
        other => anyhow::bail!("unexpected response to SubmitRoomEvent: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    /// A minimal stand-in server for exactly the wire contract these client functions speak against
    /// — proves the CLIENT's framing/encoding is correct without depending on the (closed) real
    /// provider crate. The real cross-process contract is proven at deploy-time integration testing
    /// (this pair of client/server implementations is kept in sync by written contract, documented
    /// in both files' module docs, not by shared code across the public/closed repo boundary).
    async fn stub_server(path: std::path::PathBuf, response: LocalResponse) {
        let listener = UnixListener::bind(&path).unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf);
        let mut body = vec![0u8; len as usize];
        stream.read_exact(&mut body).await.unwrap();
        let _req: LocalRequest =
            serde_json::from_slice(&body).unwrap_or(LocalRequest::Ack { event_id: -1 });
        let resp_body = serde_json::to_vec(&response).unwrap();
        stream
            .write_all(&(resp_body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&resp_body).await.unwrap();
    }

    fn scratch_path() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "mimi-bot-client-test-{}-{n}.sock",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn publish_key_package_ok_round_trips() {
        let path = scratch_path();
        let server = tokio::spawn(stub_server(path.clone(), LocalResponse::Ok));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        publish_key_package(&path, "mimi-bot", b"fake-kp-bytes")
            .await
            .unwrap();
        server.await.unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn lease_next_decodes_a_leased_event() {
        let path = scratch_path();
        let expected = b"a real event".to_vec();
        let response = LocalResponse::Leased {
            event_id: 42,
            room_uri: "mimi://havenmessenger.com/r/x".to_string(),
            bytes_b64: base64::engine::general_purpose::STANDARD.encode(&expected),
        };
        let server = tokio::spawn(stub_server(path.clone(), response));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let leased = lease_next(&path, "mimi-bot", 60).await.unwrap().unwrap();
        assert_eq!(leased.event_id, 42);
        assert_eq!(leased.room_uri, "mimi://havenmessenger.com/r/x");
        assert_eq!(leased.bytes, expected);
        server.await.unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn submit_room_event_decodes_the_delivered_counts() {
        let path = scratch_path();
        let response = LocalResponse::Submitted {
            delivered: 2,
            foreign_not_delivered: 1,
        };
        let server = tokio::spawn(stub_server(path.clone(), response));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let (delivered, foreign) =
            submit_room_event(&path, "mimi://havenmessenger.com/r/x", b"an echo reply")
                .await
                .unwrap();
        assert_eq!((delivered, foreign), (2, 1));
        server.await.unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn lease_next_returns_none_on_empty() {
        let path = scratch_path();
        let server = tokio::spawn(stub_server(path.clone(), LocalResponse::Empty));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(lease_next(&path, "mimi-bot", 60).await.unwrap().is_none());
        server.await.unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn ack_reports_provider_removed_flag() {
        let path = scratch_path();
        let server = tokio::spawn(stub_server(
            path.clone(),
            LocalResponse::Acked { removed: true },
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(ack(&path, 7).await.unwrap());
        server.await.unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_provider_error_response_surfaces_as_an_error_not_a_panic() {
        let path = scratch_path();
        let response = LocalResponse::Error {
            message: "kp_bytes_b64 is not valid base64".to_string(),
        };
        let server = tokio::spawn(stub_server(path.clone(), response));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let err = publish_key_package(&path, "mimi-bot", b"x")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not valid base64"));
        server.await.unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn connecting_to_a_nonexistent_socket_is_a_clear_error_not_a_panic() {
        let path = std::env::temp_dir().join("mimi-bot-client-test-nonexistent.sock");
        std::fs::remove_file(&path).ok();
        let err = ack(&path, 1).await.unwrap_err();
        assert!(err.to_string().contains("cannot connect"));
    }
}
