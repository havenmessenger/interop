//! `POST /groupInfo/{roomId}` (protocol-07 §5.6): what a client needs to join a room by external Commit.
//!
//! The steps, as mimid takes them:
//!
//! 1. A room this hub does not host is `404` (§5.6's `noSuchRoom`, answered as mimid answers it).
//! 2. The body must be a GroupInfoRequest (else `400`), signed with its `requestingSignatureKey`.
//! 3. Its credential must be a BasicCredential naming a user URI whose provider the request's proof authenticates.
//! 4. No joining code (not supported), a room whose tree the hub keeps with a GroupInfo kept for it, and a requester who
//!    may join it by external Commit (`external_join.rs`).
//! 5. The answer is the kept GroupInfo, the room's tree as a `full` RatchetTreeOption and the proposals held for the
//!    epoch with the time each was accepted, encrypted to the request's `groupInfoPublicKey` with the room ID as context,
//!    in a GroupInfoResponse signed by the hub's own MLS key as its `hub_sender` (credential `mimi://<hub domain>`).
//!
//! A refusal at steps 2 to 4, or a hub with no MLS key configured, is `notAuthorized`, the one failure code §5.6 has for
//! it. Nothing is written.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use mimi_core::group_info_wire::{
    encrypt_group_info, group_info_response, GroupInfoCode, GroupInfoRequest, HubSigner,
    PendingProposal,
};

use crate::http::SharedProvider;
use crate::peer::PeerCert;
use crate::Provider;

impl Provider {
    /// Sign GroupInfoResponses with `signer` (`MIMI_HUB_MLS_KEY`).
    pub fn with_hub_signer(mut self, signer: Arc<HubSigner>) -> Self {
        self.hub_signer = Some(signer);
        self
    }
}

/// The hub's MLS signer from a 32-byte Ed25519 seed, its credential naming the hub's own domain.
pub fn hub_signer_from_seed(seed: &[u8], domain: &str) -> anyhow::Result<HubSigner> {
    if seed.len() != 32 {
        anyhow::bail!("the hub's MLS key seed is 32 bytes, not {}", seed.len());
    }
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| anyhow::anyhow!("the hub's MLS key seed is not usable"))?;
    Ok(HubSigner {
        private_key: seed.to_vec(),
        public_key: ring::signature::KeyPair::public_key(&pair)
            .as_ref()
            .to_vec(),
        credential: openmls::prelude::BasicCredential::new(format!("mimi://{domain}").into_bytes())
            .into(),
    })
}

fn answer(room: &str, code: GroupInfoCode) -> Response {
    match group_info_response(room.as_bytes(), code, None) {
        Ok(bytes) => (StatusCode::OK, bytes).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The wire route.
pub async fn group_info_wire(
    State(p): State<SharedProvider>,
    Path(room_id): Path<String>,
    peer: Option<Extension<PeerCert>>,
    body: Bytes,
) -> Response {
    let peer = peer.and_then(|Extension(PeerCert(identity))| identity);
    let provider = p.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let room = mimi_core::uri::canonical(&room_id);
    if provider.assert_hub_of_record(&room).is_err() {
        eprintln!("[mimi-hubd] groupInfo: 404 (not a room this hub hosts)");
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(request) = GroupInfoRequest::decode(&body) else {
        eprintln!("[mimi-hubd] groupInfo: 400 (not a GroupInfoRequest)");
        return StatusCode::BAD_REQUEST.into_response();
    };
    let refuse = |why: &str| {
        eprintln!("[mimi-hubd] groupInfo: notAuthorized ({why})");
        answer(&room, GroupInfoCode::NotAuthorized)
    };
    if request.verify().is_err() {
        return refuse("the request's signature does not verify");
    }
    let Some(requester) = request
        .requester_uri()
        .map(|uri| mimi_core::uri::canonical(&uri))
    else {
        return refuse("the credential names no user");
    };
    let requester_provider = mimi_core::uri::MimiUri::parse(&requester)
        .ok()
        .map(|uri| uri.authority);
    if !requester_provider.is_some_and(|domain| {
        peer.as_ref()
            .is_some_and(|peer| peer.authenticates(&domain))
    }) {
        return refuse("the requester's provider is not the one that sent the request");
    }
    if request.joining_code.is_some() {
        return refuse("joining codes are not supported");
    }
    let Some(signer) = provider.hub_signer.clone() else {
        return refuse("this hub has no MLS key to sign an answer with");
    };
    let Ok(Some(tracking)) = provider.room_tracking(&room) else {
        return refuse("the room's tree is not kept here");
    };
    let Ok(Some((epoch, group_info))) = provider.store.kept_group_info(&room) else {
        return refuse("no GroupInfo is kept for the room");
    };
    if !provider.may_fetch_group_info(&room, &requester) {
        return refuse("the requester may not join this room by external Commit");
    }
    let Some(tree) = provider.tree_option(&tracking) else {
        return refuse("the room's tree could not be read");
    };
    let now = crate::outbox::now_ms() / 1000;
    let pending: Vec<PendingProposal> = provider
        .store
        .held_proposals_timed(&room, epoch, now)
        .unwrap_or_default()
        .into_iter()
        .map(|(proposal, held_at)| PendingProposal {
            proposal,
            hub_accepted_time: held_at.saturating_mul(1000),
        })
        .collect();
    let response = encrypt_group_info(
        &request.group_info_public_key,
        room.as_bytes(),
        &group_info,
        &tree,
        &pending,
    )
    .and_then(|sealed| {
        group_info_response(
            room.as_bytes(),
            GroupInfoCode::Success,
            Some((&signer, &sealed)),
        )
    });
    match response {
        Ok(bytes) => {
            eprintln!("[mimi-hubd] groupInfo: success for epoch {epoch}");
            (StatusCode::OK, bytes).into_response()
        }
        Err(_) => refuse("the answer could not be encrypted to the request's key"),
    }
}
