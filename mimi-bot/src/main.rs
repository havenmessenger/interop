//! mimi-bot: a real, portable MIMI interop test partner. Publishes its own KeyPackage, waits to be
//! invited into a room (accepts every invitation unconditionally - see README.md Security
//! section), and echoes application messages back once it is a member. Built directly on
//! `mimi-core` + `openmls` - no mock, no cheating, no cut corners (DISPATCH-184).
//!
//! Runs CO-LOCATED with the MIMI provider it pairs with, over a private Unix-socket channel with
//! lease-and-ack delivery (the DISPATCH-184 SECOND revision) - not the public mTLS HTTP compat
//! surface a design-gutcheck found had no real event-ordering guarantee and deleted-before-
//! processing (both real desync/data-loss risks for an automated consumer).

mod config;
mod identity;
mod local_channel_client;
mod mls_bot;
mod ratelimit;

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use identity::Identity;
use mls_bot::Rooms;
use ratelimit::RateLimiter;

#[derive(Parser, Debug)]
#[command(
    name = "mimi-bot",
    about = "A real, portable MIMI interop test partner"
)]
struct Args {
    /// TOML config file. If omitted, every setting comes from MIMI_BOT_* env vars (see README.md).
    #[arg(long)]
    config: Option<PathBuf>,
}

/// Fail-closed helper: a required setting that resolved to nothing is a hard, named error - never
/// a silent fallback. Mirrors mimi-hubd's own `read_required_*` wording exactly (DISPATCH-184's own
/// routing note: the two daemons should read as siblings).
fn require(
    resolved: &config::Resolved,
    env_key: &'static str,
    what: &str,
) -> anyhow::Result<String> {
    resolved
        .get(env_key)
        .and_then(|v| v.clone())
        .ok_or_else(|| anyhow::anyhow!("{env_key} is required ({what}) - see README.md quickstart"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let file = match &args.config {
        Some(path) => Some(config::ConfigFile::load(path)?),
        None => None,
    };
    let resolved = config::resolve_all(file.as_ref());

    let bot_domain = require(&resolved, "MIMI_BOT_DOMAIN", "this bot's own domain")?;
    let bot_username = resolved
        .get("MIMI_BOT_USERNAME")
        .and_then(|v| v.clone())
        .unwrap_or_else(|| "mimi-bot".to_string());

    // The private-channel path specifically gets its resolution SOURCE logged (env/file/unset) -
    // which layer supplied it is a statement about the trust boundary (the socket path IS the
    // trust boundary here, no TLS), same reasoning as mimi-hubd's own config.rs::Source doc.
    let (socket_path, socket_src) =
        config::resolve_with_source("MIMI_BOT_SOCKET_PATH", "socket_path", file.as_ref(), None);
    let socket_path = socket_path.ok_or_else(|| {
        anyhow::anyhow!(
            "MIMI_BOT_SOCKET_PATH is required (the paired provider's private channel) - see README.md quickstart"
        )
    })?;
    eprintln!("[mimi-bot] socket_path supplied by: {}", socket_src.label());
    let socket_path = PathBuf::from(socket_path);

    let poll_interval_secs: u64 = resolved["MIMI_BOT_POLL_INTERVAL_SECS"]
        .as_deref()
        .unwrap_or("5")
        .parse()
        .map_err(|_| {
            anyhow::anyhow!("MIMI_BOT_POLL_INTERVAL_SECS must be a non-negative integer")
        })?;
    let rate_limit_max: u32 = resolved["MIMI_BOT_RATE_LIMIT_MAX_PER_WINDOW"]
        .as_deref()
        .unwrap_or("5")
        .parse()
        .map_err(|_| anyhow::anyhow!("MIMI_BOT_RATE_LIMIT_MAX_PER_WINDOW must be an integer"))?;
    let rate_limit_window_secs: u64 = resolved["MIMI_BOT_RATE_LIMIT_WINDOW_SECS"]
        .as_deref()
        .unwrap_or("10")
        .parse()
        .map_err(|_| anyhow::anyhow!("MIMI_BOT_RATE_LIMIT_WINDOW_SECS must be an integer"))?;
    let max_concurrent_rooms: usize = resolved["MIMI_BOT_MAX_CONCURRENT_ROOMS"]
        .as_deref()
        .unwrap_or("50")
        .parse()
        .map_err(|_| anyhow::anyhow!("MIMI_BOT_MAX_CONCURRENT_ROOMS must be an integer"))?;

    let own_uri = format!("mimi://{bot_domain}/u/{bot_username}");
    eprintln!(
        "[mimi-bot] starting as {own_uri}, private channel {}",
        socket_path.display()
    );

    // Sanity check for usability (the plan's own DONE criterion): prove the private channel
    // actually responds before entering the poll loop, rather than retrying forever against a
    // misconfigured socket path. A cheap, harmless probe: lease-and-immediately-not-ack nothing —
    // Ack on an unknown id is defined to return `removed: false`, never an error, so this proves
    // connectivity without side effects.
    eprintln!("[mimi-bot] checking the private channel is reachable...");
    local_channel_client::ack(&socket_path, -1)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "the private channel at {} did not respond: {e} - is the paired provider running \
             with MIMI_LOCAL_SOCKET set to this same path?",
                socket_path.display()
            )
        })?;
    eprintln!("[mimi-bot] private channel reachable");

    let identity = Identity::generate(&own_uri)?;
    let mut rooms = Rooms::new(max_concurrent_rooms);
    let mut limiter = RateLimiter::new(rate_limit_max, Duration::from_secs(rate_limit_window_secs));

    publish_key_package(&socket_path, &bot_username, &identity).await?;

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    let mut tick = tokio::time::interval(Duration::from_secs(poll_interval_secs.max(1)));
    // Independent republish cadence (a second gutcheck pass's finding #11): a tester can claim the
    // one-time KeyPackage and then never send the Welcome (disconnect, crash, abandon) - relying
    // ONLY on "republish after a successful join" left the bot permanently undiscoverable in that
    // case despite continuing to poll normally. Republish on this fixed cadence regardless of
    // Welcome activity; the provider's own K1/K2 one-time-claim + TTL semantics make redundant
    // publishes harmless (each is simply a fresh claimable KeyPackage).
    let mut republish_tick = tokio::time::interval(Duration::from_secs(REPUBLISH_INTERVAL_SECS));
    republish_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = &mut shutdown => {
                eprintln!("[mimi-bot] shutdown signal received, exiting");
                break;
            }
            _ = tick.tick() => {
                if let Err(e) = poll_once(
                    &socket_path, &bot_username, &identity, &own_uri, &mut rooms, &mut limiter,
                ).await {
                    eprintln!("[mimi-bot] poll iteration error (continuing): {e}");
                }
            }
            _ = republish_tick.tick() => {
                if let Err(e) = publish_key_package(&socket_path, &bot_username, &identity).await {
                    eprintln!("[mimi-bot] periodic KeyPackage republish failed (continuing): {e}");
                }
            }
        }
    }
    Ok(())
}

/// How often mimi-bot republishes its KeyPackage independent of Welcome activity (see the loop's
/// own comment on why this can't only be reactive to a successful join).
const REPUBLISH_INTERVAL_SECS: u64 = 300;

/// One publish/republish of this identity's KeyPackage. Called at startup and whenever the bot's
/// own inbox has no queued Welcome to accept (a KeyPackage is one-time-claim, K1/K2 - if a tester
/// already claimed the last one, mimi-bot needs a fresh one waiting for the next tester).
async fn publish_key_package(
    socket_path: &std::path::Path,
    bot_username: &str,
    identity: &Identity,
) -> anyhow::Result<()> {
    let kp_bytes = identity.fresh_key_package_bytes(now_unix())?;
    local_channel_client::publish_key_package(socket_path, bot_username, &kp_bytes)
        .await
        .map_err(|e| anyhow::anyhow!("publishing KeyPackage failed: {e}"))?;
    eprintln!("[mimi-bot] published a fresh KeyPackage for {bot_username}");
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One lease/process/reply/ack cycle. Leases a single event for this bot's own identity from the
/// private channel; a Welcome is accepted (unconditionally - see README.md Security section), an
/// application message/Commit is processed via `Rooms::process_and_reply`. The event is ONLY
/// acked after the corresponding processing step returns success - an unacked lease simply becomes
/// leasable again after its visibility timeout on the provider side, closing the
/// delete-before-processing data-loss risk structurally (a crash mid-processing here just means
/// the SAME event gets leased again next time, not lost).
async fn poll_once(
    socket_path: &std::path::Path,
    bot_username: &str,
    identity: &Identity,
    own_uri: &str,
    rooms: &mut Rooms,
    limiter: &mut RateLimiter,
) -> anyhow::Result<()> {
    let recipient = format!("mimi://{}/u/{bot_username}", identity_domain(own_uri));
    let Some(leased) = local_channel_client::lease_next(socket_path, &recipient, 60).await? else {
        return Ok(()); // nothing waiting
    };

    // Try Welcome first (a distinct MlsMessage body variant from an application message/Commit -
    // accept_welcome/process_and_reply each fail closed on the WRONG variant, so trying one then
    // the other is safe: whichever this event actually is, exactly one succeeds). accept_welcome
    // itself decodes the body BEFORE checking the room-count cap (a second gutcheck pass found the
    // reverse order meant that, once at the cap, EVERY leased event - including an ordinary
    // application message for an already-tracked room - was misclassified as a rejected Welcome
    // and acked without ever reaching process_and_reply below).
    let processed = match rooms.accept_welcome(identity, &leased.room_uri, &leased.bytes) {
        Ok(group_id) => {
            eprintln!(
                "[mimi-bot] joined a new room (group_id {} bytes, {} room(s) now tracked) - \
                 republishing a fresh KeyPackage",
                group_id.len(),
                rooms.len()
            );
            publish_key_package(socket_path, bot_username, identity).await?;
            true
        }
        Err(mls_bot::BotError::NotAWelcome) | Err(mls_bot::BotError::Decode(_)) => {
            match rooms.process_and_reply(identity, &leased.bytes) {
                Ok(Some((reply_room_uri, sender_username, reply_bytes))) => {
                    if !limiter.allow(&sender_username) {
                        eprintln!(
                            "[mimi-bot] rate limit hit for sender {:?}, dropping this reply",
                            String::from_utf8_lossy(&sender_username)
                        );
                    } else {
                        // Fan out via the Room's OWN remembered room_uri (from join time), NOT
                        // `leased.room_uri` - a second gutcheck pass found that trusting a
                        // per-event queue-metadata room_uri for the reply destination let a
                        // submitter address a real group-A ciphertext under a claimed room=B,
                        // misrouting the reply. No sender_hint/exclusion here either - a prior
                        // version excluded a caller-SUPPLIED URI from fan-out, which the same pass
                        // found let a lying submitter suppress delivery to a real OTHER
                        // participant; own-echo loop prevention already guards against mimi-bot
                        // replying to its own prior echo (see mls_bot's sender-credential check),
                        // so self-delivery here is simply harmless, not a risk.
                        match local_channel_client::submit_room_event(
                            socket_path,
                            &reply_room_uri,
                            &reply_bytes,
                        )
                        .await
                        {
                            Ok((delivered, foreign)) => eprintln!(
                                "[mimi-bot] echo reply delivered to {delivered} local member(s) \
                                 ({foreign} foreign not reachable on this surface)"
                            ),
                            Err(e) => eprintln!("[mimi-bot] echo reply submission failed: {e}"),
                        }
                    }
                    true
                }
                Ok(None) => true, // a Commit was merged, or the message was for an untracked room
                Err(e) => {
                    eprintln!("[mimi-bot] could not process a leased event: {e}");
                    false // NOT acked — leave it for a retry rather than silently dropping it
                }
            }
        }
        Err(e) => {
            eprintln!("[mimi-bot] rejected a leased Welcome: {e}");
            true // a real, permanent rejection (not a transient failure) — ack so it isn't retried forever
        }
    };

    if processed {
        local_channel_client::ack(socket_path, leased.event_id).await?;
    }

    limiter.sweep_expired(Duration::from_secs(3600));
    Ok(())
}

fn identity_domain(own_uri: &str) -> &str {
    own_uri
        .strip_prefix("mimi://")
        .and_then(|rest| rest.split("/u/").next())
        .unwrap_or(own_uri)
}

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
