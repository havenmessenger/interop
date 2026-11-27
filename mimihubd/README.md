# mimihubd

A reference MIMI hub daemon: mTLS-terminated HTTP server, durable SQLite-backed state, and the
v1 request-handling semantics (add-driven membership, text-only content, the MLS ciphersuites the
deployment accepts) over [`mimi-core`](..)'s gate, consent, and room-policy logic.

## Wire format: read this before you rely on interop

This hub speaks two lanes side by side.

**`/mimi/v1/*`** is JSON. It implements the *semantics* of the v1 endpoints (the gate, the consent
flow, the room-policy RBAC, the ciphersuite restriction) faithfully, but its request/response bodies
are not the TLS presentation-language framing `draft-ietf-mimi-protocol` defines.

**`/mimi/pl/*`** is the draft's actual wire framing (TLS presentation language, RFC 8446 §3), routed
for nine endpoints: `submitMessage` (§5.4), `requestConsent`/`updateConsent` (§5.7), `keyMaterial`
(§5.2), `notify` inbound-receive (§5.5), `identifierQuery` (§5.8), `reportAbuse` (§5.9), `groupInfo` (§5.6, for an
external join; DIV-1), and `update` (§5.3, bounded - see below). Every wire route decodes the same bytes a strict protocol-07
client would send and calls the identical business logic the JSON lane calls, so state written
through one lane is readable through the other (proven below for `keyMaterial`). The path segment
on the request/consent/keyMaterial/update/reportAbuse routes plays the same opaque routing-key role
the JSON lane's query parameters play. Message delivery follows the room's participant list: what the
hub accepts for a room it hosts goes to each local participant's queue and, as a FanoutMessage, to
each other provider with a participant (DIVERGENCES.md, DIV-5). The directory (`/.well-known/mimi-
protocol-directory`) advertises all eight under `wireEndpoints`, with concrete path templates.

`update` (§5.3) takes an `UpdateRequest` and answers an `UpdateRoomResponse`. It handles one bounded
case: a Commit whose proposal list holds a single proposal changing the room. A participant-list
change is read from an AppDataUpdate for component `0x0022` or from the private type `0xF7A0`, and a
room-policy change from an AppDataUpdate for `roles_list` (`0x0025`) or `base_room_policy`
(`0x0027`), and applies it to the room's stored participant list or policy. For a room whose
ratchet tree it keeps (a tracked room), the hub first verifies the Commit against the tree with
openmls: the sender must be a member whose signature verifies, the Commit must be for the room's
group and epoch, and it must apply to the tree; one that does not is refused and changes nothing.
A room is tracked from the first accepted Commit whose bundle carries a Full GroupInfo and a full
ratchet tree, after checks on who sent it (`../DIVERGENCES.md`, DIV-10), and takes its policy
and participant list from the group's GroupContext; each change to a tracked room is then authorized
for the member who proposed it (DIV-15). `untrackRoom` on the operator's listener drops a room's tree. A room hosted
here that the hub keeps no tree for takes no change the hub cannot authorize: its first Commit, and any participant-list
or room-policy change to it, is taken only with a bundle carrying a Full GroupInfo and the full ratchet tree that seed
the tree, and is otherwise refused (`notAllowed`, saying so); the seeding Commit's changes are authorized for its
committer (DIV-10). The policy's `untracked_rooms = "accept"` is the other choice: the hub applies changes it cannot
authorize, reading an untracked room's Commit without verifying its signature, as RFC 9420's delivery-service model
allows.
`success` means that change was applied. The hub does not store or relay the Commit; another epoch
than the room's is `wrongEpoch`. A Commit mixing that proposal with a standard MLS proposal (Add/Remove/Update,
...) in the same proposal list is refused - full general Commit processing is out of scope for this
reference hub. `groupInfo` (§5.6) is not built yet (DIV-1): it is the external-commit join
endpoint, and framing it without the accept-path behind it would wire-format half of a
security-relevant endpoint. Asset download (§5.10) has no v1
handler of any kind to frame. The four v1 room-admin JSON endpoints
(`roomPolicy`/`memberRole`/`addParticipant`/`authorizeSender`) are not protocol-07 endpoints at all -
they are this hub's own RBAC surface, not part of the draft's wire vocabulary - so there is nothing
to frame them against.

Output from the wire lane against a live hub, with MLS objects on the wire.

`submitMessage`, round-tripped against the JSON lane's store:

```
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @submit_message.bin \
    https://localhost:8443/mimi/pl/submitMessage/xxx@haven -w '\nHTTP_STATUS=%{http_code}\n'
HTTP_STATUS=200
# response body: 01 00 00000000 6a4d6bba  (protocol=mls10, code=accepted, accepted_timestamp)

$ curl -s "http://127.0.0.1:8445/mimi/v1/operator/message?user=xxx@haven" -o fetched.bin
# fetched.bin is byte-identical to the MLS envelope inside submit_message.bin: the wire and
# JSON lanes read from the same store. A local user's queue is the operator's to read (on the
# loopback listener, MIMI_ADMIN_BIND_ADDR), never a peer's.
```

`keyMaterial`, published over the *JSON* lane and served back over the *wire* lane, proving the two
lanes share one store in both directions, not just one:

```
$ curl -s -X POST --data-binary @bob_kp.bin \
    "http://127.0.0.1:8445/mimi/v1/operator/keyMaterial?user=bob" -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=204
# Bob is a user of this hub, so his KeyPackage is published by its operator, on the loopback listener.

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @km_req.bin \
    https://localhost:8443/mimi/pl/keyMaterial/bob -o km_resp.bin -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=200
# the served KeyPackage bytes inside km_resp.bin are byte-identical to bob_kp.bin (290-byte
# response: userStatus=success, one ClientKeyMaterial entry, the KeyPackage as published)
```

`notify` (an application message wrapped as `FanoutMessage`, for a room on another hub that no user here is a member
of, so it is refused with the `no-local-member` problem) and `identifierQuery` (a wire-encoded query for a user the
hub does not answer for, which gets the same `notFound` answer as a name nobody has):

```
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @notify.bin \
    https://localhost:8443/mimi/pl/notify/mimi%3A%2F%2Fexample.com%2Fr%2Fdemo -w '\nHTTP_STATUS=%{http_code}\n'
{"type":"https://github.com/havenmessenger/interop/blob/main/docs/problems.md#no-local-member","title":"Not delivered: no member of the room here","status":404,"detail":"No user of this provider is a member of the room: no Welcome for it has named one."}
HTTP_STATUS=404

# The same body for a room on a hub this certificate is not: only a room's hub sends a notify for it.
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @notify.bin \
    https://localhost:8443/mimi/pl/notify/mimi%3A%2F%2Fother.example%2Fr%2Fdemo -w '\nHTTP_STATUS=%{http_code}\n'
{"type":"https://github.com/havenmessenger/interop/blob/main/docs/problems.md#not-the-rooms-hub","title":"Not from the room's hub","status":403,"detail":"Only the hub that hosts a room sends a notify for it, and the request's provider is not that hub."}
HTTP_STATUS=403

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @idq.bin \
    https://localhost:8443/mimi/pl/identifierQuery -o idq_resp.bin -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=200
$ xxd -p idq_resp.bin
01000000
```

## Quickstart (env vars)

**This is a reference implementation, not yet hardened for unsupervised public exposure.** It's
positioned as a reference/demo artifact. A deployment carrying live traffic should be
network-restricted (an allowlist, not open to the internet), and current limitations (see
`../SECURITY.md` and `../DIVERGENCES.md`) are disclosed here rather than discovered the hard way.

You need `cargo` and `openssl` (or any tool that can issue a CA and a leaf certificate signed by
it). This daemon requires mTLS: it will not start without a server certificate, a server key, and
a client CA to validate incoming peer certificates against.

```bash
mkdir -p /tmp/mimihubd-demo
CERTDIR=/tmp/mimihubd-demo

# A throwaway CA.
openssl req -x509 -newkey rsa:2048 -nodes -keyout $CERTDIR/ca-key.pem -out $CERTDIR/ca-cert.pem \
  -days 365 -subj "/CN=mimihubd-demo-ca"

# A server certificate for localhost, signed by that CA.
openssl req -newkey rsa:2048 -nodes -keyout $CERTDIR/server-key.pem -out $CERTDIR/server-req.pem \
  -subj "/CN=localhost"
openssl x509 -req -in $CERTDIR/server-req.pem -CA $CERTDIR/ca-cert.pem -CAkey $CERTDIR/ca-key.pem \
  -CAcreateserial -out $CERTDIR/server-cert.pem -days 365 \
  -extfile <(echo "subjectAltName=DNS:localhost")

# A client certificate, also signed by that CA - this is what a peer presents to be trusted. Its
# DNS name is the provider domain it speaks for: `notify` is accepted only from the provider that
# hosts the room it names (protocol-07 §5.5), so this one is the hub of rooms under example.com.
openssl req -newkey rsa:2048 -nodes -keyout $CERTDIR/client-key.pem -out $CERTDIR/client-req.pem \
  -subj "/CN=demo-client"
openssl x509 -req -in $CERTDIR/client-req.pem -CA $CERTDIR/ca-cert.pem -CAkey $CERTDIR/ca-key.pem \
  -CAcreateserial -out $CERTDIR/client-cert.pem -days 365 \
  -extfile <(echo "subjectAltName=DNS:example.com")

# Run the hub from the repo root (cargo needs the workspace Cargo.toml; the cert paths above are
# already absolute, so this does not need to run from $CERTDIR).
MIMI_PROVIDER_DOMAIN=example.com \
MIMI_BIND_ADDR=127.0.0.1:8443 \
MIMI_ADMIN_BIND_ADDR=127.0.0.1:8445 \
MIMI_DB_PATH=/tmp/mimihubd-demo/hub.db \
MIMI_SERVER_CERT=/tmp/mimihubd-demo/server-cert.pem \
MIMI_SERVER_KEY=/tmp/mimihubd-demo/server-key.pem \
MIMI_CLIENT_CA=/tmp/mimihubd-demo/ca-cert.pem \
cargo run -p mimihubd
```

Output from the sequence above:

```
[mimihubd] MIMI_SERVER_CERT supplied by: env
[mimihubd] MIMI_SERVER_KEY supplied by: env
[mimihubd] MIMI_CLIENT_CA supplied by: env
[mimihubd 0.0.1] domain=example.com db=/tmp/mimihubd-demo/hub.db listening (mTLS) on 127.0.0.1:8443
```

In a second terminal, query the directory with a client certificate signed by the same CA:

```bash
curl -s --cacert /tmp/mimihubd-demo/ca-cert.pem --cert /tmp/mimihubd-demo/client-cert.pem \
  --key /tmp/mimihubd-demo/client-key.pem \
  https://localhost:8443/.well-known/mimi-protocol-directory
```

Output from the sequence above:

```json
{
    "endpoints": {
        "identifierQuery": "/mimi/v1/identifierQuery",
        "keyMaterial": "/mimi/v1/keyMaterial",
        "message": "/mimi/v1/message",
        "notify": "/mimi/v1/notify",
        "requestConsent": "/mimi/v1/requestConsent",
        "submitMessage": "/mimi/v1/submitMessage",
        "updateConsent": "/mimi/v1/updateConsent",
        "welcome": "/mimi/v1/welcome"
    },
    "mls_ciphersuites": [1],
    "protocol_drafts": {"content": "10", "protocol": "07", "room-policy": "04"},
    "provider": "example.com",
    "unsupported": {
        "assets_ohttp": "DIV-3: v1 is messaging-only",
        "groupInfo_external_commit_join": "DIV-1: not built yet; joins are add-driven",
        "reportAbuse_with_abusive_messages": "DIV-9: a report attaching an AbusiveMessage is refused (its Frank cannot yet be verified) - metadata-only reports are accepted",
        "update_wire_endpoint_mixed_commits": "DIV-10: a Commit is applied when it carries exactly one participant-list or room-policy change, alone or with Add and Remove proposals beside it; proposals by reference are accepted only when they are the ones this hub holds for a member's leave. A second change, a Commit with no change, any other proposal type and any other proposal by reference are refused"
    },
    "wireEndpoints": {
        "identifierQuery": "/mimi/pl/identifierQuery/{domain}",
        "keyMaterial": "/mimi/pl/keyMaterial/{targetUser}",
        "notify": "/mimi/pl/notify/{roomId}",
        "reportAbuse": "/mimi/pl/reportAbuse/{roomId}",
        "requestConsent": "/mimi/pl/requestConsent/{targetDomain}",
        "submitMessage": "/mimi/pl/submitMessage/{roomId}",
        "update": "/mimi/pl/update/{roomId}",
        "updateConsent": "/mimi/pl/updateConsent/{requesterDomain}"
    }
}
```

A request without a client certificate is rejected at the TLS handshake (curl exits 56, connection
reset), proving mTLS is actually enforced rather than merely configured.

## Quickstart (config file)

The same settings can come from a TOML file instead of (or layered under) env vars - useful
for a systemd/`.deb` deployment where a config file is the more natural interface than an
environment block. Reusing the certs generated above:

```bash
cat > /tmp/mimihubd-demo/mimihubd.toml <<'EOF'
provider_domain = "example.com"
bind_addr = "127.0.0.1:8443"
db_path = "/tmp/mimihubd-demo/hub.db"
server_cert = "/tmp/mimihubd-demo/server-cert.pem"
server_key = "/tmp/mimihubd-demo/server-key.pem"
client_ca = "/tmp/mimihubd-demo/ca-cert.pem"
EOF

cargo run -p mimihubd -- --config /tmp/mimihubd-demo/mimihubd.toml
```

Output from the sequence above - note `supplied by: file` instead of `env`, the only
observable difference from the env-only run above:

```
[mimihubd] MIMI_SERVER_CERT supplied by: file
[mimihubd] MIMI_SERVER_KEY supplied by: file
[mimihubd] MIMI_CLIENT_CA supplied by: file
[mimihubd 0.0.1] domain=example.com db=/tmp/mimihubd-demo/hub.db listening (mTLS) on 127.0.0.1:8443
```

Any `MIMI_*` env var set alongside `--config` still overrides that one key from the file (a
deployment can be mostly file-config with one setting pinned by the environment) - and a env var
set to the empty string is treated as not-set, falling through to the file/default rather than
becoming an empty override.

## Installing as a service

Beyond `cargo run`, this daemon packages like a normal system service:

- **systemd unit**: [`debian/mimihubd.service`](debian/mimihubd.service) - a hardened unit
  (dedicated non-root user, `ProtectSystem=strict`, `NoNewPrivileges=true`, `UMask=0077`, and more)
  that reads `/etc/mimihubd/mimihubd.toml` by default. It ships **not** enabled and **not**
  started: this daemon is fail-closed on missing mTLS material, so a fresh install has nothing
  valid to start with yet. Fill in your certificates and config, then
  `systemctl enable --now mimihubd` yourself.
- **`.deb` package**: built via [`cargo-deb`](https://github.com/kornelski/cargo-deb) from
  [`mimihubd/Cargo.toml`](Cargo.toml)'s `[package.metadata.deb]` section. Creates a dedicated
  system user on install (`debian/postinst`), installs the systemd unit and two config templates
  (`/etc/mimihubd/mimihubd.toml.example`, `/etc/mimihubd/mimihubd.env.example`), and on
  `purge` (not plain `remove`) wipes `/etc/mimihubd` and `/var/lib/mimihubd` while deliberately
  leaving the system user in place (`debian/postrm`) - reusing a freed system UID for an unrelated
  future package is a known packaging hazard. Build it yourself: `cargo install cargo-deb --locked
  && cargo deb -p mimihubd`.
- **Prebuilt binaries and the `.deb`**: attached to each GitHub Release by
  [`.github/workflows/release.yml`](../.github/workflows/release.yml), for `x86_64` and `aarch64`
  Linux. These are ordinary `glibc`-linked, dynamically-linked binaries (built on the GitHub-hosted
  `ubuntu-latest` runner's glibc) - not static binaries; a target glibc materially older than that
  runner's may not be compatible. Each archive ships alongside a `.sha256` checksum file.
- **Docker**: [`../Dockerfile`](../Dockerfile) (repo root, since the build context needs both
  `mimi-core` and `mimihubd`) - a multi-stage build producing a minimal runtime image that runs
  as the same dedicated non-root user. Pushed to `ghcr.io/havenmessenger/mimihubd` by the same
  release workflow.

All four installation paths take the identical env-var/config-file interface documented below -
packaging changes how you *install* the daemon, never what it *does*.

## Configuration reference

Ten settings, either as env vars or as keys in a `--config <path>` TOML file (see the two
quickstarts above). An env var, if set to a non-empty value, always overrides the same key from
the file - see [`debian/mimihubd.toml.example`](debian/mimihubd.toml.example) and
[`debian/mimihubd.env.example`](debian/mimihubd.env.example) for filled-in templates.

| Env var | TOML key | Required | Default | Meaning |
|---|---|---|---|---|
| `MIMI_PROVIDER_DOMAIN` | `provider_domain` | yes | none, hard error if unresolved | This hub's own domain, used in the directory response and in `From`-authority checks. |
| `MIMI_SERVER_CERT` | `server_cert` | yes | none | PEM path, this hub's TLS server certificate (+ chain). |
| `MIMI_SERVER_KEY` | `server_key` | yes | none | PEM path, this hub's TLS server private key. |
| `MIMI_CLIENT_CA` | `client_ca` | yes | none | PEM path, the CA that signs client certificates for peers this hub trusts. A peer presenting a cert this CA signed is allowed to call the hub's endpoints; a peer may instead sign its requests with a DNS-published key (`MIMI_PEER_KEYS`, see Peer authentication). The fingerprint (SHA-256) of each CA in the file is logged at startup, and so is which layer (env/file) supplied it, since it's a statement about the actual trust boundary, not just an ergonomic detail. |
| `MIMI_BIND_ADDR` | `bind_addr` | no | `0.0.0.0:8443` | Listen address. |
| `MIMI_DB_PATH` | `db_path` | no | `/var/lib/mimi/provider.db` | SQLite file path for durable state. This binary-level default is unchanged by packaging - the shipped `.toml.example` template recommends `/var/lib/mimihubd/hub.db` instead (matching the systemd unit's `StateDirectory=`), but that is the template's choice, not a change to this daemon's own default. |
| `MIMI_PUBLIC_BASE_URL` | `public_base_url` | no | `https://{MIMI_PROVIDER_DOMAIN}` | The `https://` URL the directory's endpoint URLs start at, for a hub behind a reverse proxy, on a port other than 443, or on a dedicated host. Identifiers keep using `MIMI_PROVIDER_DOMAIN`. One trailing `/` is dropped; a query, fragment or non-`https` URL is a hard error at startup. |
| `MIMI_DIRECTORY_BIND_ADDR` | `directory_bind_addr` | no | none | A second listener, plain HTTP and with no client certificate, that answers `GET /.well-known/mimi-protocol-directory` and nothing else. It is meant to sit behind whatever terminates TLS for the public name. Unset means there is no such listener. |
| `MIMI_ADMIN_BIND_ADDR` | `admin_bind_addr` | no | none | The operator's listener: plain HTTP with no client certificate, serving `roomPolicy`, `memberRole`, `addParticipant`, `untrackRoom`, `outbox`, `dropOutbox` and the three `operator/` routes for local users, and nothing else. It must be a loopback `ip:port` (127.0.0.0/8 or `::1`); any other address stops the hub at start. Unset means there is no such listener, and no request can change a room's policy, roles or participants except a peer's `update`. |
| `MIMI_LANE_BIND_ADDR` | `lane_bind_addr` | no | none | The client lane's listener (below), off when unset. When set, the three below are required and a missing or unreadable one stops the start. |
| `MIMI_LANE_CERT` | `lane_cert` | with the lane | none | PEM path, the lane listener's TLS certificate (+ chain). |
| `MIMI_LANE_KEY` | `lane_key` | with the lane | none | PEM path, the lane listener's TLS private key. |
| `MIMI_LANE_ROOM_POLICY` | `lane_room_policy` | no | the neutral profile | TOML file of what a room the lane creates starts with: its room policy, the role its creator holds and whether it allows external Commits (format in `mimihubd/src/client_lane_rooms.rs`). A file the hub cannot read or that is not a valid profile stops the start. The neutral profile: admins add, remove, ban and change roles, members send and may leave, the creator is an admin, external Commits are refused. |
| `MIMI_LANE_KEYS` | `lane_keys` | with the lane | none | Path of a JSON file of the client-facing service's signing keys, `{"<keyid>._mimi.client-lane": "<base64 Ed25519 public key>"}`, an empty value for a revoked key. |
| `MIMI_LANE_DELIVERY` | `lane_delivery` | no | `inbox` | How the hub hands this provider's users what it holds for them: `inbox` (per-user, legacy), a queue per user read with `inboxFetch`/`inboxAck`, or `events` (provider stream), one stream for the whole provider read by pull on the lane or pushed (below, "Delivering to your server: push or pull"). `events` needs a reader: the lane, or `MIMI_EVENTS_PUSH_URL`. Any other value stops the start. |
| `MIMI_EVENTS_PUSH_URL` | `events_push_url` | no | none | With `MIMI_LANE_DELIVERY=events`, the `https` URL of the provider's own server the hub pushes the event stream to; its host is the provider's domain or a subdomain of it, and its addresses pass the outbound gate under the push's own allowlist (`MIMI_EVENTS_PUSH_ALLOW`). Needs `MIMI_SIGNING_KEY`: every push is signed. Unset means no push. |
| `MIMI_EVENTS_PUSH_ALLOW` | `events_push_allow` | no | none | Comma-separated `addr/len` ranges the push destination may be at although they are special (loopback, private, ...), for a provider server on its own network. It applies to the push alone: `MIMI_OUTBOUND_ALLOW` does not apply to the push, and this one never to a request to a peer. A value that does not parse stops the start. |
| `MIMI_POLICY` | `policy` | no | none | A TOML file of the deployment's choices, below. Unset means the drafts' defaults. A named file the hub cannot read, or one that is not a valid policy, stops the start. |
| `MIMI_PEER_KEYS` | `peer_keys` | no | none | Path of a JSON file of peers' DNS-published signing keys, `{"<keyid>._mimi.<domain>": "<base64 Ed25519 public key>"}`, an empty value for a revoked key. Re-read when it changes. Without it, no signature verifies and only a client certificate admits a peer. |
| `MIMI_ACTIVITY_LOG` | `activity_log` | no | off | `1` prints one line per request on the peer-facing listener to stderr: `[mimi-activity] method=POST route=/mimi/pl/update/:room_id status=200`. The route is the template the request matched (`route=unmatched` when none did), so no path, query string, header, certificate or body appears in it. Any other value, or none, leaves it off. The directory-only listener is not logged. |
| `MIMI_LAST_RESORT_REUSE` | `last_resort_reuse` | no | `false` | `true` keeps a claimed last-resort KeyPackage (draft-ietf-mls-extensions §6.4) to hand out again; `false` hands it out once and deletes it, as protocol-07 §5.2 has it ("Keying material provided from one response MUST NOT be provided in any other response"). Any other value stops the start. `../DIVERGENCES.md`, DIV-23, has what reuse rests on and its limits. |
| `MIMI_OTLP_ENDPOINT` | `otlp_endpoint` | no | off | The base URL of an OpenTelemetry collector that takes OTLP/HTTP with protobuf bodies (`/v1/traces` and `/v1/metrics` are added). `https`, or `http` only to a loopback address (`localhost`, 127.0.0.0/8, `::1`): the collector is the operator's own, so requests to it skip the outbound gate, and this is the gate's stance applied to it. Exported: a span and the counters and latency histograms `mimi.server.requests`/`mimi.server.duration` (requests peers make) and `mimi.client.requests`/`mimi.client.duration` (requests this hub makes), with the method, route template, status or failure class, the peer provider's domain, a refusal's problem type and a delivery's attempt number. Never a path value, query, header, certificate, body, user or room. Needs a build with the `otlp` feature (the release binary and .deb have it); the startup log says `otlp: off (not built)`, `otlp: off`, or `otlp: <endpoint>`. |
| `MIMI_OUTBOUND_ALLOW` | `outbound_allow` | no | none | Comma-separated `addr/len` ranges an outbound request may reach although they are special (loopback, private, link-local, ...), for a test deployment whose peers run on such addresses. A value that does not parse stops the start. See "Outbound requests" below. |
| `MIMI_OUTBOUND_PROXY` | `outbound_proxy` | no | none | An HTTP `CONNECT` proxy for outbound requests, `http://host:port`, or `http://user:secret@host:port` for a proxy that requires credentials (sent as `Proxy-Authorization: Basic` on each `CONNECT`; the secret is never logged or shown in an error). With a proxy the hub does not resolve: the `CONNECT` names the peer's host and port, and the proxy resolves it and is trusted to check the addresses. TLS with the hub's client certificate runs end to end inside it. |
| `MIMI_PEER_TRUST` | `peer_trust` | no | `system` | The roots a peer's server certificate may chain to: `system` (the system's roots plus `MIMI_CLIENT_CA`) or `bundle` (`MIMI_CLIENT_CA` only). |
| `MIMI_CLIENT_CERT` | `client_cert` | no | `MIMI_SERVER_CERT`, for a hub that does not sign | PEM path of the certificate outbound requests present, with `MIMI_CLIENT_KEY`. With a signing key set and this unset, no client certificate is presented. Set both or neither. |
| `MIMI_SIGNING_KEY` | `signing_key` | no | none | Path of a file holding the provider's request-signing key, a base64 32-byte Ed25519 seed (for example `head -c 32 /dev/urandom` encoded as base64), mode 0600, never in a repository. With it, every outbound request is signed. Set with `MIMI_SIGNING_SELECTOR`. |
| `MIMI_SIGNING_SELECTOR` | `signing_selector` | no | none | The key's DNS selector: its public half is the TXT record `v=MIMI1; k=ed25519; p=...` at `<selector>._mimi.<MIMI_PROVIDER_DOMAIN>`. |
| `MIMI_HUB_MLS_KEY` | `hub_mls_key` | no | none | Path of a file holding the hub's own MLS signing key, a base64 32-byte Ed25519 seed, mode 0600, kept apart from `MIMI_SIGNING_KEY`. It signs `groupInfo` answers as the hub's `hub_sender` (credential `mimi://<MIMI_PROVIDER_DOMAIN>`). Unset, every `groupInfo` request is answered `notAuthorized`. |
| `MIMI_CLIENT_KEY` | `client_key` | no | `MIMI_SERVER_KEY` | PEM path of that certificate's key. |
| `MIMI_PEERS` | `peers` | no | none | A TOML file of `"<peer domain>" = "https://<base>"`, for a peer whose directory is not at `https://<domain>` (mimid serves it at its configured base, such as `https://mimi.a.example`). A base outside the peer's domain stops the start. |

The daemon never falls back to plain HTTP: a missing certificate, key, or CA path is a hard error
at startup, not a degraded-but-running mode - and mTLS material is validated *before* the SQLite
store is opened, so a bad or missing certificate fails before anything touches disk. An
unrecognized key in a `--config` file is logged as a warning (not a hard error - a genuinely new,
forward-compatible key should not break parsing), which also means a *typo'd* key surfaces as a
diagnostic instead of a silent no-op.

### The policy file

Where the drafts leave a choice to the deployment, the hub reads it from the file `MIMI_POLICY` names. Every field has
a default that is the drafts' behaviour; the hub prints the policy it runs with at startup.

```toml
# The MLS ciphersuites accepted from other providers, as wire values. Default: every suite the
# crypto provider implements. The directory's `mls_ciphersuites` advertises exactly this list.
mls_ciphersuites = [0x0001]
# Who identifierQuery may find. "all" (default): every user this hub can answer for, which on this
# hub means a user it has enrolled or holds an unexpired KeyPackage for. "enrolled": only users
# enrolled with `mimihubd enroll`.
identifier_discovery = "enrolled"
# Refuse a signed keyMaterial request that carries no nonce (default false: provider-auth -00 has no nonce). A
# repeated nonce is always refused.
require_nonce_on_key_material = true
# An external Commit to a room whose operational policy says nothing: "allow" (default, as MLS: subject to who may
# join) or "deny".
external_commit_when_unset = "allow"
# A room hosted here whose ratchet tree the hub does not keep. "refuse" (default): its first Commit, and any
# participant-list or room-policy change to it, is taken only with a bundle carrying a Full GroupInfo and the full
# ratchet tree, so every change is authorized for its proposer. "accept": the hub applies changes it cannot authorize,
# trusting the members to have checked them, until a bundle gives it the tree (DIVERGENCES DIV-10).
untracked_rooms = "refuse"
# Consent on the client lane (protocol-07 §8). Each of these is the deployment's choice and changes without code.
# Decide for every user of a provider (default false: the draft's scope is one requesting user). A provider grant is
# read against the requester URI's domain, which any peer naming a room on its own domain can choose (DIVERGENCES
# DIV-6), so on it admits any authenticated peer: leave it off unless every peer is trusted.
consent_provider_grants = false
# Send a revoke to the requester's provider (default false: §8, "typically not communicated").
consent_revoke_notifies = false
# Keep a user's consent decisions when they opt out (default false: opting in again starts over).
consent_kept_at_opt_out = false
# Days a consent request made of a user stays pending (default 30; 0 stops the start).
consent_request_days = 30
```

A key the hub does not know, an empty suite list, or a suite the crypto provider does not implement stops the start,
so a misspelt policy never runs as the defaults. Either discovery setting answers every miss with the same `notFound`;
protocol-07 §5.8's privacy considerations say what discovery reveals and are worth reading before choosing.

## Peer authentication

Every request on the peer-facing listener is from an authenticated provider, decided in one place for every route but
the directory (`provider_auth.rs`):

- by a client certificate that chains to `MIMI_CLIENT_CA` and names the provider's domain (protocol-07 §4.1), or
- with no certificate, by an HTTP Message Signature (RFC 9421) from a key the provider publishes in DNS, as
  draft-atwood-mimi-provider-auth §5 has it: tag `mimi`, covering `@method`, `@target-uri`, `from` and, when the request
  has content, `content-digest` (sha-256); `created` within 300 s in the past and 60 s in the future; the key at
  `<keyid>._mimi.<From domain>`.

A request with neither is answered 403, with nothing more. A signed request's domain is the one its `From` header names,
so a route's own check of which provider is calling reads the same for both proofs.

The hub does not query DNS. A job on the host resolves the key records through a DNSSEC-validating resolver (an answer
that does not validate gives no key) and writes the `MIMI_PEER_KEYS` file; the record's TTL bounds how stale it may be.

## Outbound requests

Every request this hub makes to another provider goes through one client (`src/outbound.rs`), and nothing else opens a
connection. Before connecting it requires an `https` URL whose host is the peer's domain or a subdomain of it, resolves
the host once, and refuses the request if any address it resolves to is in a special range (loopback, unspecified,
link-local, private, shared, unique-local, multicast, documentation, reserved), unless `MIMI_OUTBOUND_ALLOW` names it;
it then connects to that checked address. With `MIMI_SIGNING_KEY` and `MIMI_SIGNING_SELECTOR` set, every request is
signed with the provider's DNS-published key (draft-atwood-mimi-provider-auth §5), and a client certificate is presented
only when `MIMI_CLIENT_CERT` / `MIMI_CLIENT_KEY` name one. Without a signing key, the client certificate is
`MIMI_CLIENT_CERT` when set, else `MIMI_SERVER_CERT` / `MIMI_SERVER_KEY`, which then needs the `clientAuth` extended key
usage as well as `serverAuth` (a Let's Encrypt certificate has `serverAuth` only). The peer's server certificate must
be valid for the host connected to. Requests carry
`From: mimi@<MIMI_PROVIDER_DOMAIN>`; redirects are not followed. The startup log says how the client reaches peers.

A peer's endpoints come from its directory, `<base>/.well-known/mimi-protocol-directory`, where the base is
`https://<domain>` unless `MIMI_PEERS` gives another. Fan-out for other providers waits in the outbox, one queue per
room and provider, delivered in order by a worker in the hub (`../DIVERGENCES.md`, DIV-5, says what each answer does);
`GET /mimi/v1/outbox` and `POST /mimi/v1/dropOutbox` on the operator's listener show and drop queues. What goes into
the outbox: an accepted Commit, the Welcome in its bundle, held leave proposals and application messages, for each
other provider with a participant in the room (DIV-5). A `keyMaterial` request for another provider's user, for a room
this hub hosts and from a participant who may add participants, is forwarded to that provider, and each KeyPackage it
returns is recorded so the Welcome that uses it goes there; any other such request is answered `noConsent`. The
provider path takes a `keyMaterial` request only from the provider of the user it names as requester, or from the hub
of the room it names (403 `not-permitted` otherwise), and only when its path and its `targetUser` name the same user
(400 `malformed-request` otherwise; `../DIVERGENCES.md`, DIV-6). One requesting provider (the domain the peer proved; the
requester it names is not counted) may make at most 5 `keyMaterial` requests an hour for one target user; past that the hub answers 429
`key-material-rate-limited` (`../docs/problems.md`).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/mimi-protocol-directory` | Advertises supported ciphersuite, draft revisions, and endpoint URLs. |
| GET | `/mimi/v1/keyMaterial?user=` | Serve one local user's KeyPackage: a one-time one, or the last-resort one when none is left (handed out once unless `MIMI_LAST_RESORT_REUSE` is `true`). |
| POST | `/mimi/v1/keyMaterial/ingest` | Gate + optionally publish a KeyPackage, for a user of the provider the peer's proof names (403 otherwise; never for a user of this provider, whose operator publishes on its own listener). |
| POST | `/mimi/v1/notify?room=` | Idempotent fanout receipt; the peer must be the hub of `room` (403 otherwise). |
| POST | `/mimi/v1/welcome/ingest` | Gate a Welcome; with `?recipient=`, relay it for a user of the peer's own provider (403 for a user of this provider). |
| GET | `/mimi/v1/welcome?user=` | Deliver-once pull of a Welcome queued for a user of the peer's own provider (403 for a user of this provider). |
| POST | `/mimi/v1/submitMessage?recipient=` | Deposit an opaque application message for a user of the peer's own provider (403 for a user of this provider, whose queue only this hub's fan-out and operator fill). |
| GET | `/mimi/v1/message?user=` | Deliver-once pull of a message queued for a user of the peer's own provider (403 for a user of this provider). |
| POST | `/mimi/v1/identifierQuery` | Opt-in-only identifier lookup. |
| POST | `/mimi/v1/requestConsent` | Consent request or cancel (§5.7 C1), always 201. A cancel withdraws only a pending request, and only from the requester's provider. The wire route answers 202, and 422 for an operation it does not take. |
| POST | `/mimi/v1/updateConsent` | Consent grant/revoke (§5.7 C2), always 201. Recorded only from the provider of its target user, for a requester of this provider (§5.7); a peer cannot record a decision for this hub's own users. |
| POST | `/mimi/v1/authorizeSender?room=&sender=` | Check whether a sender may send in a room. |

### The client lane

MIMI defines how providers talk to each other, not how a provider's own clients reach their hub. The client lane is
this hub's answer for a provider whose client-facing service authenticates its users itself: that service signs each
request for one of this hub's users, and the hub acts for that user and no other. It is a local extension, not a MIMI
route (DIVERGENCES, DIV-19), served only on the listener `MIMI_LANE_BIND_ADDR` names, under `/mimi/client/v1/`.

Every request is an RFC 9421 signature with tag `mimi-client-lane`, covering `@method`, `@target-uri`,
`content-digest`, `mimi-client-user` and `mimi-client-device`, with `created`, `nonce` and `keyid`; it verifies with a
key in `MIMI_LANE_KEYS`, its nonce is new, it is at most 30 s old, and it was signed after this process started.
`mimi-client-user` must be a user URI on this hub's domain; the routes act for that user and take no user from a body.
A refused request is a 401 `client-not-authenticated`; past 600 requests a minute for one user, a 429
`client-rate-limited` (`docs/problems.md`). Bodies are JSON with MLS objects in base64, at most 4 MiB.

| Path | Body → answer | What it does |
|---|---|---|
| `publishKeyPackages` | `{key_packages}` → `{count}` | Adds KeyPackages for the user (at most 32 a request; the hub keeps 64 a user, dropping the oldest one-time ones). Each passes the suite gate and names the user, exactly, in its credential: a Basic credential's identity, or the one `mimi:` URI in the `alsoKnownAs` of a `did_webvh` credential's log when the log verifies and authorizes the leaf's key. One whose credential is of another type is answered 400 `credential-not-supported` (DIV-24). One-time KeyPackages are handed out first, once each; a last-resort one (draft-ietf-mls-extensions) only when none is left, once, or again and again when `MIMI_LAST_RESORT_REUSE` is `true`; the newest replaces the one before. |
| `keyPackageCount` | `{}` → `{one_time, last_resort}` | How many unexpired one-time KeyPackages the user has here, and whether a last-resort one is: what the client reads to know when to publish more. |
| `withdrawKeyPackages` | `{}` → `{count}` | Removes them; no one can claim the user's KeyPackages after. |
| `inboxFetch` | `{after_welcome, after_message, limit}` → `{welcomes, messages, more}` | With `MIMI_LANE_DELIVERY=inbox` (the default; a hub delivering through the event stream answers this and `inboxAck` with 409 `delivery-mode`). Reads the user's queued Welcomes and messages after the cursors, oldest first (at most 256 of each), without removing them. Each item is `{seq, bytes, received_at}`; a Welcome's also has `room`, the room it joins, when the hub queued it for one (a room it hosts, or the room a hub's notify named). |
| `inboxAck` | `{welcomes_up_to, messages_up_to}` → `{welcomes, messages}` | Removes the user's items up to the cursors. |
| `createRoom` | `{}` → 201 `{room, creator_role, components}` | A room hosted here under a fresh URI, with the user as its only participant, in the creator role, room policy and external-Commit setting of the deployment's profile (`MIMI_LANE_ROOM_POLICY`); the client names none of them. The answer gives the role the user holds and the room's components (`[{id, data}]`, `data` base64: its `roles_list`, `base_room_policy` and operational policy): the client's group starts with them and a participant list naming the user in `creator_role`. Once the creator's group is tracked, its own components are the room's state; a first Commit whose GroupInfo would seed the tree with other components is refused (`notAllowed`), so a room keeps the profile it was created with. |
| `submitMessage` | `{room, message}` → `{}` | An application message into the room, from the user. In a room hosted here: 403 `not-permitted` unless the user is an active participant whose role may send; 400 `not-an-application-message` unless `message` is a PrivateMessage carrying application content (RFC 9420 §6; a Commit or a proposal goes to `update`); in a room whose tree the hub keeps, 400 `group-mismatch` unless the message's MLS framing names the room's group at an epoch the room has reached (no message is decrypted; an earlier epoch is taken); fanned out as from a peer. In a room on another hub: sent to that hub's `submitMessage` as this provider, naming the user as the sender (protocol-07 §3.4), and answered as it answers (403 for its refusal, 502 `upstream-failed` when it cannot be reached or this hub has no outbound client). |
| `update` | `{room, update}` → `{answer, ...}` | `update` is the UpdateRequest as the wire carries it (a Commit bundle, or a leave's proposals). The same checks as the provider path's `update`, with the user as the requester: a leave removes only the user, an external Commit joins only the user, a GroupInfo seeding the room's tree is signed by the user. The answer is the wire's: `success` (with the room's `epoch`), `wrongEpoch` (with `current_epoch`), `notAllowed` or `invalidProposal` (with a `description`). For a room on another hub the update is sent to that hub's `update` as this provider, and its answer passed on (`success` with no `epoch`; 502 when it cannot be reached). |
| `keyMaterial` | `{request}` → `{response}` | `request` is the client's `KeyMaterialRequest` (protocol-07 §5.2) naming the room, signed with the user's MLS key; its `requestingUser` and its credential must be the user and its signature must verify (403 otherwise). The MLS signature shows the request was made with the key it names; that the request is the user's is what the lane signature on it says, as on every lane request. For a room hosted here it is answered as the provider path answers it (a user of another provider's through that provider); for a room on another hub it is sent there, the room's hub (§5.2: "MUST be sent via the hub provider of whatever room"). `response` is the `KeyMaterialResponse`. At most 30 a minute per user, and 5 an hour per user for one target user (429 `client-rate-limited`). |
| `consent` | `{requester \| provider, room?, decision}` → `{notified}` | The user's consent (protocol-07 §8) to a requesting user fetching their KeyPackages: `decision` is `grant` or `revoke`, for any room or for `room`. It is recorded at this hub, where it gates the user's KeyPackages, replacing a pending request of the same scope; a revoke with no request is a preemptive one. A grant to a user of another provider is sent to that provider as `updateConsent`, a revoke only when the policy's `consent_revoke_notifies` says so; `notified` is whether that provider took it, and the decision stands either way. `provider` (a domain) decides for every user of that provider, for any room, only when the policy's `consent_provider_grants` is on (403 otherwise); a user's own decision is read before it. |
| `requestConsent` | `{target, room?, cancel?}` → `{delivered}` | Asks `target` for consent to fetch their KeyPackages, or cancels that request. For a user of another provider it is sent there as `requestConsent`; for a user of this provider it is recorded here. `delivered` is whether it was taken. |
| `consentRequests` | `{after?, limit?}` → `{requests: [{seq, requester, room?, at}]}` | The requests made of the user that are still pending, oldest first, after `seq` `after`, at most 100. A request leaves the list when the user decides, when the requester cancels, or after the policy's `consent_request_days`. |
| `consentReceived` | `{}` → `{grants: [{target, room?, at}]}` | The grants the user holds from other users, a user of another provider's from its `updateConsent`. A revoke is never listed. |
| `optOut` | `{}` → `{count, cleared}` | Withdraws the user's KeyPackages, as `withdrawKeyPackages`, and, unless the policy's `consent_kept_at_opt_out`, clears the user's consent decisions and the requests made of them: `count` KeyPackages, `cleared` consent records. |

#### Delivering to your server: push or pull

A hub delivers in one of two modes: `inbox` (per-user, legacy), the default, a queue per user read with `inboxFetch`
and `inboxAck`; or `events` (provider stream). A hub with `MIMI_LANE_DELIVERY=events` keeps one stream of everything it holds for the provider's users, in place of a
queue per user, and the provider's own server reads it, much as a mail server hands mail to a delivery agent. Each event
has a `seq`, one more than the event before it, across every user and room: Welcomes, room messages and consent
changes come in the order the hub took them, one ordering for the whole provider, stricter than ordering per room. The
server reads the stream one of two ways, the same events in the same order with the same cursor either way:

- **Pull.** The server opens every connection. It waits for events, fetches them, and acknowledges what it handled.
- **Push.** The hub posts the events to the server's URL (`MIMI_EVENTS_PUSH_URL`), one batch at a time, and a `2xx`
  acknowledges it.

Which one a deployment uses is its own choice: a hub placed where it may not open connections to the provider's network
pulls, and one that may can push. An operator can switch between them at any time: the cursor is the hub's, so nothing
past the last acknowledged `seq` is lost or delivered twice by the switch.

An event, as `events/fetch` answers it and a push posts it (`{events: [...], more}`, at most 256 events and 4 MiB of
payload past the first event; `more` says further events were waiting):

| Field | What it is |
|---|---|
| `seq` | Its place in the stream. |
| `kind` | `welcome`, `message` (an MLSMessage for the room: a Commit, a proposal or an application message, as the hub took it) or `consent`. |
| `user` | The user it is for, as a URI on this provider's domain. |
| `room` | The room: for a message, always; for a Welcome, when the hub knew which room it joins; for a consent change, when it is for one room. |
| `bytes` | The MLS object, base64, for `welcome` and `message`. The hub never reads it. |
| `consent` | For `consent`: `{requester, target, room?, state}`, `state` being `requested` (for the target to decide), `granted` or `revoked` (for the requester), or `withdrawn` (a pending request its requester took back, for the target). |
| `received_at` | When the hub took it, in Unix seconds. |

Delivery is at least once: a batch is posted again if its acknowledgement is lost. The server keeps the highest `seq`
it has handled and skips any event at or below it. Events stay until they are acknowledged. A user's backlog is bounded
as a user's queue is (32 Welcomes, 256 messages, 256 consent changes); past it, a new item for that user is refused and
takes no `seq`, so the stream has no gaps.

**Pull.** Three provider-level calls on the lane, each signed with a lane key as the provider's server signing for
itself: tag `mimi-client-lane-provider`, covering `@method`, `@target-uri` and `content-digest` (no user or device
header), with the same `created`, `nonce` and age rules as a user's request. A signature for a user is not accepted on
these routes, nor one for the provider on a user's route.

| Path | Body → answer | What it does |
|---|---|---|
| `events/wait` | `{after_seq, timeout_ms}` → `{latest_seq, users}` | Held until an event past `after_seq` exists, then answered at once with the last `seq` and the users with events past `after_seq`; at `timeout_ms` (at most 25000) answered with no users. |
| `events/fetch` | `{after_seq, limit}` → `{events, more}` | The events past `after_seq`, in `seq` order, left in place. |
| `events/ack` | `{up_to_seq}` → `{acked_through}` | Takes every event up to `up_to_seq` out of the stream and moves the cursor there. The cursor only moves forward; `up_to_seq` past the last event is refused with 400 `ack-past-end`, so an acknowledgement can never skip an event written later. |
| `info` | `{}` → `{lane_version, delivery, push, stream?, push_status?}` | The lane's contract version (`1`), `inbox` or `events`, and whether the hub pushes. For `events`, `stream` is `{last_seq, acked_through}`. For a hub that pushes, `push_status` is `{acked_through, failures, last_error?, last_attempt_at?}`: a push the server keeps refusing shows its failures and why, never an event's content. |

A server written in Rust can link `mimihubd-api` (in this repository), the lane as a library: its types, the signing
of both lane profiles, and the check of a pushed batch. mimihubd uses the same library for its own side.

A server's loop: `events/wait` from its last handled `seq`; when `latest_seq` is past it, `events/fetch`, handle the
events in order, `events/ack` the last one; repeat.

**Push.** With `MIMI_EVENTS_PUSH_URL` set, the hub posts each batch to that URL as `application/json`, signed like every
request the hub makes (`MIMI_SIGNING_KEY`, RFC 9421, the key published at `<selector>._mimi.<domain>`; plus the client
certificate when one is configured), so the server knows it came from its hub. One batch is in flight at a time, in
`seq` order.

- A `2xx` acknowledges through the batch's last `seq`, and the next batch follows.
- Any other answer, or none, is retried after 1 s, doubling to at most 5 minutes, or later when the server's
  `Retry-After` asks for it.
- No answer causes a batch to be skipped, a `4xx` included: a skipped batch would be lost events.
- After a restart the hub resumes from the last acknowledged `seq`.

A push that keeps failing is never given up: the lane's `info` shows it (`push_status`), and the hub logs a line when
the push starts failing, when the reason changes, and when it goes through again, not on every retry.

The URL's host must be the provider's domain or a subdomain of it. Its addresses pass the outbound gate, which refuses
loopback, private and the other special ranges, under an allowlist of the push's own: `MIMI_EVENTS_PUSH_ALLOW` names the
ranges a provider server on its own network may be at. That allowlist is the operator's statement about one destination
it configured, so it applies to the push and nothing else; `MIMI_OUTBOUND_ALLOW`, which widens what a peer-supplied
destination may reach, does not apply to the push, and the push's allowlist never applies to a peer. The push connects
directly, never through `MIMI_OUTBOUND_PROXY`: a hub that can reach its provider's server only through a proxy pulls
instead.

```toml
# The hub posts the stream to the provider's own server.
lane_delivery = "events"
events_push_url = "https://app.example.com/mimi-events"
# The server is on the provider's own network: name its range, addr/len.
events_push_allow = "<the server's range>"
signing_key = "/etc/mimihubd/signing.key"
signing_selector = "hub1"
```

```text
POST /mimi-events HTTP/1.1
Host: app.example.com
Content-Type: application/json
Content-Digest: sha-256=:...:
Signature-Input: mimi=("@method" "@target-uri" "content-digest" "from");created=...;nonce="...";keyid="hub1";tag="mimi"
Signature: mimi=:...:

{"events":[{"seq":41,"kind":"welcome","user":"mimi://example.com/u/bob","room":"mimi://example.com/r/1f..","bytes":"AAEA..","received_at":1767225600},
           {"seq":42,"kind":"message","user":"mimi://example.com/u/bob","room":"mimi://example.com/r/1f..","bytes":"AAEA..","received_at":1767225601}],
 "more":false}
```

A pulling deployment sets `lane_delivery = "events"` and no push URL, and its server calls the routes above on the lane.

With `MIMI_LANE_DELIVERY=events`, the per-user queues are not written: `inboxFetch` and `inboxAck` answer 409
`delivery-mode`, and the operator's deliver-once `operator/welcome` and `operator/message` find nothing. A hub
delivering per user (the default) writes no events, and the `events/*` routes answer 409 `delivery-mode`. Changing a
running hub from one mode to the other leaves what the other mode holds where it is, so drain it first.

The operator's routes are served only on the loopback listener `MIMI_ADMIN_BIND_ADDR` names, never to a peer. They are
not MIMI routes; a peer changes a room's roster or policy through `update`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/mimi/v1/roomPolicy?room=` | Set a room's RBAC policy. |
| POST | `/mimi/v1/memberRole?room=&member=&role=` | Assign a member's role in a room. |
| POST | `/mimi/v1/addParticipant?room=&member=` | Register a room participant. |
| POST | `/mimi/v1/untrackRoom?room=` | Drop the room's ratchet tree; its next bundle with a Full GroupInfo and a full tree seeds it again. |
| GET | `/mimi/v1/outbox` | Each queue of fan-out waiting for another provider: room, domain, depth, oldest row, and its head's attempts and last outcome. A queue the outbound client refuses (for example a peer resolving into a refused range) never moves on its own; its last outcome says why. |
| POST | `/mimi/v1/dropOutbox?room=&domain=` | Drop that queue, every row of it; answers how many. |
| POST | `/mimi/v1/operator/keyMaterial?user=` | Publish a KeyPackage for a user of this provider (a bare name or a URI on its domain), through the suite gate. |
| GET | `/mimi/v1/operator/welcome?user=` | Take one Welcome queued for a user of this provider (deliver-once). |
| GET | `/mimi/v1/operator/message?user=` | Take one message queued for a user of this provider (deliver-once). |

### How user and room URIs compare

The hub stores and compares every `mimi://` URI in its canonical form (RFC 3986 §6.2.2, `mimi_core::uri::canonical`):
the scheme and the host in lowercase, a percent-encoded unreserved character decoded, any other percent-encoding's hex
digits in uppercase; the path keeps its case, and a path written as an IRI is mapped to its URI (RFC 3987 §3.1: any
byte that may not stand as itself in a path is percent-encoded from its UTF-8). So `MIMI://A.Example/u/%61lice` and
`mimi://a.example/u/alice` are the same user, and so are `mimi://a.example/u/zoë` and `mimi://a.example/u/zo%C3%AB`. A store written before this rewrites its URIs once, at the first open, and logs any row it left because its
canonical form was already stored.

## Enrolling a handle for identifierQuery

`identifierQuery` answers `success` for a user the hub answers for (the policy's `identifier_discovery`, under the
configuration reference), and the one `notFound` answer for every other, both HTTP 200 on the wire lane (the JSON
lane answers 404 with no body). An enrolled handle is always found. No route enrolls a handle, so no peer can make a
user discoverable this way. The operator does it, on the hub's host:

```bash
mimihubd --config /etc/mimihubd/mimihubd.toml enroll erin
# or with the environment alone:
MIMI_DB_PATH=/var/lib/mimihubd/hub.db mimihubd enroll erin
```

Output from the sequence above:

```
enrolled "erin" for identifierQuery in /var/lib/mimihubd/hub.db
```

It takes the database path from the settings the daemon takes, reads no certificate and needs no provider domain. Run
it as the user the daemon runs as. A running hub reads its store at each query, so it answers for the handle from its
next request and there is nothing to restart. The handle is matched exactly. Enrolling one that is already there
changes nothing.

It refuses when no database is at the path it resolved, and creates none: run without the hub's settings it would
otherwise make a new, empty database at the default path and enroll the handle there, while the hub's own store
stayed as it was.

## Seeding a hub for a visiting implementation

[`../examples/seed_table.sh`](../examples/seed_table.sh) puts on a running hub what another implementation needs to
test against it, through the routes above: a user with KeyPackages, a user with none, a consent grant from each to the
visiting user, and a room whose first participant is the visiting user. Its `check` mode then asks the wire lane what
that visitor would ask.

```bash
HUB=https://localhost:8443 CACERT=/tmp/mimihubd-demo/ca-cert.pem \
CERT=/tmp/mimihubd-demo/client-cert.pem KEY=/tmp/mimihubd-demo/client-key.pem \
PEER_USER=mimi://other.example/u/alice ../examples/seed_table.sh seed
```

The KeyPackages are real ones under ciphersuite 0x0001, made by
[`../examples/seed_fixtures.rs`](../examples/seed_fixtures.rs). Their private keys are never written anywhere, so a
Welcome made for a seeded user cannot be opened: the users exist for the hub's answers, not to join a group.

`identifierQuery` takes one more step, on the hub's host: `mimihubd enroll <handle>` (above). The script's `check`
says whether the handle it was given is enrolled.

## What this hub does not do (v1 scope)

- **§5.6 GroupInfo / external-commit join.** Not built yet; membership is add-driven.
- **Assets / OHTTP (§5.10).** v1 is messaging-only.
- **General `update` (§5.3) Commit processing.** Only a Commit whose proposal list holds exactly
  one participant-list or room-policy proposal is applied - a Commit mixing it with a standard MLS
  proposal in the same list is refused. An untracked room's Commit is not verified against any
  group state; a tracked room's is verified against its ratchet tree. The hub does not store or
  relay the Commit.
- **Who sets a room's policy.** `roomPolicy`, `memberRole` and `addParticipant` are the hub
  operator's, on a loopback listener with no credential; a peer cannot reach them, and they answer
  409 for a tracked room, whose policy and list are its group's. A peer's `update` is checked
  against the room's policy; who made a change is checked for a tracked room, for its proposer
  (DIVERGENCES, DIV-15).

The directory endpoint discloses the ciphersuite and join-model restrictions programmatically, so
a client can detect them without reading source.

## Security

See the parent repo's [`SECURITY.md`](../SECURITY.md) for the vulnerability-reporting process and
the scope statement covering this daemon.
