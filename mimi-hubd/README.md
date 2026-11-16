# mimi-hubd

A reference MIMI hub daemon: mTLS-terminated HTTP server, durable SQLite-backed state, and the
v1 request-handling semantics (add-driven membership, text-only content, the MLS ciphersuites the
deployment accepts) over [`mimi-core`](..)'s gate, consent, and room-policy logic.

## Wire format: read this before you rely on interop

This hub speaks two lanes side by side.

**`/mimi/v1/*`** is JSON. It implements the *semantics* of the v1 endpoints (the gate, the consent
flow, the room-policy RBAC, the ciphersuite restriction) faithfully, but its request/response bodies
are not the TLS presentation-language framing `draft-ietf-mimi-protocol` defines.

**`/mimi/pl/*`** is the draft's actual wire framing (TLS presentation language, RFC 8446 §3), routed
for eight endpoints: `submitMessage` (§5.4), `requestConsent`/`updateConsent` (§5.7), `keyMaterial`
(§5.2), `notify` inbound-receive (§5.5), `identifierQuery` (§5.8), `reportAbuse` (§5.9), and
`update` (§5.3, bounded - see below). Every wire route decodes the same bytes a strict protocol-07
client would send and calls the identical business logic the JSON lane calls, so state written
through one lane is readable through the other (proven below for `keyMaterial`). The path segment
on the request/consent/keyMaterial/update/reportAbuse routes plays the same opaque routing-key role
the JSON lane's query parameters play; it is not the draft's room-participant-list fanout, which
this reference hub does not implement for message delivery. The directory (`/.well-known/mimi-
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
for the member who proposed it (DIV-15). `untrackRoom` on the operator's listener drops a room's tree. An untracked room's Commit is read without verifying its
signature, as RFC 9420's delivery-service model allows.
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

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    "https://localhost:8443/mimi/v1/message?user=xxx@haven" -o fetched.bin
# fetched.bin is byte-identical to the MLS envelope inside submit_message.bin: the wire and
# JSON lanes read from the same store.
```

`keyMaterial`, published over the *JSON* lane and served back over the *wire* lane, proving the two
lanes share one store in both directions, not just one:

```
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @bob_kp.bin \
    "https://localhost:8443/mimi/v1/keyMaterial/ingest?user=bob" -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=204

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @km_req.bin \
    https://localhost:8443/mimi/pl/keyMaterial/bob -o km_resp.bin -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=200
# the served KeyPackage bytes inside km_resp.bin are byte-identical to bob_kp.bin (290-byte
# response: userStatus=success, one ClientKeyMaterial entry, the KeyPackage as published)
```

`notify` (an application message wrapped as `FanoutMessage`) and `identifierQuery` (a
wire-encoded query for a user the hub does not answer for, which gets the same `notFound` answer as a name nobody
has):

```
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @notify.bin \
    https://localhost:8443/mimi/pl/notify/mimi%3A%2F%2Fexample.com%2Fr%2Fdemo -w '\nHTTP_STATUS=%{http_code}\n'
HTTP_STATUS=201

# The same body for a room hosted by another provider: this certificate is not that provider's.
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @notify.bin \
    https://localhost:8443/mimi/pl/notify/mimi%3A%2F%2Fother.example%2Fr%2Fdemo -w '\nHTTP_STATUS=%{http_code}\n'
HTTP_STATUS=403

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @idq.bin \
    https://localhost:8443/mimi/pl/identifierQuery -o idq_resp.bin -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=404
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
mkdir -p /tmp/mimi-hubd-demo
CERTDIR=/tmp/mimi-hubd-demo

# A throwaway CA.
openssl req -x509 -newkey rsa:2048 -nodes -keyout $CERTDIR/ca-key.pem -out $CERTDIR/ca-cert.pem \
  -days 365 -subj "/CN=mimi-hubd-demo-ca"

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
MIMI_DB_PATH=/tmp/mimi-hubd-demo/hub.db \
MIMI_SERVER_CERT=/tmp/mimi-hubd-demo/server-cert.pem \
MIMI_SERVER_KEY=/tmp/mimi-hubd-demo/server-key.pem \
MIMI_CLIENT_CA=/tmp/mimi-hubd-demo/ca-cert.pem \
cargo run -p mimi-hubd
```

Output from the sequence above:

```
[mimi-hubd] MIMI_SERVER_CERT supplied by: env
[mimi-hubd] MIMI_SERVER_KEY supplied by: env
[mimi-hubd] MIMI_CLIENT_CA supplied by: env
[mimi-hubd 0.0.1] domain=example.com db=/tmp/mimi-hubd-demo/hub.db listening (mTLS) on 127.0.0.1:8443
```

In a second terminal, query the directory with a client certificate signed by the same CA:

```bash
curl -s --cacert /tmp/mimi-hubd-demo/ca-cert.pem --cert /tmp/mimi-hubd-demo/client-cert.pem \
  --key /tmp/mimi-hubd-demo/client-key.pem \
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
cat > /tmp/mimi-hubd-demo/mimi-hubd.toml <<'EOF'
provider_domain = "example.com"
bind_addr = "127.0.0.1:8443"
db_path = "/tmp/mimi-hubd-demo/hub.db"
server_cert = "/tmp/mimi-hubd-demo/server-cert.pem"
server_key = "/tmp/mimi-hubd-demo/server-key.pem"
client_ca = "/tmp/mimi-hubd-demo/ca-cert.pem"
EOF

cargo run -p mimi-hubd -- --config /tmp/mimi-hubd-demo/mimi-hubd.toml
```

Output from the sequence above - note `supplied by: file` instead of `env`, the only
observable difference from the env-only run above:

```
[mimi-hubd] MIMI_SERVER_CERT supplied by: file
[mimi-hubd] MIMI_SERVER_KEY supplied by: file
[mimi-hubd] MIMI_CLIENT_CA supplied by: file
[mimi-hubd 0.0.1] domain=example.com db=/tmp/mimi-hubd-demo/hub.db listening (mTLS) on 127.0.0.1:8443
```

Any `MIMI_*` env var set alongside `--config` still overrides that one key from the file (a
deployment can be mostly file-config with one setting pinned by the environment) - and a env var
set to the empty string is treated as not-set, falling through to the file/default rather than
becoming an empty override.

## Installing as a service

Beyond `cargo run`, this daemon packages like a normal system service:

- **systemd unit**: [`debian/mimi-hubd.service`](debian/mimi-hubd.service) - a hardened unit
  (dedicated non-root user, `ProtectSystem=strict`, `NoNewPrivileges=true`, `UMask=0077`, and more)
  that reads `/etc/mimi-hubd/mimi-hubd.toml` by default. It ships **not** enabled and **not**
  started: this daemon is fail-closed on missing mTLS material, so a fresh install has nothing
  valid to start with yet. Fill in your certificates and config, then
  `systemctl enable --now mimi-hubd` yourself.
- **`.deb` package**: built via [`cargo-deb`](https://github.com/kornelski/cargo-deb) from
  [`mimi-hubd/Cargo.toml`](Cargo.toml)'s `[package.metadata.deb]` section. Creates a dedicated
  system user on install (`debian/postinst`), installs the systemd unit and two config templates
  (`/etc/mimi-hubd/mimi-hubd.toml.example`, `/etc/mimi-hubd/mimi-hubd.env.example`), and on
  `purge` (not plain `remove`) wipes `/etc/mimi-hubd` and `/var/lib/mimi-hubd` while deliberately
  leaving the system user in place (`debian/postrm`) - reusing a freed system UID for an unrelated
  future package is a known packaging hazard. Build it yourself: `cargo install cargo-deb --locked
  && cargo deb -p mimi-hubd`.
- **Prebuilt binaries and the `.deb`**: attached to each GitHub Release by
  [`.github/workflows/release.yml`](../.github/workflows/release.yml), for `x86_64` and `aarch64`
  Linux. These are ordinary `glibc`-linked, dynamically-linked binaries (built on the GitHub-hosted
  `ubuntu-latest` runner's glibc) - not static binaries; a target glibc materially older than that
  runner's may not be compatible. Each archive ships alongside a `.sha256` checksum file.
- **Docker**: [`../Dockerfile`](../Dockerfile) (repo root, since the build context needs both
  `mimi-core` and `mimi-hubd`) - a multi-stage build producing a minimal runtime image that runs
  as the same dedicated non-root user. Pushed to `ghcr.io/havenmessenger/mimi-hubd` by the same
  release workflow.

All four installation paths take the identical env-var/config-file interface documented below -
packaging changes how you *install* the daemon, never what it *does*.

## Configuration reference

Ten settings, either as env vars or as keys in a `--config <path>` TOML file (see the two
quickstarts above). An env var, if set to a non-empty value, always overrides the same key from
the file - see [`debian/mimi-hubd.toml.example`](debian/mimi-hubd.toml.example) and
[`debian/mimi-hubd.env.example`](debian/mimi-hubd.env.example) for filled-in templates.

| Env var | TOML key | Required | Default | Meaning |
|---|---|---|---|---|
| `MIMI_PROVIDER_DOMAIN` | `provider_domain` | yes | none, hard error if unresolved | This hub's own domain, used in the directory response and in `From`-authority checks. |
| `MIMI_SERVER_CERT` | `server_cert` | yes | none | PEM path, this hub's TLS server certificate (+ chain). |
| `MIMI_SERVER_KEY` | `server_key` | yes | none | PEM path, this hub's TLS server private key. |
| `MIMI_CLIENT_CA` | `client_ca` | yes | none | PEM path, the CA that signs client certificates for peers this hub trusts. A peer presenting a cert this CA signed is allowed to call the hub's endpoints; a peer may instead sign its requests with a DNS-published key (`MIMI_PEER_KEYS`, see Peer authentication). The fingerprint (SHA-256) of each CA in the file is logged at startup, and so is which layer (env/file) supplied it, since it's a statement about the actual trust boundary, not just an ergonomic detail. |
| `MIMI_BIND_ADDR` | `bind_addr` | no | `0.0.0.0:8443` | Listen address. |
| `MIMI_DB_PATH` | `db_path` | no | `/var/lib/mimi/provider.db` | SQLite file path for durable state. This binary-level default is unchanged by packaging - the shipped `.toml.example` template recommends `/var/lib/mimi-hubd/hub.db` instead (matching the systemd unit's `StateDirectory=`), but that is the template's choice, not a change to this daemon's own default. |
| `MIMI_PUBLIC_BASE_URL` | `public_base_url` | no | `https://{MIMI_PROVIDER_DOMAIN}` | The `https://` URL the directory's endpoint URLs start at, for a hub behind a reverse proxy, on a port other than 443, or on a dedicated host. Identifiers keep using `MIMI_PROVIDER_DOMAIN`. One trailing `/` is dropped; a query, fragment or non-`https` URL is a hard error at startup. |
| `MIMI_DIRECTORY_BIND_ADDR` | `directory_bind_addr` | no | none | A second listener, plain HTTP and with no client certificate, that answers `GET /.well-known/mimi-protocol-directory` and nothing else. It is meant to sit behind whatever terminates TLS for the public name. Unset means there is no such listener. |
| `MIMI_ADMIN_BIND_ADDR` | `admin_bind_addr` | no | none | The operator's listener: plain HTTP with no client certificate, serving `roomPolicy`, `memberRole`, `addParticipant`, `untrackRoom`, `outbox` and `dropOutbox` and nothing else. It must be a loopback `ip:port` (127.0.0.0/8 or `::1`); any other address stops the hub at start. Unset means there is no such listener, and no request can change a room's policy, roles or participants except a peer's `update`. |
| `MIMI_POLICY` | `policy` | no | none | A TOML file of the deployment's choices, below. Unset means the drafts' defaults. A named file the hub cannot read, or one that is not a valid policy, stops the start. |
| `MIMI_PEER_KEYS` | `peer_keys` | no | none | Path of a JSON file of peers' DNS-published signing keys, `{"<keyid>._mimi.<domain>": "<base64 Ed25519 public key>"}`, an empty value for a revoked key. Re-read when it changes. Without it, no signature verifies and only a client certificate admits a peer. |
| `MIMI_ACTIVITY_LOG` | `activity_log` | no | off | `1` prints one line per request on the peer-facing listener to stderr: `[mimi-activity] method=POST route=/mimi/pl/update/:room_id status=200`. The route is the template the request matched (`route=unmatched` when none did), so no path, query string, header, certificate or body appears in it. Any other value, or none, leaves it off. The directory-only listener is not logged. |
| `MIMI_OUTBOUND_ALLOW` | `outbound_allow` | no | none | Comma-separated `addr/len` ranges an outbound request may reach although they are special (loopback, private, link-local, ...), for a test deployment whose peers run on such addresses. A value that does not parse stops the start. See "Outbound requests" below. |
| `MIMI_OUTBOUND_PROXY` | `outbound_proxy` | no | none | An HTTP `CONNECT` proxy for outbound requests, `http://host:port`. The tunnel is opened to the address the hub checked, and TLS with the hub's client certificate runs end to end inside it. |
| `MIMI_PEER_TRUST` | `peer_trust` | no | `system` | The roots a peer's server certificate may chain to: `system` (the system's roots plus `MIMI_CLIENT_CA`) or `bundle` (`MIMI_CLIENT_CA` only). |
| `MIMI_CLIENT_CERT` | `client_cert` | no | `MIMI_SERVER_CERT` | PEM path of the certificate outbound requests present, with `MIMI_CLIENT_KEY`; for a server certificate without the `clientAuth` extended key usage. Set both or neither. |
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
# enrolled with `mimi-hubd enroll`.
identifier_discovery = "enrolled"
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
it then connects to that checked address. TLS presents a client certificate on every request: `MIMI_CLIENT_CERT` /
`MIMI_CLIENT_KEY` when set, else `MIMI_SERVER_CERT` / `MIMI_SERVER_KEY`, which then needs the `clientAuth` extended key
usage as well as `serverAuth`. The peer's server certificate must be valid for the host connected to. Requests carry
`From: mimi@<MIMI_PROVIDER_DOMAIN>`; redirects are not followed. The startup log says how the client reaches peers.

A peer's endpoints come from its directory, `<base>/.well-known/mimi-protocol-directory`, where the base is
`https://<domain>` unless `MIMI_PEERS` gives another. Fan-out for other providers waits in the outbox, one queue per
room and provider, delivered in order by a worker in the hub (`../DIVERGENCES.md`, DIV-5, says what each answer does);
`GET /mimi/v1/outbox` and `POST /mimi/v1/dropOutbox` on the operator's listener show and drop queues. Nothing is queued
yet: the hub does not fan out to other providers (DIV-5).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/mimi-protocol-directory` | Advertises supported ciphersuite, draft revisions, and endpoint URLs. |
| GET | `/mimi/v1/keyMaterial?user=` | Serve one local user's one-time KeyPackage. |
| POST | `/mimi/v1/keyMaterial/ingest` | Gate + optionally publish a KeyPackage: for a user of this provider, or for another provider's user only by a peer whose certificate is that provider's (403 otherwise). |
| POST | `/mimi/v1/notify?room=` | Idempotent fanout receipt; the peer must be the hub of `room` (403 otherwise). |
| POST | `/mimi/v1/welcome/ingest` | Gate + optionally relay a Welcome. |
| GET | `/mimi/v1/welcome?user=` | Deliver-once pull of a queued Welcome. |
| POST | `/mimi/v1/submitMessage?recipient=` | Deposit an opaque application message for a recipient. |
| GET | `/mimi/v1/message?user=` | Deliver-once pull of a queued message. |
| POST | `/mimi/v1/identifierQuery` | Opt-in-only identifier lookup. |
| POST | `/mimi/v1/requestConsent` | Consent request or cancel (§5.7 C1), always 201. A cancel withdraws only a pending request, and only from the requester's provider. The wire route answers 202, and 422 for an operation it does not take. |
| POST | `/mimi/v1/updateConsent` | Consent grant/revoke (§5.7 C2), always 201. |
| POST | `/mimi/v1/authorizeSender?room=&sender=` | Check whether a sender may send in a room. |

The operator's routes are served only on the loopback listener `MIMI_ADMIN_BIND_ADDR` names, never to a peer. They are
not MIMI routes; a peer changes a room's roster or policy through `update`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/mimi/v1/roomPolicy?room=` | Set a room's RBAC policy. |
| POST | `/mimi/v1/memberRole?room=&member=&role=` | Assign a member's role in a room. |
| POST | `/mimi/v1/addParticipant?room=&member=` | Register a room participant. |
| POST | `/mimi/v1/untrackRoom?room=` | Drop the room's ratchet tree; its next bundle with a Full GroupInfo and a full tree seeds it again. |
| GET | `/mimi/v1/outbox` | Each queue of fan-out waiting for another provider: room, domain, depth, oldest row, and its head's attempts and last outcome. |
| POST | `/mimi/v1/dropOutbox?room=&domain=` | Drop that queue, every row of it; answers how many. |

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
mimi-hubd --config /etc/mimi-hubd/mimi-hubd.toml enroll erin
# or with the environment alone:
MIMI_DB_PATH=/var/lib/mimi-hubd/hub.db mimi-hubd enroll erin
```

Output from the sequence above:

```
enrolled "erin" for identifierQuery in /var/lib/mimi-hubd/hub.db
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
HUB=https://localhost:8443 CACERT=/tmp/mimi-hubd-demo/ca-cert.pem \
CERT=/tmp/mimi-hubd-demo/client-cert.pem KEY=/tmp/mimi-hubd-demo/client-key.pem \
PEER_USER=mimi://other.example/u/alice ../examples/seed_table.sh seed
```

The KeyPackages are real ones under ciphersuite 0x0001, made by
[`../examples/seed_fixtures.rs`](../examples/seed_fixtures.rs). Their private keys are never written anywhere, so a
Welcome made for a seeded user cannot be opened: the users exist for the hub's answers, not to join a group.

`identifierQuery` takes one more step, on the hub's host: `mimi-hubd enroll <handle>` (above). The script's `check`
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
