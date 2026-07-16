# mimi-hubd

A reference MIMI hub daemon: mTLS-terminated HTTP server, durable SQLite-backed state, and the
v1 request-handling semantics (add-driven membership, text-only content, MLS ciphersuite 0x0001
only) over [`mimi-core`](..)'s gate, consent, and room-policy logic.

## Wire format: read this before you rely on interop

This hub speaks two lanes side by side.

**`/mimi/v1/*`** is JSON. It implements the *semantics* of the v1 endpoints (the gate, the consent
flow, the room-policy RBAC, the ciphersuite restriction) faithfully, but its request/response bodies
are not the TLS presentation-language framing `draft-ietf-mimi-protocol` defines.

**`/mimi/pl/*`** is the draft's actual wire framing (TLS presentation language, RFC 8446 §3), routed
for eight endpoints: `submitMessage` (§5.4), `requestConsent`/`updateConsent` (§5.7), `keyMaterial`
(§5.2), `notify` inbound-receive (§5.5), `identifierQuery` (§5.8), `reportAbuse` (§5.9), and
`update` (§5.3, bounded - see below). Every wire route decodes the same bytes a strict protocol-06
client would send and calls the identical business logic the JSON lane calls, so state written
through one lane is readable through the other (proven below for `keyMaterial`). The path segment
on the request/consent/keyMaterial/update/reportAbuse routes plays the same opaque routing-key role
the JSON lane's query parameters play; it is not the draft's room-participant-list fanout, which
this reference hub does not implement for message delivery. The directory (`/.well-known/mimi-
protocol-directory`) advertises all eight under `wireEndpoints`, with concrete path templates.

`update` (§5.3) is wired for exactly one bounded case: a Commit whose proposal list holds a single
custom proposal (`mimiParticipantList` or `mimiRoomPolicy`, protocol §5.3/§7.5) is decoded (without
verifying its signature or holding live MLS group state - RFC 9420's own delivery-service trust
model does not expect a DS to do either) and applied to the room's stored participant list or
policy. A Commit mixing a custom proposal with a standard MLS proposal (Add/Remove/Update, ...) in
the same proposal list is refused - full general Commit processing is out of scope for this
reference hub. `groupInfo` (§5.6) is out of scope for a different reason: it is the external-commit
join endpoint DIV-1 disallows in Haven's own product build, and framing it without the accept-path
behind it would wire-format half of a security-relevant endpoint. Asset download (§5.10) has no v1
handler of any kind to frame. The four v1 room-admin JSON endpoints
(`roomPolicy`/`memberRole`/`addParticipant`/`authorizeSender`) are not protocol-06 endpoints at all -
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
wire-encoded query against a non-enrolled user, proving DIV-4's no-body-oracle property holds on
the wire lane the same way it holds on the JSON lane):

```
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @notify.bin \
    https://localhost:8443/mimi/pl/notify -w '\nHTTP_STATUS=%{http_code}\n'
HTTP_STATUS=201

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @idq.bin \
    https://localhost:8443/mimi/pl/identifierQuery -o idq_resp.bin -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=404
$ wc -c idq_resp.bin
0 idq_resp.bin
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

# A client certificate, also signed by that CA - this is what a peer presents to be trusted.
openssl req -newkey rsa:2048 -nodes -keyout $CERTDIR/client-key.pem -out $CERTDIR/client-req.pem \
  -subj "/CN=demo-client"
openssl x509 -req -in $CERTDIR/client-req.pem -CA $CERTDIR/ca-cert.pem -CAkey $CERTDIR/ca-key.pem \
  -CAcreateserial -out $CERTDIR/client-cert.pem -days 365

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
    "protocol_drafts": {"content": "09", "protocol": "06", "room-policy": "04"},
    "provider": "example.com",
    "unsupported": {
        "assets_ohttp": "DIV-3: v1 is messaging-only",
        "groupInfo_external_commit_join": "DIV-1: add-driven join only (ETK security)",
        "non_0x0001_ciphersuites": "DIV-2: rejected at ingest",
        "reportAbuse_with_abusive_messages": "DIV-9: a report attaching an AbusiveMessage is refused (its Frank cannot yet be verified) - metadata-only reports are accepted",
        "update_wire_endpoint_mixed_commits": "DIV-10: a Commit combining a custom proposal with a standard MLS proposal (Add, Remove, ...) in the same proposal list is refused - only a Commit whose list holds exactly one custom proposal is applied"
    },
    "wireEndpoints": {
        "identifierQuery": "/mimi/pl/identifierQuery",
        "keyMaterial": "/mimi/pl/keyMaterial/{targetUser}",
        "notify": "/mimi/pl/notify",
        "reportAbuse": "/mimi/pl/reportAbuse/{roomId}",
        "requestConsent": "/mimi/pl/requestConsent/{targetDomain}",
        "submitMessage": "/mimi/pl/submitMessage/{recipient}",
        "update": "/mimi/pl/update/{roomId}",
        "updateConsent": "/mimi/pl/updateConsent/{requesterDomain}"
    }
}
```

A request without a client certificate is rejected at the TLS handshake (curl exits 56, connection
reset), proving mTLS is actually enforced rather than merely configured.

## Quickstart (config file)

The same six settings can come from a TOML file instead of (or layered under) env vars - useful
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

Six settings, either as env vars or as keys in a `--config <path>` TOML file (see the two
quickstarts above). An env var, if set to a non-empty value, always overrides the same key from
the file - see [`debian/mimi-hubd.toml.example`](debian/mimi-hubd.toml.example) and
[`debian/mimi-hubd.env.example`](debian/mimi-hubd.env.example) for filled-in templates.

| Env var | TOML key | Required | Default | Meaning |
|---|---|---|---|---|
| `MIMI_PROVIDER_DOMAIN` | `provider_domain` | yes | none, hard error if unresolved | This hub's own domain, used in the directory response and in `From`-authority checks. |
| `MIMI_SERVER_CERT` | `server_cert` | yes | none | PEM path, this hub's TLS server certificate (+ chain). |
| `MIMI_SERVER_KEY` | `server_key` | yes | none | PEM path, this hub's TLS server private key. |
| `MIMI_CLIENT_CA` | `client_ca` | yes | none | PEM path, the CA that signs client certificates for peers this hub trusts. This is the whole peer-trust model: any peer presenting a cert this CA signed is allowed to call the hub's endpoints. Which layer (env/file) supplied this is logged at startup, since it's a statement about the actual trust boundary, not just an ergonomic detail. |
| `MIMI_BIND_ADDR` | `bind_addr` | no | `0.0.0.0:8443` | Listen address. |
| `MIMI_DB_PATH` | `db_path` | no | `/var/lib/mimi/provider.db` | SQLite file path for durable state. This binary-level default is unchanged by packaging - the shipped `.toml.example` template recommends `/var/lib/mimi-hubd/hub.db` instead (matching the systemd unit's `StateDirectory=`), but that is the template's choice, not a change to this daemon's own default. |

The daemon never falls back to plain HTTP: a missing certificate, key, or CA path is a hard error
at startup, not a degraded-but-running mode - and mTLS material is validated *before* the SQLite
store is opened, so a bad or missing certificate fails before anything touches disk. An
unrecognized key in a `--config` file is logged as a warning (not a hard error - a genuinely new,
forward-compatible key should not break parsing), which also means a *typo'd* key surfaces as a
diagnostic instead of a silent no-op.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/mimi-protocol-directory` | Advertises supported ciphersuite, draft revisions, and endpoint URLs. |
| GET | `/mimi/v1/keyMaterial?user=` | Serve one local user's one-time KeyPackage. |
| POST | `/mimi/v1/keyMaterial/ingest` | Gate + optionally publish a KeyPackage (local or foreign). |
| POST | `/mimi/v1/notify` | Idempotent fanout receipt. |
| POST | `/mimi/v1/welcome/ingest` | Gate + optionally relay a Welcome. |
| GET | `/mimi/v1/welcome?user=` | Deliver-once pull of a queued Welcome. |
| POST | `/mimi/v1/submitMessage?recipient=` | Deposit an opaque application message for a recipient. |
| GET | `/mimi/v1/message?user=` | Deliver-once pull of a queued message. |
| POST | `/mimi/v1/identifierQuery` | Opt-in-only identifier lookup. |
| POST | `/mimi/v1/requestConsent` | Consent request (§5.7 C1), always 201. |
| POST | `/mimi/v1/updateConsent` | Consent grant/revoke (§5.7 C2), always 201. |
| POST | `/mimi/v1/roomPolicy?room=` | Set a room's RBAC policy. |
| POST | `/mimi/v1/memberRole?room=&member=&role=` | Assign a member's role in a room. |
| POST | `/mimi/v1/addParticipant?room=&member=` | Register a room participant. |
| POST | `/mimi/v1/authorizeSender?room=&sender=` | Check whether a sender may send in a room. |

## What this hub does not do (v1 scope)

- **§5.6 GroupInfo / external-commit join.** Membership is add-driven only.
- **Non-0x0001 ciphersuites.** Rejected at the gate before they reach any MLS processing.
- **Assets / OHTTP (§5.10).** v1 is messaging-only.
- **General `update` (§5.3) Commit processing.** Only a Commit whose proposal list holds exactly
  one custom proposal (`mimiParticipantList` or `mimiRoomPolicy`) is applied - a Commit mixing a
  custom proposal with a standard MLS proposal in the same list is refused. This hub does not hold
  live MLS group state or verify a Commit's signature (matching RFC 9420's own delivery-service
  trust model).
- **A per-caller room-admin principal.** The mutating room-policy endpoints trust any mTLS peer in
  the allowlist to administer any room this hub hosts; they do not yet bind an authenticated
  principal and check a per-room admin role before mutating. See the `SECURITY SCOPE` comment in
  `src/http.rs` for the exact boundary.

The directory endpoint discloses the ciphersuite and join-model restrictions programmatically, so
a client can detect them without reading source.

## Security

See the parent repo's [`SECURITY.md`](../SECURITY.md) for the vulnerability-reporting process and
the scope statement covering this daemon.
