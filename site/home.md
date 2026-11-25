# mimihubd

mimihubd is an open-source MIMI hub: the provider side of the IETF's MIMI drafts (draft-ietf-mimi-protocol-07,
mimi-content-10 and mimi-room-policy-04) over MLS (RFC 9420). It hosts rooms, checks each change to a room it hosts
against the room's policy, serves key material and consent, and delivers messages and Commits to the providers of a
room's members. It is written in Rust over mimi-core, in [github.com/havenmessenger/interop](https://github.com/havenmessenger/interop),
under the Apache License 2.0.

Haven runs mimihubd at `mimi.havenmessenger.com`. Start here to test an implementation against it, or to run a hub of
your own.

## Test against Haven's hub

[Test against our hub](interop.html) says what your provider needs to connect and how to ask to be added. The revision
the hub runs and its directory are on [Live status](status.html).

## Run your own

[Run a hub](running.html) covers the quickstart, the configuration, the policy file a deployment makes its choices in,
and installing it as a service: a systemd unit, a `.deb`, prebuilt Linux binaries or a Docker image.

## What it implements

[Conformance](conformance.html) goes through the drafts section by section. Where a draft leaves a point open,
mimihubd takes a reading, and [Divergences](divergences.html) gives each one with its reasoning, along with what is not
built yet. [Security](security.html) states the properties the hub holds and the code that holds each one, and
[Problem types](problems.html) lists the RFC 9457 problems it answers with.

## Feedback

Open an issue on [github.com/havenmessenger/interop](https://github.com/havenmessenger/interop/issues/new/choose): a
peering request, an interop result, or a bug or question. Security reports go to the contact in
[SECURITY.md](https://github.com/havenmessenger/interop/blob/main/SECURITY.md).
