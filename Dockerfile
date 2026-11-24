# mimihubd - reference MIMI hub daemon. Multi-stage: build in a full Rust image, run from a
# minimal Debian base with only the compiled binary and its runtime dependencies.
#
# Build (from the repo root, so the build context includes both mimi-core and mimihubd):
#   docker build -t mimihubd .
# Run (same fail-closed mTLS requirements as the systemd unit / bare binary - see
# mimihubd/README.md for how to generate a throwaway CA + server + client certificate set):
#   docker run --rm -p 8443:8443 \
#     -e MIMI_PROVIDER_DOMAIN=hub.example.org \
#     -v /path/to/certs:/etc/mimihubd:ro \
#     -e MIMI_SERVER_CERT=/etc/mimihubd/server-cert.pem \
#     -e MIMI_SERVER_KEY=/etc/mimihubd/server-key.pem \
#     -e MIMI_CLIENT_CA=/etc/mimihubd/ca-cert.pem \
#     mimihubd
# or mount a TOML file and pass --config /etc/mimihubd/mimihubd.toml as the container command.

FROM rust:1.96-slim-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p mimihubd

FROM debian:bookworm-slim
RUN groupadd --system mimihubd \
    && useradd --system --gid mimihubd --no-create-home --home-dir /var/lib/mimihubd \
       --shell /usr/sbin/nologin mimihubd \
    && mkdir -p /var/lib/mimihubd \
    && chown mimihubd:mimihubd /var/lib/mimihubd
COPY --from=builder /build/target/release/mimihubd /usr/bin/mimihubd

USER mimihubd
WORKDIR /var/lib/mimihubd
EXPOSE 8443
ENTRYPOINT ["/usr/bin/mimihubd"]
