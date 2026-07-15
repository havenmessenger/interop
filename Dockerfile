# mimi-hubd - reference MIMI hub daemon. Multi-stage: build in a full Rust image, run from a
# minimal Debian base with only the compiled binary and its runtime dependencies.
#
# Build (from the repo root, so the build context includes both mimi-core and mimi-hubd):
#   docker build -t mimi-hubd .
# Run (same fail-closed mTLS requirements as the systemd unit / bare binary - see
# mimi-hubd/README.md for how to generate a throwaway CA + server + client certificate set):
#   docker run --rm -p 8443:8443 \
#     -e MIMI_PROVIDER_DOMAIN=hub.example.org \
#     -v /path/to/certs:/etc/mimi-hubd:ro \
#     -e MIMI_SERVER_CERT=/etc/mimi-hubd/server-cert.pem \
#     -e MIMI_SERVER_KEY=/etc/mimi-hubd/server-key.pem \
#     -e MIMI_CLIENT_CA=/etc/mimi-hubd/ca-cert.pem \
#     mimi-hubd
# or mount a TOML file and pass --config /etc/mimi-hubd/mimi-hubd.toml as the container command.

FROM rust:1.96-slim-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p mimi-hubd

FROM debian:bookworm-slim
RUN groupadd --system mimi-hubd \
    && useradd --system --gid mimi-hubd --no-create-home --home-dir /var/lib/mimi-hubd \
       --shell /usr/sbin/nologin mimi-hubd \
    && mkdir -p /var/lib/mimi-hubd \
    && chown mimi-hubd:mimi-hubd /var/lib/mimi-hubd
COPY --from=builder /build/target/release/mimi-hubd /usr/bin/mimi-hubd

USER mimi-hubd
WORKDIR /var/lib/mimi-hubd
EXPOSE 8443
ENTRYPOINT ["/usr/bin/mimi-hubd"]
