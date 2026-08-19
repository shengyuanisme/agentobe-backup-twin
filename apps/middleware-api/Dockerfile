FROM rust:1.96-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY apps/middleware-api apps/middleware-api
COPY crates crates
COPY fixtures/ticketing-rs fixtures/ticketing-rs
RUN cargo build --release -p agentobe-middleware-api --bins

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home agentobe
COPY --from=build /app/target/release/agentobe-middleware-api /usr/local/bin/
COPY --from=build /app/target/release/agentobe-outbox-worker /usr/local/bin/
COPY --from=build /app/target/release/agentobe-db-migrate /usr/local/bin/
USER agentobe
ENV RUST_LOG=info
CMD ["/usr/local/bin/agentobe-middleware-api"]
