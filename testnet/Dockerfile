# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM rust:1.75-slim AS builder

RUN apt-get update -qq && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

RUN cargo build --release --bin ego-node

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update -qq && \
    apt-get install -y ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ego-node /usr/local/bin/ego-node

EXPOSE 9000 8545

CMD ["ego-node", "--type", "validator", "--shards", "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"]
