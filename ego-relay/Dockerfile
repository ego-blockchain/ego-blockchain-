FROM rust:1.75-slim AS builder
WORKDIR /app
COPY Cargo.toml .
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/ego-relay .
EXPOSE 4001
EXPOSE 8080
CMD ["./ego-relay"]
