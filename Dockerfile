FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p aether-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/aether-server /usr/local/bin/aether-server
ENV AETHER_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/aether-server"]
