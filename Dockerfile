# Relay only
FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY p2pshare-relay/ p2pshare-relay/
COPY p2pshare-core/ p2pshare-core/
COPY p2pshare-cli/ p2pshare-cli/
RUN cargo build --release -p p2pshare-relay

FROM alpine:3.20
COPY --from=builder /app/target/release/p2pshare-relay /usr/local/bin/
EXPOSE 8080
CMD ["p2pshare-relay"]
