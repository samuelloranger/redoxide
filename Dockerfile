FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src
RUN touch src/main.rs && \
    cargo build --release

FROM debian:bookworm-slim

COPY --from=builder /build/target/release/redoxide /redoxide
COPY config.example.toml /config.example.toml

EXPOSE 25565

ENTRYPOINT ["/redoxide"]
