## Builds the Komodo Core, Periphery, and Util binaries
## for a specific architecture. Requires OpenSSL 3 or later.

FROM rust:1.98.0-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake pkg-config libssl-dev \
  && rm -rf /var/lib/apt/lists/*
ENV OPENSSL_NO_VENDOR=1
RUN cargo install cargo-strip cargo-edit

WORKDIR /builder
COPY Cargo.toml Cargo.lock ./
COPY ./lib ./lib
COPY ./client/core/rs ./client/core/rs
COPY ./client/periphery ./client/periphery
COPY ./bin/core ./bin/core
COPY ./bin/periphery ./bin/periphery
COPY ./bin/cli ./bin/cli
COPY ./bin/proxy ./bin/proxy
COPY ./xtask ./xtask

# Set Version
ARG VERSION="0.0.0"
ARG IMAGE_TAG=""
RUN cargo set-version -p komodo_core ${VERSION}${IMAGE_TAG:+-${IMAGE_TAG}}

# Compile bin
RUN \
  cargo build -p komodo_core --release && \
  cargo build -p komodo_periphery --release && \
  cargo build -p komodo_cli --release && \
  cargo build -p komodo_proxy --release && \
  cargo strip

# Copy just the binaries to scratch image
FROM scratch

COPY --from=builder /builder/target/release/core /core
COPY --from=builder /builder/target/release/periphery /periphery
COPY --from=builder /builder/target/release/km /km
COPY --from=builder /builder/target/release/proxy /proxy

LABEL org.opencontainers.image.source="https://github.com/moghtech/komodo"
LABEL org.opencontainers.image.description="Komodo Binaries"
LABEL org.opencontainers.image.licenses="GPL-3.0"