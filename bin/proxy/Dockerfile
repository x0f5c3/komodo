FROM rust:1.98.0-trixie AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake pkg-config \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /builder
COPY Cargo.toml Cargo.lock ./
COPY lib lib
COPY client/core/rs client/core/rs
COPY client/periphery/rs client/periphery/rs
COPY bin bin
COPY xtask xtask
RUN cargo build --locked --release -p komodo_proxy

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /builder/target/release/proxy /usr/local/bin/proxy
EXPOSE 8080 8443
HEALTHCHECK --interval=10s --timeout=3s CMD ["proxy", "--health"]
ENTRYPOINT ["proxy"]
LABEL komodo.skip="true"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"
