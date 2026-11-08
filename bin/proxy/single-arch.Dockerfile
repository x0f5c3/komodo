ARG BINARIES_IMAGE=ghcr.io/moghtech/komodo-binaries:2
FROM ${BINARIES_IMAGE} AS binaries
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=binaries /proxy /usr/local/bin/proxy
EXPOSE 8080 8443
HEALTHCHECK --interval=10s --timeout=3s CMD ["proxy", "--health"]
ENTRYPOINT ["proxy"]
LABEL komodo.skip="true"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"
