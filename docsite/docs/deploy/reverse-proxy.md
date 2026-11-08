# Managed Reverse Proxy and Certificates

Komodo runs its own dedicated Rust proxy container, built on Pingora, and manages its routes and TLS certificates. Configure it under the Server's **Reverse Proxy** settings; there is no Traefik, Caddy, Kubernetes provider, or separate proxy control plane to configure. Certificate issuance and renewal belong to Komodo, not the proxy.

## Building the proxy image

The new proxy image must be built and made available to each Docker host before enabling the proxy. From the repository root, run `docker build -f bin/proxy/Dockerfile -t komodo-proxy:0.0.0 .`. Periphery defaults to `komodo-proxy:<Periphery package version>`. When distributing a custom registry image, set `PERIPHERY_REVERSE_PROXY_IMAGE` on Periphery to its full image reference (prefer a digest-pinned image); the managed container is recreated when this reference changes. This repository does not yet publish a prebuilt proxy image.

On a Unix Docker host with Python 3 and OpenSSL installed, run `python3 bin/proxy/tests/container_smoke.py` after building the default image to exercise its health check, TLS forwarding, redirects, certificate rotation, and invalid-update retention with the managed container's security settings. The test removes its own container and temporary files.

## Requirements and networking

- The Server must run Periphery on a Unix host with Docker access. The managed proxy and the Cloudflare ACME issuer currently require Unix.
- The configured HTTP and HTTPS host ports must be free. By default, the proxy publishes ports `80` and `443`.
- Route upstreams must be reachable **from the proxy container**. Use an HTTP(S) origin for TLS termination (for example, `http://host.docker.internal:3000`) or a `host:port` address for TLS passthrough.
- HTTP traffic is redirected to HTTPS. Passthrough routes use SNI and forward the original TLS stream; they cannot route by HTTP path.
- Proxy certificate and route files are mounted read-only. Each proxy container receives only the certificate directories used by its routes.

## Certificates

Create a **Certificate** resource on the Server that will use it:

- **ACME via Cloudflare** issues DNS-01 certificates. Add a scoped Cloudflare API token to Komodo Core's secrets and reference the secret name. The token is sent to Periphery only during issuance and written to a temporary protected file for Certbot. DNS propagation and CA issuance time vary.
- **Tailscale** calls `tailscale cert` on the Periphery host. The host must already have an authenticated Tailscale daemon and the requested name must be eligible for Tailscale TLS certificates.

Private keys and certificate versions remain on the Server. Komodo renews certificates before expiry and publishes new versions atomically. The ACME account state is stored separately from workload-mounted certificate files. Removing a Certificate removes its local certificate and ACME state.
The Server assignment is fixed when the Certificate is created; create a new Certificate to move issuance to another Server.

## Proxy routes

Add routes in the Server's **Reverse Proxy** settings:

| Setting | Meaning |
|---|---|
| Domain | Exact DNS name routed by the proxy. Wildcard routes are not currently supported. |
| Upstream | HTTP(S) URL when terminating TLS, or `host:port` when passing TLS through. |
| TLS mode | **Terminate** presents the selected Komodo Certificate; **Passthrough** leaves TLS intact for the upstream to terminate. |

Komodo writes the proxy's JSON route configuration atomically. The proxy checks routes and certificate files every second and atomically replaces its in-memory snapshot after validating the entire update. An invalid update is logged and the last working snapshot stays active. Certificate rotation affects new TLS handshakes without interrupting existing connections; route updates affect new HTTP requests and passthrough connections. A change to listener ports, proxy image, or the set of mounted certificates recreates the container.

The proxy supports HTTP/1.1 and HTTP/2 termination, streaming and WebSocket forwarding, and SNI-based raw TLS passthrough on the same HTTPS port. Unknown domains are rejected rather than sent to a default upstream. Terminated requests must have matching SNI and HTTP authority. Forwarding headers supplied by clients are replaced with the observed client address and HTTPS metadata. HTTPS upstream certificates are verified against the container's trusted CAs. If an upstream URL includes a path, it is prefixed to the original request path.

HTTP redirects preserve the request path and query and use the configured public HTTPS port. TLS handshakes and upstream connections have a ten-second timeout; upstream HTTP reads and writes have a sixty-second timeout. The proxy has no Docker socket, ACME credentials, discovery providers, or public administration API. It runs with a read-only filesystem, no Linux capabilities, and only its route-specific certificate mounts.

## Attach certificates to workloads

Deployments and non-Swarm Stacks can attach a Ready Certificate on the same Server. Komodo mounts a read-only directory containing `current/tls.crt` and `current/tls.key` at the path you choose. For Stacks, select the Compose service that receives the mount.

On rotation, **Restart** (the default) restarts the attached Deployment or Stack service. Choose **Hot reload** only when the application watches the files and reloads its TLS configuration itself; the mount points to the certificate directory so an atomic certificate-version switch is visible to the container. Swarm Deployments and Stacks are not supported for these host-file mounts.
