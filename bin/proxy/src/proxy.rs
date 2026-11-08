use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::{
  Error, ErrorType, Result,
  apps::ServerApp,
  listeners::TlsAccept,
  protocols::{
    Stream,
    tls::{TlsRef, server::handshake_with_callback},
  },
  server::ShutdownWatch,
  upstreams::peer::HttpPeer,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{HttpProxy, ProxyHttp, Session};
use tokio::{net::TcpStream, time::timeout};

use crate::{
  config::{RuntimeRoute, Snapshot},
  stream::client_hello,
};

pub struct Ingress {
  pub state: Arc<ArcSwap<Snapshot>>,
  pub http: Arc<HttpProxy<Proxy>>,
}

struct ConnectionName(String);

#[async_trait]
impl TlsAccept for ConnectionName {
  async fn handshake_complete_callback(
    &self,
    _: &TlsRef,
  ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
    Some(Arc::new(self.0.clone()))
  }
}

impl Ingress {
  async fn serve(
    &self,
    stream: Stream,
    shutdown: &ShutdownWatch,
  ) -> anyhow::Result<()> {
    let deadline =
      tokio::time::Instant::now() + Duration::from_secs(10);
    let (domain, mut stream) =
      tokio::time::timeout_at(deadline, client_hello(stream))
        .await
        .context("TLS ClientHello timed out")??;
    let route = self
      .state
      .load()
      .routes
      .get(&domain)
      .cloned()
      .context("No proxy route for requested SNI")?;
    if let Some(acceptor) = &route.acceptor {
      let tls = tokio::time::timeout_at(
        deadline,
        handshake_with_callback(
          acceptor,
          stream,
          &ConnectionName(domain),
        ),
      )
      .await
      .context("TLS handshake timed out")??;
      self.http.process_new(Box::new(tls), shutdown).await;
    } else {
      let host = upstream_host(&route.upstream)?;
      let port =
        route.upstream.port().context("Missing passthrough port")?;
      let mut upstream = timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
      )
      .await
      .context("Passthrough connection timed out")??;
      tokio::io::copy_bidirectional(&mut stream, &mut upstream)
        .await?;
    }
    Ok(())
  }
}

#[async_trait]
impl ServerApp for Ingress {
  async fn process_new(
    self: &Arc<Self>,
    stream: Stream,
    shutdown: &ShutdownWatch,
  ) -> Option<Stream> {
    let mut stopped = shutdown.clone();
    tokio::select! {
      result = self.serve(stream, shutdown) => {
        if let Err(error) = result { log::warn!("TLS proxy connection failed: {error:#}"); }
      },
      _ = stopped.changed() => {},
    }
    None
  }

  async fn cleanup(&self) {
    self.http.cleanup().await;
  }
}

pub struct Proxy {
  pub state: Arc<ArcSwap<Snapshot>>,
  pub redirect: bool,
}

#[derive(Default)]
pub struct RequestContext {
  route: Option<Arc<RuntimeRoute>>,
  host: String,
}

fn proxy_error(message: impl Into<String>) -> Box<Error> {
  Error::explain(ErrorType::HTTPStatus(502), message.into())
}

fn request_host(request: &RequestHeader) -> Option<String> {
  let authority = request
    .uri
    .authority()
    .map(|value| value.as_str())
    .or_else(|| request.headers.get("host")?.to_str().ok())?;
  let authority: url::Url =
    url::Url::parse(&format!("https://{authority}")).ok()?;
  if !authority.username().is_empty()
    || authority.password().is_some()
    || authority.path() != "/"
    || authority.query().is_some()
    || authority.fragment().is_some()
  {
    return None;
  }
  authority.host_str().map(str::to_ascii_lowercase)
}

fn upstream_host(url: &url::Url) -> anyhow::Result<String> {
  url
    .host()
    .map(|host| match host {
      url::Host::Domain(domain) => domain.to_string(),
      url::Host::Ipv4(address) => address.to_string(),
      url::Host::Ipv6(address) => address.to_string(),
    })
    .context("Upstream has no host")
}

fn upstream_path(base: &str, request: &str) -> String {
  if base == "/" || base.is_empty() {
    request.to_string()
  } else {
    format!("{}{}", base.trim_end_matches('/'), request)
  }
}

#[async_trait]
impl ProxyHttp for Proxy {
  type CTX = RequestContext;

  fn new_ctx(&self) -> Self::CTX {
    RequestContext::default()
  }

  async fn request_filter(
    &self,
    session: &mut Session,
    ctx: &mut Self::CTX,
  ) -> Result<bool> {
    let Some(host) = request_host(session.req_header()) else {
      session.respond_error(400).await?;
      return Ok(true);
    };
    let state = self.state.load();
    let Some(route) = state.routes.get(&host).cloned() else {
      session.respond_error(404).await?;
      return Ok(true);
    };
    if self.redirect {
      let port = if state.https_port == 443 {
        String::new()
      } else {
        format!(":{}", state.https_port)
      };
      let path = session
        .req_header()
        .uri
        .path_and_query()
        .map_or("/", |path| path.as_str());
      let mut response = ResponseHeader::build(308, Some(2))?;
      response.insert_header(
        "Location",
        format!("https://{host}{port}{path}"),
      )?;
      response.insert_header("Content-Length", "0")?;
      session
        .write_response_header(Box::new(response), true)
        .await?;
      return Ok(true);
    }
    let sni = session
      .digest()
      .and_then(|digest| digest.ssl_digest.as_ref())
      .and_then(|digest| digest.extension.get::<String>());
    if route.acceptor.is_none()
      || !sni.is_some_and(|sni| sni.eq_ignore_ascii_case(&host))
    {
      session.respond_error(421).await?;
      return Ok(true);
    }
    ctx.host = host;
    ctx.route = Some(route);
    Ok(false)
  }

  async fn upstream_peer(
    &self,
    _: &mut Session,
    ctx: &mut Self::CTX,
  ) -> Result<Box<HttpPeer>> {
    let route = ctx
      .route
      .as_ref()
      .ok_or_else(|| proxy_error("No selected upstream"))?;
    let host = upstream_host(&route.upstream)
      .map_err(|error| proxy_error(error.to_string()))?;
    let port = route
      .upstream
      .port_or_known_default()
      .ok_or_else(|| proxy_error("Missing upstream port"))?;
    let mut addresses = timeout(
      Duration::from_secs(5),
      tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| proxy_error("Upstream DNS lookup timed out"))?
    .map_err(|error| {
      proxy_error(format!("Upstream DNS lookup failed: {error}"))
    })?;
    let address = addresses.next().ok_or_else(|| {
      proxy_error("Upstream DNS returned no addresses")
    })?;
    drop(addresses);
    let mut peer = HttpPeer::new(
      address,
      route.upstream.scheme() == "https",
      host,
    );
    peer.options.connection_timeout = Some(Duration::from_secs(10));
    peer.options.read_timeout = Some(Duration::from_secs(60));
    peer.options.write_timeout = Some(Duration::from_secs(60));
    Ok(Box::new(peer))
  }

  async fn upstream_request_filter(
    &self,
    session: &mut Session,
    request: &mut RequestHeader,
    ctx: &mut Self::CTX,
  ) -> Result<()> {
    let route = ctx
      .route
      .as_ref()
      .ok_or_else(|| proxy_error("No selected upstream"))?;
    let path = request
      .uri
      .path_and_query()
      .map_or("/", |path| path.as_str());
    let path = upstream_path(route.upstream.path(), path);
    request.set_uri(
      path
        .parse()
        .map_err(|_| proxy_error("Invalid upstream path"))?,
    );
    // Do not trust forwarding headers supplied by an Internet client.
    for name in [
      "forwarded",
      "x-forwarded-for",
      "x-real-ip",
      "x-forwarded-host",
      "x-forwarded-proto",
      "x-forwarded-port",
    ] {
      request.remove_header(name);
    }
    if let Some(address) =
      session.client_addr().and_then(|address| address.as_inet())
    {
      let ip = address.ip().to_string();
      request.insert_header("X-Forwarded-For", &ip)?;
      request.insert_header("X-Real-IP", ip)?;
    }
    request.insert_header("X-Forwarded-Host", &ctx.host)?;
    request.insert_header("X-Forwarded-Proto", "https")?;
    request.insert_header(
      "X-Forwarded-Port",
      self.state.load().https_port.to_string(),
    )?;
    Ok(())
  }

  async fn logging(
    &self,
    session: &mut Session,
    error: Option<&Error>,
    ctx: &mut Self::CTX,
  ) {
    if let Some(error) = error {
      log::error!("Proxy request failed for {}: {error}", ctx.host);
    } else {
      log::debug!(
        "Proxy request for {}: {}",
        ctx.host,
        session
          .response_written()
          .map_or(0, |response| response.status.as_u16())
      );
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn prefixes_origin_path_without_losing_query() {
    assert_eq!(upstream_path("/", "/path?q=1"), "/path?q=1");
    assert_eq!(
      upstream_path("/base/", "/path?q=1"),
      "/base/path?q=1"
    );
  }

  #[test]
  fn validates_request_authority() {
    let mut request =
      RequestHeader::build("GET", b"/path", None).unwrap();
    request
      .insert_header("Host", "APP.example.com:8443")
      .unwrap();
    assert_eq!(
      request_host(&request).as_deref(),
      Some("app.example.com")
    );
    request
      .insert_header("Host", "user@evil.example.com")
      .unwrap();
    assert_eq!(request_host(&request), None);
  }
}
