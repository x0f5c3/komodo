use std::{collections::HashSet, path::PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
  pub https_port: u16,
  pub routes: Vec<ProxyRoute>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRoute {
  pub domain: String,
  pub upstream: String,
  /// Absent for TLS passthrough.
  pub certificate_directory: Option<PathBuf>,
}

impl ProxyConfig {
  pub fn validate(&self) -> anyhow::Result<()> {
    if self.https_port == 0 {
      bail!("HTTPS port must be nonzero");
    }
    let mut domains = HashSet::new();
    for route in &self.routes {
      validate_domain(&route.domain)?;
      if !domains.insert(route.domain.to_ascii_lowercase()) {
        bail!("Duplicate proxy route domain: {}", route.domain);
      }
      if route.certificate_directory.is_some() {
        http_upstream(&route.upstream)?;
      } else {
        tcp_upstream(&route.upstream)?;
      }
    }
    Ok(())
  }
}

pub fn validate_domain(domain: &str) -> anyhow::Result<()> {
  if domain.len() > 253
    || !domain.contains('.')
    || domain.parse::<std::net::IpAddr>().is_ok()
    || domain.split('.').any(|label| {
      label.is_empty()
        || label.len() > 63
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
  {
    bail!("Proxy route must be an exact DNS name: {domain}");
  }
  Ok(())
}

pub fn http_upstream(upstream: &str) -> anyhow::Result<url::Url> {
  let url = url::Url::parse(upstream)
    .context("TLS termination requires an HTTP(S) upstream URL")?;
  if !matches!(url.scheme(), "http" | "https")
    || url.host_str().is_none()
    || url.port() == Some(0)
    || !url.username().is_empty()
    || url.password().is_some()
    || url.query().is_some()
    || url.fragment().is_some()
  {
    bail!(
      "HTTP(S) upstream cannot contain credentials, query, or fragment"
    );
  }
  Ok(url)
}

pub fn tcp_upstream(upstream: &str) -> anyhow::Result<url::Url> {
  let url = url::Url::parse(&format!("tcp://{upstream}"))
    .context("TLS passthrough requires a host:port upstream")?;
  if url.host_str().is_none()
    || url.port().is_none_or(|port| port == 0)
    || !url.username().is_empty()
    || url.password().is_some()
    || !matches!(url.path(), "" | "/")
    || url.query().is_some()
    || url.fragment().is_some()
  {
    bail!("TLS passthrough requires a host:port upstream");
  }
  Ok(url)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn validates_origins_and_addresses() {
    assert!(http_upstream("http://origin:3000/base").is_ok());
    assert!(http_upstream("https://[::1]:8443").is_ok());
    assert!(http_upstream("http://origin:0").is_err());
    assert!(http_upstream("ftp://origin").is_err());
    assert!(http_upstream("http://user:pass@origin").is_err());
    assert!(http_upstream("https://origin/?secret=true").is_err());
    assert!(tcp_upstream("origin:8443").is_ok());
    assert!(tcp_upstream("[::1]:8443").is_ok());
    assert!(tcp_upstream("origin").is_err());
    assert!(tcp_upstream("origin:0").is_err());
    assert!(tcp_upstream("user@origin:8443").is_err());
    assert!(tcp_upstream("origin:8443/path").is_err());
  }

  #[test]
  fn rejects_invalid_and_duplicate_domains() {
    for domain in [
      "*.example.com",
      "127.0.0.1",
      "bad`.example.com",
      "-bad.example.com",
    ] {
      assert!(validate_domain(domain).is_err());
    }
    let config = ProxyConfig {
      https_port: 443,
      routes: ["app.example.com", "APP.example.com"]
        .map(|domain| ProxyRoute {
          domain: domain.into(),
          upstream: "origin:8443".into(),
          certificate_directory: None,
        })
        .into(),
    };
    assert!(config.validate().is_err());
  }
}
