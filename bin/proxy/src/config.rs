use std::{
  collections::BTreeMap,
  fs,
  path::{Path, PathBuf},
  sync::Arc,
};

use anyhow::Context;
#[cfg(feature = "openssl")]
use anyhow::bail;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use komodo_proxy_config::{ProxyConfig, ProxyRoute};
use pingora_core::{
  server::ShutdownWatch, services::background::BackgroundService,
};

#[cfg(feature = "rustls")]
type TlsAcceptor = pingora_core::listeners::tls::Acceptor;

#[cfg(feature = "openssl")]
type TlsAcceptor = pingora_core::tls::ssl::SslAcceptor;

pub struct RuntimeRoute {
  pub upstream: url::Url,
  pub acceptor: Option<TlsAcceptor>,
}

pub struct Snapshot {
  pub https_port: u16,
  pub routes: BTreeMap<String, Arc<RuntimeRoute>>,
}

// Keep source bytes to detect rotations even if the configured paths are unchanged.
#[derive(PartialEq, Eq)]
pub struct Source {
  config: Vec<u8>,
  certificates: BTreeMap<PathBuf, (Vec<u8>, Vec<u8>)>,
}

impl Source {
  pub fn read(path: &Path) -> anyhow::Result<Self> {
    let config =
      fs::read(path).context("Failed to read proxy configuration")?;
    let parsed: ProxyConfig = serde_json::from_slice(&config)
      .context("Invalid proxy configuration JSON")?;
    parsed.validate()?;
    let mut certificates = BTreeMap::new();
    for route in &parsed.routes {
      if let Some(directory) = &route.certificate_directory {
        if certificates.contains_key(directory) {
          continue;
        }
        // Resolve current once: both PEM files must come from the same version.
        let version = fs::canonicalize(directory.join("current"))
          .with_context(|| {
            format!("Certificate unavailable for {}", route.domain)
          })?;
        certificates.insert(
          directory.clone(),
          (
            fs::read(version.join("tls.crt"))
              .context("Failed to read certificate chain")?,
            fs::read(version.join("tls.key"))
              .context("Failed to read certificate key")?,
          ),
        );
      }
    }
    Ok(Self {
      config,
      certificates,
    })
  }

  pub fn compile(&self) -> anyhow::Result<Snapshot> {
    let config: ProxyConfig = serde_json::from_slice(&self.config)?;
    let mut routes = BTreeMap::new();
    for route in &config.routes {
      let acceptor = match &route.certificate_directory {
        Some(directory) => {
          let (cert, key) = self
            .certificates
            .get(directory)
            .context("Missing certificate source")?;
          Some(build_acceptor(cert, key).with_context(|| {
            format!("Invalid TLS certificate for {}", route.domain)
          })?)
        }
        None => None,
      };
      routes.insert(
        route.domain.to_ascii_lowercase(),
        Arc::new(RuntimeRoute {
          upstream: parse_upstream(route)?,
          acceptor,
        }),
      );
    }
    Ok(Snapshot {
      https_port: config.https_port,
      routes,
    })
  }
}

fn parse_upstream(route: &ProxyRoute) -> anyhow::Result<url::Url> {
  if route.certificate_directory.is_some() {
    komodo_proxy_config::http_upstream(&route.upstream)
  } else {
    komodo_proxy_config::tcp_upstream(&route.upstream)
  }
}

fn build_acceptor(
  cert: &[u8],
  key: &[u8],
) -> anyhow::Result<TlsAcceptor> {
  #[cfg(feature = "rustls")]
  {
    use std::io::Cursor;

    let certificates = rustls_pemfile::certs(&mut Cursor::new(cert))
      .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key))?
      .context("Private key is missing")?;
    pingora_core::tls::install_default_crypto_provider();
    let mut config =
      pingora_core::tls::ServerConfig::builder_with_protocol_versions(
        &[
        &pingora_core::tls::version::TLS13,
        &pingora_core::tls::version::TLS12,
        ],
      )?
      .with_no_client_auth()
      .with_single_cert(certificates, key)?;
    config.alpn_protocols =
      vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from_server_config(Arc::new(config)))
  }

  #[cfg(feature = "openssl")]
  {
    use pingora_core::tls::{
      pkey::PKey,
      ssl::{AlpnError, SslAcceptor, SslMethod, select_next_proto},
      x509::X509,
    };

    let mut chain = X509::stack_from_pem(cert)?.into_iter();
    let Some(leaf) = chain.next() else {
      bail!("Certificate chain is empty");
    };
    let mut builder =
      SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_certificate(&leaf)?;
    let key = PKey::private_key_from_pem(key)?;
    builder.set_private_key(&key)?;
    for cert in chain {
      builder.add_extra_chain_cert(cert)?;
    }
    builder.check_private_key()?;
    builder.set_alpn_select_callback(|_, offered| {
      select_next_proto(b"\x02h2\x08http/1.1", offered)
        .ok_or(AlpnError::NOACK)
    });
    Ok(builder.build())
  }
}

pub struct Reload {
  pub path: PathBuf,
  pub state: Arc<ArcSwap<Snapshot>>,
  pub initial: std::sync::Mutex<Option<Source>>,
}

#[async_trait]
impl BackgroundService for Reload {
  async fn start(&self, mut shutdown: ShutdownWatch) {
    let mut previous = self
      .initial
      .lock()
      .expect("reload lock poisoned")
      .take()
      .expect("reload service started twice");
    let mut last_error = None;
    loop {
      tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
        _ = shutdown.changed() => break,
      }
      let loaded = Source::read(&self.path).and_then(|source| {
        if source == previous {
          return Ok(None);
        }
        Ok(Some((source.compile()?, source)))
      });
      match loaded {
        Ok(Some((snapshot, source))) => {
          self.state.store(Arc::new(snapshot));
          previous = source;
          last_error = None;
          log::info!(
            "Activated updated proxy routes and certificates"
          );
        }
        Ok(None) => {
          last_error = None;
        }
        Err(error) => {
          let message = format!("{error:#}");
          if last_error.as_ref() != Some(&message) {
            log::error!(
              "Proxy reload rejected; retaining last good configuration: {message}"
            );
            last_error = Some(message);
          }
        }
      }
    }
  }
}
