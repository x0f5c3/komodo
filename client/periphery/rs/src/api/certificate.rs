use komodo_client::entities::certificate::{CertificateConfig, CertificateTlsMode};
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(CertificateIssueResult)]
#[error(anyhow::Error)]
pub struct EnsureCertificate {
  /// Mongo resource id; validated as a safe path component by Periphery.
  pub id: String,
  pub config: CertificateConfig,
  #[serde(default)]
  pub force: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificateIssueResult {
  /// True only when the active certificate contents were atomically changed.
  pub changed: bool,
  /// Expiry timestamp in Unix seconds, or 0 when unavailable.
  pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(())]
#[error(anyhow::Error)]
pub struct DeleteCertificate {
  pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(String)]
#[error(anyhow::Error)]
pub struct GetHostPlatform {}

#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(Log)]
#[error(anyhow::Error)]
pub struct ReconcileCertificateProxy {
  pub routes: Vec<ManagedProxyRoute>,
  /// Public HTTPS listener in host:port form.
  pub listener: String,
  /// Dedicated managed Pingora image.
  pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedProxyRoute {
  pub certificate_id: String,
  pub domain: String,
  pub upstream: String,
  pub tls_mode: CertificateTlsMode,
  pub redirect_http_to_https: bool,
}

use komodo_client::entities::update::Log;
