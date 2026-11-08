use komodo_client::entities::certificate::CertificateIssuer;
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(EnsureCertificateResponse)]
#[error(anyhow::Error)]
pub struct EnsureCertificate {
  pub id: String,
  pub domains: Vec<String>,
  pub issuer: CertificateIssuer,
  #[serde(default)]
  pub force: bool,
  #[serde(default)]
  pub cloudflare_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsureCertificateResponse {
  pub expires_at: i64,
  pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(())]
#[error(anyhow::Error)]
pub struct RemoveCertificate {
  pub id: String,
}
