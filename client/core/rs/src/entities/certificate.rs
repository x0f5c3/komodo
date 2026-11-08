use partial_derive2::Partial;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use super::{
  I64,
  resource::{Resource, ResourceListItem, ResourceQuery},
};

#[cfg(feature = "utoipa")]
#[derive(utoipa::ToSchema)]
#[schema(as = Certificate)]
pub struct CertificateSchema(
  #[schema(inline)] pub Resource<CertificateConfig, CertificateInfo>,
);

#[typeshare]
pub type Certificate = Resource<CertificateConfig, CertificateInfo>;

#[typeshare]
pub type CertificateListItem =
  ResourceListItem<CertificateListItemInfo>;

#[typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CertificateListItemInfo {
  pub server_id: String,
  pub domains: Vec<String>,
  pub issuer: CertificateIssuer,
  pub status: CertificateStatus,
  pub expires_at: Option<I64>,
}

#[typeshare(serialized_as = "Partial<CertificateConfig>")]
pub type _PartialCertificateConfig = PartialCertificateConfig;

#[typeshare]
#[derive(Debug, Clone, Default, Serialize, Deserialize, Partial)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[partial_derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
  feature = "schemars",
  partial_derive(schemars::JsonSchema)
)]
#[diff_derive(Debug, Clone, Default, Serialize, Deserialize)]
#[partial(skip_serializing_none, from, diff)]
pub struct CertificateConfig {
  /// The server where this certificate will be issued and stored.
  #[serde(default)]
  pub server_id: String,

  /// DNS names covered by this certificate.
  #[serde(default)]
  pub domains: Vec<String>,

  /// The certificate issuer. Credentials are referenced by name and are not
  /// stored in this resource.
  #[serde(default)]
  pub issuer: CertificateIssuer,
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for PartialCertificateConfig {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for PartialCertificateConfig {}

#[typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(tag = "type", content = "params", rename_all = "snake_case")]
pub enum CertificateIssuer {
  AcmeCloudflare {
    /// Name of the Core config secret containing a scoped Cloudflare API token.
    api_token_secret: String,
    #[serde(default)]
    email: String,
  },
  Tailscale,
}

impl Default for CertificateIssuer {
  fn default() -> Self {
    Self::AcmeCloudflare {
      api_token_secret: String::new(),
      email: String::new(),
    }
  }
}

#[typeshare]
#[derive(
  Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
  #[default]
  Pending,
  Ready,
  Error,
}

#[typeshare]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CertificateInfo {
  #[serde(default)]
  pub status: CertificateStatus,
  #[serde(default)]
  pub expires_at: Option<I64>,
  #[serde(default)]
  pub last_error: Option<String>,
  /// Workloads awaiting acknowledgement of the current certificate rotation.
  #[serde(default)]
  pub pending_restarts: Vec<String>,
}

#[typeshare]
pub type CertificateQuery = ResourceQuery<()>;

#[typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct DeploymentCertificateAttachment {
  pub certificate_id: String,
  /// Directory inside the container. `current/tls.crt` and
  /// `current/tls.key` are available below this path.
  pub mount_path: String,
  #[serde(default)]
  pub refresh: CertificateRefreshBehavior,
}

#[typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct StackCertificateAttachment {
  pub certificate_id: String,
  pub service: String,
  /// Directory inside the Compose service. `current/tls.crt` and
  /// `current/tls.key` are available below this path.
  pub mount_path: String,
  #[serde(default)]
  pub refresh: CertificateRefreshBehavior,
}

#[typeshare]
#[derive(
  Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum CertificateRefreshBehavior {
  #[default]
  Restart,
  HotReload,
}
