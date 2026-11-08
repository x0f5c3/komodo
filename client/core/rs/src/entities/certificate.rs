use bson::Document;
use partial_derive2::Partial;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use super::{
  I64, ResourceTargetVariant,
  resource::{AddFilters, Resource, ResourceListItem, ResourceQuery},
};

#[typeshare]
pub type Certificate = Resource<CertificateConfig, CertificateInfo>;

#[cfg(feature = "utoipa")]
#[derive(utoipa::ToSchema)]
#[schema(as = Certificate)]
pub struct CertificateSchema(
  #[schema(inline)] pub Resource<CertificateConfig, CertificateInfo>,
);

#[typeshare]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CertificateInfo {
  /// Unix timestamp of the last successful issue or renewal.
  #[serde(default)]
  pub last_issued: I64,
  /// Certificate expiry timestamp reported by the host.
  #[serde(default)]
  pub expires_at: I64,
  /// A non-secret status summary.
  #[serde(default)]
  pub status: String,
}

#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CertificateListItemInfo {
  pub server_id: String,
  pub server_name: String,
  pub provider: CertificateProvider,
  pub domains: Vec<String>,
  pub last_issued: I64,
  pub expires_at: I64,
  pub status: String,
}

#[typeshare]
pub type CertificateListItem = ResourceListItem<CertificateListItemInfo>;

#[typeshare]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum CertificateProvider {
  /// Issue with Certbot using the DNS-01 challenge and a host-local
  /// Cloudflare API token.
  #[default]
  CloudflareDns01,
  /// Retrieve a certificate using the host's authenticated Tailscale CLI.
  Tailscale,
}

#[typeshare]
#[derive(Debug, Clone, Default, Serialize, Deserialize, Partial)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[partial_derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", partial_derive(schemars::JsonSchema))]
#[diff_derive(Debug, Clone, Default, Serialize, Deserialize)]
#[partial(skip_serializing_none, from, diff)]
pub struct CertificateConfig {
  /// The Unix Server whose Periphery agent owns the certificate files.
  #[serde(default, alias = "server")]
  pub server_id: String,
  /// Exact DNS names included in the certificate. Wildcards are accepted
  /// for certificates, but are never accepted as proxy route names.
  #[serde(default)]
  pub domains: Vec<String>,
  #[serde(default)]
  pub provider: CertificateProvider,
  /// Required by ACME for account registration and expiry notifications.
  #[serde(default)]
  pub email: String,
  /// Name of the Cloudflare token in Periphery's local `secrets` map.
  /// The token value is never sent to or stored in Core.
  #[serde(default)]
  pub cloudflare_token_secret: String,
  /// Optional name passed to the Tailscale CLI; defaults to the first domain.
  #[serde(default)]
  pub tailscale_cert_name: String,
  /// Routes associated with this certificate. Route domains must be exact.
  #[serde(default)]
  pub proxy_routes: Vec<CertificateProxyRoute>,
}

#[typeshare]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct CertificateMount {
  /// Certificate resource id or name.
  pub certificate: String,
  /// Absolute path visible inside the workload.
  pub mount_path: String,
  /// Required for Stack services; ignored for Deployments.
  #[serde(default)]
  pub service: String,
}

#[typeshare]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct CertificateProxyRoute {
  /// Exact public hostname; wildcard routes are deliberately unsupported.
  pub domain: String,
  /// HTTP(S) upstream URL or host:port.
  pub upstream: String,
  #[serde(default)]
  pub tls_mode: CertificateTlsMode,
  /// Redirect HTTP requests to HTTPS for this domain.
  #[serde(default)]
  pub redirect_http_to_https: bool,
}

#[typeshare]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum CertificateTlsMode {
  /// Terminate TLS in the managed Pingora proxy.
  #[default]
  Terminate,
  /// Forward the TLS stream based on exact SNI without terminating it.
  SniPassthrough,
}

#[typeshare]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CertificateQuerySpecifics {
  #[serde(default)]
  pub server_ids: Vec<String>,
}

impl AddFilters for CertificateQuerySpecifics {
  fn add_filters(&self, filters: &mut Document) {
    if !self.server_ids.is_empty() {
      filters.insert(
        "config.server_id",
        bson::doc! { "$in": &self.server_ids },
      );
    }
  }
}

#[typeshare]
pub type CertificateQuery = ResourceQuery<CertificateQuerySpecifics>;

#[typeshare(serialized_as = "Partial<CertificateConfig>")]
pub type _PartialCertificateConfig = PartialCertificateConfig;

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for PartialCertificateConfig {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for PartialCertificateConfig {}

impl Certificate {
  pub fn target(&self) -> crate::entities::ResourceTarget {
    crate::entities::ResourceTarget::Certificate(self.id.clone())
  }
}

impl CertificateListItem {
  pub fn resource_type(&self) -> ResourceTargetVariant {
    ResourceTargetVariant::Certificate
  }
}
