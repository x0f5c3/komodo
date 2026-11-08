use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::entities::update::Update;

use super::KomodoExecuteRequest;

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/RenewCertificate",
  description = "Check or force renewal of a managed Certificate.",
  request_body(content = RenewCertificate),
  responses((status = 200, description = "The renewal update", body = Update)),
)]
pub fn renew_certificate() {}

/// Check or force renewal of a managed certificate.
/// Private key material never leaves the Periphery host.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoExecuteRequest)]
#[response(Update)]
#[error(mogh_error::Error)]
pub struct RenewCertificate {
  pub certificate: String,
  #[serde(default)]
  pub force: bool,
}
