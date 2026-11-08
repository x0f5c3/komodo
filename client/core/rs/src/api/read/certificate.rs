use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
  entities::{
    U64,
    certificate::{
      Certificate, CertificateListItem, CertificateQuery,
    },
  },
};

use super::KomodoReadRequest;

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/GetCertificate",
  description = "Get a managed certificate.",
  request_body(content = GetCertificate),
  responses(
    (status = 200, description = "The certificate", body = crate::entities::certificate::CertificateSchema),
  ),
)]
pub fn get_certificate() {}

/// Get a managed certificate.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoReadRequest)]
#[response(GetCertificateResponse)]
#[error(mogh_error::Error)]
pub struct GetCertificate {
  #[serde(alias = "id", alias = "name")]
  pub certificate: String,
}

#[typeshare]
pub type GetCertificateResponse = Certificate;

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/ListCertificates",
  description = "List managed certificates.",
  request_body(content = ListCertificates),
  responses(
    (status = 200, description = "The certificates", body = ListCertificatesResponse),
  ),
)]
pub fn list_certificates() {}

#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Default, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoReadRequest)]
#[response(ListCertificatesResponse)]
#[error(mogh_error::Error)]
pub struct ListCertificates {
  #[serde(default)]
  pub query: CertificateQuery,
  #[serde(default)]
  pub page: U64,
  pub limit: Option<U64>,
}

#[typeshare]
pub type ListCertificatesResponse = Vec<CertificateListItem>;

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/ListFullCertificates",
  description = "List full managed certificate resources.",
  request_body(content = ListFullCertificates),
  responses(
    (status = 200, description = "The certificates", body = ListFullCertificatesResponse),
  ),
)]
pub fn list_full_certificates() {}

#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Default, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoReadRequest)]
#[response(ListFullCertificatesResponse)]
#[error(mogh_error::Error)]
pub struct ListFullCertificates {
  #[serde(default)]
  pub query: CertificateQuery,
  #[serde(default)]
  pub page: U64,
  pub limit: Option<U64>,
}

#[typeshare]
pub type ListFullCertificatesResponse = Vec<Certificate>;
