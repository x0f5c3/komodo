use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::entities::{
  certificate::{Certificate, _PartialCertificateConfig},
  update::Update,
};

use super::KomodoWriteRequest;

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/CreateCertificate",
  description = "Create a managed certificate.",
  request_body(content = CreateCertificate),
  responses(
    (status = 200, description = "The certificate", body = crate::entities::certificate::CertificateSchema),
  ),
)]
pub fn create_certificate() {}

#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoWriteRequest)]
#[response(Certificate)]
#[error(mogh_error::Error)]
pub struct CreateCertificate {
  pub name: String,
  #[serde(default)]
  pub config: _PartialCertificateConfig,
}

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/CopyCertificate",
  description = "Copy a managed certificate.",
  request_body(content = CopyCertificate),
  responses(
    (status = 200, description = "The certificate", body = crate::entities::certificate::CertificateSchema),
  ),
)]
pub fn copy_certificate() {}

#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoWriteRequest)]
#[response(Certificate)]
#[error(mogh_error::Error)]
pub struct CopyCertificate {
  pub name: String,
  pub id: String,
}

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/DeleteCertificate",
  description = "Delete a managed certificate.",
  request_body(content = DeleteCertificate),
  responses(
    (status = 200, description = "The deleted certificate", body = crate::entities::certificate::CertificateSchema),
  ),
)]
pub fn delete_certificate() {}

#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoWriteRequest)]
#[response(Certificate)]
#[error(mogh_error::Error)]
pub struct DeleteCertificate {
  pub id: String,
}

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/UpdateCertificate",
  description = "Update a managed certificate.",
  request_body(content = UpdateCertificate),
  responses(
    (status = 200, description = "The certificate", body = crate::entities::certificate::CertificateSchema),
  ),
)]
pub fn update_certificate() {}

#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoWriteRequest)]
#[response(Certificate)]
#[error(mogh_error::Error)]
pub struct UpdateCertificate {
  pub id: String,
  pub config: _PartialCertificateConfig,
}

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/RenameCertificate",
  description = "Rename a managed certificate.",
  request_body(content = RenameCertificate),
  responses((status = 200, description = "The update", body = Update)),
)]
pub fn rename_certificate() {}

#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(KomodoWriteRequest)]
#[response(Update)]
#[error(mogh_error::Error)]
pub struct RenameCertificate {
  pub id: String,
  pub name: String,
}
