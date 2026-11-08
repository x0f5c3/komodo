use anyhow::Context;
use komodo_client::{
  api::execute::RenewCertificate,
  entities::{
    certificate::Certificate,
    permission::PermissionLevel,
    update::{Log, Update},
  },
};
use mogh_resolver::Resolve;

use crate::{
  permission::get_check_permissions,
  resource::certificate::ensure_certificate,
  helpers::update::update_update,
};

use super::ExecuteArgs;

impl Resolve<ExecuteArgs> for RenewCertificate {
  #[instrument("RenewCertificate", skip_all, fields(certificate = self.certificate))]
  async fn resolve(
    self,
    ExecuteArgs {
      user, update, ..
    }: &ExecuteArgs,
  ) -> mogh_error::Result<Update> {
    let certificate = get_check_permissions::<Certificate>(
      &self.certificate,
      user,
      PermissionLevel::Execute.into(),
    )
    .await?;
    let mut update = update.clone();
    match ensure_certificate(&certificate, self.force)
      .await
      .context("Failed to ensure Certificate")
    {
      Ok(true) => update.logs.push(Log::simple(
        "Certificate renewal",
        "A new immutable certificate version was installed on the Periphery host.".to_string(),
      )),
      Ok(false) => update.logs.push(Log::simple(
        "Certificate renewal",
        "The current certificate remains active.".to_string(),
      )),
      Err(error) => update.push_error_log(
        "Certificate renewal",
        format!("{error:#}"),
      ),
    }
    update.finalize();
    update_update(update.clone()).await?;
    Ok(update)
  }
}
