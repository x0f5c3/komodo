use komodo_client::{
  api::write::*,
  entities::{
    certificate::Certificate,
    permission::PermissionLevel,
    update::Update,
  },
};
use mogh_resolver::Resolve;

use crate::{permission::get_check_permissions, resource};

use super::WriteArgs;

impl Resolve<WriteArgs> for CreateCertificate {
  async fn resolve(
    self,
    WriteArgs { user }: &WriteArgs,
  ) -> mogh_error::Result<Certificate> {
    resource::create::<Certificate>(&self.name, self.config, None, user)
      .await
  }
}

impl Resolve<WriteArgs> for CopyCertificate {
  async fn resolve(
    self,
    WriteArgs { user }: &WriteArgs,
  ) -> mogh_error::Result<Certificate> {
    let Certificate { config, .. } =
      get_check_permissions::<Certificate>(
        &self.id,
        user,
        PermissionLevel::Write.into(),
      )
      .await?;
    resource::create::<Certificate>(&self.name, config.into(), None, user)
      .await
  }
}

impl Resolve<WriteArgs> for DeleteCertificate {
  async fn resolve(
    self,
    WriteArgs { user }: &WriteArgs,
  ) -> mogh_error::Result<Certificate> {
    Ok(resource::delete::<Certificate>(&self.id, user).await?)
  }
}

impl Resolve<WriteArgs> for UpdateCertificate {
  async fn resolve(
    self,
    WriteArgs { user }: &WriteArgs,
  ) -> mogh_error::Result<Certificate> {
    Ok(
      resource::update::<Certificate>(&self.id, self.config, user)
        .await?,
    )
  }
}

impl Resolve<WriteArgs> for RenameCertificate {
  async fn resolve(
    self,
    WriteArgs { user }: &WriteArgs,
  ) -> mogh_error::Result<Update> {
    Ok(resource::rename::<Certificate>(&self.id, &self.name, user).await?)
  }
}
