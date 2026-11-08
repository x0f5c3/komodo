use komodo_client::{
  api::read::*,
  entities::{
    certificate::{Certificate, CertificateListItem},
    permission::PermissionLevel,
  },
};
use mogh_resolver::Resolve;

use crate::{permission::get_check_permissions, resource};

use super::{ReadArgs, list_limit};

impl Resolve<ReadArgs> for GetCertificate {
  async fn resolve(
    self,
    ReadArgs { user }: &ReadArgs,
  ) -> mogh_error::Result<Certificate> {
    Ok(
      get_check_permissions::<Certificate>(
        &self.certificate,
        user,
        PermissionLevel::Read.into(),
      )
      .await?,
    )
  }
}

impl Resolve<ReadArgs> for ListCertificates {
  async fn resolve(
    self,
    ReadArgs { user }: &ReadArgs,
  ) -> mogh_error::Result<Vec<CertificateListItem>> {
    let limit = list_limit(self.limit);
    Ok(
      resource::list_items_for_user::<Certificate>(
        self.query,
        resource::ListItemsQueryOptions {
          limit,
          page: self.page,
          sort_desc: self.sort_desc,
          sort_by: resource::ListItemSort::Name,
        },
        user,
        PermissionLevel::Read.into(),
        &[],
        |_| true,
      )
      .await?,
    )
  }
}

impl Resolve<ReadArgs> for ListFullCertificates {
  async fn resolve(
    self,
    ReadArgs { user }: &ReadArgs,
  ) -> mogh_error::Result<ListFullCertificatesResponse> {
    let limit = list_limit(self.limit);
    Ok(
      resource::list_full_for_user::<Certificate>(
        self.query,
        limit as i64,
        self.page.saturating_mul(limit),
        user,
        PermissionLevel::Read.into(),
        &[],
      )
      .await?,
    )
  }
}
