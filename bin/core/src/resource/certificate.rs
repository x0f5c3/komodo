use std::time::Duration;

use anyhow::Context;
use database::{
  bson::to_bson,
  mungos::{
    by_id::update_one_by_id,
    find::find_collect,
    mongodb::{Collection, bson::doc},
    update::Update as DbUpdate,
  },
};
use indexmap::IndexSet;
use komodo_client::entities::{
  Operation, ResourceTarget, ResourceTargetVariant,
  certificate::{
    Certificate, CertificateConfig, CertificateConfigDiff,
    CertificateInfo, CertificateIssuer, CertificateListItem,
    CertificateListItemInfo, CertificateRefreshBehavior,
    CertificateStatus, PartialCertificateConfig,
  },
  permission::{PermissionLevel, SpecificPermission},
  resource::Resource,
  server::Server,
  update::Update,
  user::User,
};
use periphery_client::api::certificate::{
  EnsureCertificate, RemoveCertificate,
};

use crate::{
  config::core_config, helpers::periphery_client, state::db_client,
};
use periphery_client::api as periphery_api;

pub async fn validate_attachment(
  certificate_id: &str,
  server_id: &str,
  user: &User,
) -> anyhow::Result<String> {
  let certificate = super::get_check_permissions::<Certificate>(
    certificate_id,
    user,
    PermissionLevel::Read.attach(),
  )
  .await
  .context("Cannot attach this Certificate")?;
  if certificate.config.server_id != server_id {
    anyhow::bail!(
      "Certificate and workload must be assigned to the same Server."
    );
  }
  Ok(certificate.id)
}

pub fn validate_mount_path(path: &str) -> anyhow::Result<String> {
  let path = path.trim();
  if !path.starts_with('/')
    || path == "/"
    || path.contains('\\')
    || path.contains(':')
    || path.contains(',')
    || path.contains('\0')
    || path
      .split('/')
      .any(|component| component == "." || component == "..")
  {
    anyhow::bail!(
      "Certificate mount path must be an absolute container path without dot, colon, comma, or backslash characters."
    );
  }
  Ok(path.trim_end_matches('/').to_string())
}

impl super::KomodoResource for Certificate {
  type Config = CertificateConfig;
  type PartialConfig = PartialCertificateConfig;
  type ConfigDiff = CertificateConfigDiff;
  type Info = CertificateInfo;
  type ListItem = CertificateListItem;
  type QuerySpecifics = ();

  fn resource_type() -> ResourceTargetVariant {
    ResourceTargetVariant::Certificate
  }

  fn resource_target(id: impl Into<String>) -> ResourceTarget {
    ResourceTarget::Certificate(id.into())
  }

  fn creator_specific_permissions() -> IndexSet<SpecificPermission> {
    [SpecificPermission::Inspect].into_iter().collect()
  }

  fn coll() -> &'static Collection<Resource<Self::Config, Self::Info>>
  {
    &db_client().certificates
  }

  async fn to_list_item(
    certificate: Resource<Self::Config, Self::Info>,
  ) -> Self::ListItem {
    CertificateListItem {
      name: certificate.name,
      id: certificate.id,
      template: certificate.template,
      tags: certificate.tags,
      resource_type: ResourceTargetVariant::Certificate,
      info: CertificateListItemInfo {
        server_id: certificate.config.server_id,
        domains: certificate.config.domains,
        issuer: certificate.config.issuer,
        status: certificate.info.status,
        expires_at: certificate.info.expires_at,
      },
    }
  }

  async fn busy(_id: &String) -> anyhow::Result<bool> {
    Ok(false)
  }

  fn create_operation() -> Operation {
    Operation::CreateCertificate
  }

  fn user_can_create(user: &User) -> bool {
    user.admin
  }

  async fn validate_create_config(
    config: &mut Self::PartialConfig,
    user: &User,
  ) -> anyhow::Result<()> {
    validate_config(config, user, None, None).await
  }

  async fn post_create(
    _created: &Resource<Self::Config, Self::Info>,
    _update: &mut Update,
  ) -> anyhow::Result<()> {
    Ok(())
  }

  fn update_operation() -> Operation {
    Operation::UpdateCertificate
  }

  async fn validate_update_config(
    id: &str,
    config: &mut Self::PartialConfig,
    user: &User,
  ) -> anyhow::Result<()> {
    let existing = super::get::<Certificate>(id).await?;
    validate_config(config, user, Some(&existing.config), Some(id))
      .await
  }

  async fn post_update(
    updated: &Self,
    _update: &mut Update,
  ) -> anyhow::Result<()> {
    update_certificate_info(
      &updated.id,
      CertificateInfo {
        status: CertificateStatus::Pending,
        expires_at: None,
        last_error: None,
      },
    )
    .await?;
    Ok(())
  }

  fn rename_operation() -> Operation {
    Operation::RenameCertificate
  }

  fn delete_operation() -> Operation {
    Operation::DeleteCertificate
  }

  async fn pre_delete(
    resource: &Resource<Self::Config, Self::Info>,
    _update: &mut Update,
  ) -> anyhow::Result<()> {
    let server = super::get::<Server>(&resource.config.server_id)
      .await
      .context("Certificate Server no longer exists")?;
    let used_by_proxy = server.config.reverse_proxy.routes.iter().any(
      |route| {
        matches!(
          &route.tls,
          komodo_client::entities::server::ReverseProxyTlsMode::Terminate {
            certificate_id
          } if certificate_id == &resource.id
        )
      },
    );
    if used_by_proxy {
      anyhow::bail!(
        "Remove this Certificate from the Server's reverse proxy routes before deleting it."
      );
    }

    let deployments = find_collect(
      &db_client().deployments,
      doc! { "config.certificate_mounts.certificate_id": &resource.id },
      None,
    )
    .await
    .context("Failed to check Certificate Deployment attachments")?;
    let stacks = find_collect(
      &db_client().stacks,
      doc! { "config.certificate_mounts.certificate_id": &resource.id },
      None,
    )
    .await
    .context("Failed to check Certificate Stack attachments")?;
    if !deployments.is_empty() || !stacks.is_empty() {
      anyhow::bail!(
        "Remove this Certificate from attached Deployments and Stacks before deleting it."
      );
    }
    Ok(())
  }

  async fn post_delete(
    resource: &Resource<Self::Config, Self::Info>,
    _update: &mut Update,
  ) -> anyhow::Result<()> {
    let server =
      super::get::<Server>(&resource.config.server_id).await?;
    periphery_client(&server)
      .await?
      .request(RemoveCertificate {
        id: resource.id.clone(),
      })
      .await
      .context("Failed to remove certificate files from Periphery")?;
    Ok(())
  }
}

pub fn spawn_certificate_refresh_loop() {
  tokio::spawn(async {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
      interval.tick().await;
      refresh_certificates().await;
    }
  });
}

async fn refresh_certificates() {
  let certificates =
    match find_collect(&db_client().certificates, None, None).await {
      Ok(certificates) => certificates,
      Err(error) => {
        error!("Failed to load Certificates for refresh | {error:#}");
        return;
      }
    };

  for certificate in certificates {
    let result = refresh_certificate(&certificate).await;
    let (info, changed) = match result {
      Ok((expires_at, changed)) => (
        CertificateInfo {
          status: CertificateStatus::Ready,
          expires_at: Some(expires_at),
          last_error: None,
        },
        changed,
      ),
      Err(error) => {
        warn!(
          "Certificate refresh failed | {} | {error:#}",
          certificate.name
        );
        (
          CertificateInfo {
            status: CertificateStatus::Error,
            expires_at: certificate.info.expires_at,
            last_error: Some(format!("{error:#}")),
          },
          false,
        )
      }
    };
    if let Err(error) =
      update_certificate_info(&certificate.id, info).await
    {
      error!(
        "Failed to update Certificate state | {} | {error:#}",
        certificate.name
      );
    }
    if changed
      && let Err(error) =
        restart_attached_workloads(&certificate).await
    {
      error!(
        "Certificate was renewed but attached workloads could not all be restarted | {} | {error:#}",
        certificate.name
      );
    }
  }
}

async fn refresh_certificate(
  certificate: &Resource<CertificateConfig, CertificateInfo>,
) -> anyhow::Result<(i64, bool)> {
  let server = super::get::<Server>(&certificate.config.server_id)
    .await
    .context("Certificate Server no longer exists")?;
  let cloudflare_token = match &certificate.config.issuer {
    CertificateIssuer::AcmeCloudflare {
      api_token_secret, ..
    } => Some(
      core_config()
        .secrets
        .get(api_token_secret)
        .with_context(|| {
          format!(
            "Cloudflare token secret '{api_token_secret}' is not configured in Core"
          )
        })?
        .clone(),
    ),
    CertificateIssuer::Tailscale => None,
  };
  let response = periphery_client(&server)
    .await?
    .request(EnsureCertificate {
      id: certificate.id.clone(),
      domains: certificate.config.domains.clone(),
      issuer: certificate.config.issuer.clone(),
      force: false,
      cloudflare_token,
    })
    .await
    .context("Failed to issue or renew certificate on Periphery")?;
  Ok((response.expires_at, response.changed))
}

async fn restart_attached_workloads(
  certificate: &Resource<CertificateConfig, CertificateInfo>,
) -> anyhow::Result<()> {
  let server = super::get::<Server>(&certificate.config.server_id)
    .await
    .context("Certificate Server no longer exists")?;
  if server.config.reverse_proxy.enabled
    && server
      .config
      .reverse_proxy
      .routes
      .iter()
      .any(|route| {
        matches!(
          &route.tls,
          komodo_client::entities::server::ReverseProxyTlsMode::Terminate {
            certificate_id
          } if certificate_id == &certificate.id
        )
      })
  {
    periphery_client(&server)
      .await?
      .request(periphery_api::reverse_proxy::EnsureReverseProxy {
        server_id: server.id.clone(),
        config: server.config.reverse_proxy.clone(),
      })
      .await
      .context("Failed to reload reverse proxy certificate")?;
  }

  let deployments = find_collect(
    &db_client().deployments,
    doc! {
      "config.certificate_mounts.certificate_id": &certificate.id
    },
    None,
  )
  .await
  .context("Failed to find attached Deployments")?;
  for deployment in deployments {
    if !deployment.config.certificate_mounts.iter().any(
      |attachment| {
        attachment.certificate_id == certificate.id
          && attachment.refresh == CertificateRefreshBehavior::Restart
      },
    ) {
      continue;
    }
    let server = super::get::<Server>(&deployment.config.server_id)
      .await
      .context("Attached Deployment Server no longer exists")?;
    let result = periphery_client(&server)
      .await?
      .request(periphery_api::container::RestartContainer {
        name: deployment.deployed_name().to_string(),
      })
      .await
      .with_context(|| {
        format!("Failed to restart Deployment '{}'", deployment.name)
      })?;
    if !result.success {
      anyhow::bail!(
        "Failed to restart Deployment '{}': {}",
        deployment.name,
        result.stderr
      );
    }
  }

  let stacks = find_collect(
    &db_client().stacks,
    doc! {
      "config.certificate_mounts.certificate_id": &certificate.id
    },
    None,
  )
  .await
  .context("Failed to find attached Stacks")?;
  for stack in stacks {
    let services = stack
      .config
      .certificate_mounts
      .iter()
      .filter(|attachment| {
        attachment.certificate_id == certificate.id
          && attachment.refresh == CertificateRefreshBehavior::Restart
      })
      .map(|attachment| attachment.service.clone())
      .collect::<IndexSet<_>>()
      .into_iter()
      .collect::<Vec<_>>();
    if services.is_empty() {
      continue;
    }
    let server = super::get::<Server>(&stack.config.server_id)
      .await
      .context("Attached Stack Server no longer exists")?;
    let project = shlex::try_quote(&stack.project_name(false))
      .context("Invalid Stack project name")?
      .into_owned();
    let services =
      shlex::try_join(services.iter().map(String::as_str))
        .context("Invalid Stack service name")?;
    let command = format!("restart -- {services}");
    let result = periphery_client(&server)
      .await?
      .request(periphery_api::compose::ComposeExecution {
        project,
        command,
      })
      .await
      .with_context(|| {
        format!("Failed to restart attached Stack '{}'", stack.name)
      })?;
    if !result.success {
      anyhow::bail!(
        "Failed to restart Stack '{}': {}",
        stack.name,
        result.stderr
      );
    }
  }
  Ok(())
}

async fn update_certificate_info(
  id: &str,
  info: CertificateInfo,
) -> anyhow::Result<()> {
  update_one_by_id(
    &db_client().certificates,
    id,
    DbUpdate::Set(doc! {
      "info": to_bson(&info).context("Failed to serialize Certificate state")?
    }),
    None,
  )
  .await
  .context("Failed to persist Certificate state")?;
  Ok(())
}

async fn validate_config(
  config: &mut PartialCertificateConfig,
  user: &User,
  existing: Option<&CertificateConfig>,
  certificate_id: Option<&str>,
) -> anyhow::Result<()> {
  if let Some(server_id) = &mut config.server_id {
    *server_id = server_id.trim().to_string();
  }
  let server_id = config
    .server_id
    .as_deref()
    .or(existing.map(|config| config.server_id.as_str()))
    .unwrap_or_default()
    .to_string();
  if server_id.is_empty() {
    anyhow::bail!("Certificate must be attached to a Server.");
  }
  if let Some(existing) = existing
    && server_id != existing.server_id
  {
    anyhow::bail!(
      "A Certificate cannot be moved to another Server; create a new Certificate instead."
    );
  }
  if config.server_id.is_some() {
    let server = super::get_check_permissions::<Server>(
      &server_id,
      user,
      PermissionLevel::Read.attach(),
    )
    .await
    .context("Cannot attach Certificate to this Server")?;
    config.server_id = Some(server.id);
  }

  if let Some(domains) = &mut config.domains {
    domains.iter_mut().for_each(|domain| {
      *domain = domain.trim().to_ascii_lowercase();
    });
    domains.sort();
    domains.dedup();
  }
  let domains = config
    .domains
    .as_ref()
    .or_else(|| existing.map(|config| &config.domains))
    .map(Vec::as_slice)
    .unwrap_or_default();
  if domains.is_empty() {
    anyhow::bail!("Certificate must include at least one DNS name.");
  }
  if domains.iter().any(|domain| !valid_domain(domain)) {
    anyhow::bail!("Certificate must contain valid DNS names.");
  }
  if existing.is_some_and(|existing| existing.domains != domains) {
    let server = super::get::<Server>(&server_id).await?;
    for route in &server.config.reverse_proxy.routes {
      if matches!(
        &route.tls,
        komodo_client::entities::server::ReverseProxyTlsMode::Terminate {
          certificate_id: route_certificate_id
        } if Some(route_certificate_id.as_str()) == certificate_id
      ) && !certificate_covers_domain(domains, &route.domain)
      {
        anyhow::bail!(
          "Updated Certificate domains would no longer cover reverse proxy route '{}'.",
          route.domain
        );
      }
    }
  }

  if let Some(CertificateIssuer::AcmeCloudflare {
    api_token_secret,
    ..
  }) = &mut config.issuer
  {
    *api_token_secret = api_token_secret.trim().to_string();
  }
  let issuer = config
    .issuer
    .as_ref()
    .or_else(|| existing.map(|config| &config.issuer));
  if let Some(issuer) = issuer {
    match issuer {
      CertificateIssuer::AcmeCloudflare {
        api_token_secret, ..
      } if api_token_secret.trim().is_empty() => {
        anyhow::bail!(
          "ACME Cloudflare certificates require an API token secret reference."
        );
      }
      CertificateIssuer::AcmeCloudflare {
        api_token_secret, ..
      } if !crate::config::core_config()
        .secrets
        .contains_key(api_token_secret) =>
      {
        anyhow::bail!(
          "The referenced Cloudflare token secret is not configured in Core."
        );
      }
      CertificateIssuer::Tailscale
        if domains.len() != 1 || domains[0].starts_with("*.") =>
      {
        anyhow::bail!(
          "Tailscale certificates require exactly one non-wildcard DNS name."
        );
      }
      _ => {}
    }
  } else {
    anyhow::bail!("Certificate issuer must be selected.");
  }
  Ok(())
}

pub(crate) fn valid_domain(domain: &str) -> bool {
  let domain = domain.strip_prefix("*.").unwrap_or(domain);
  if domain.is_empty() || domain.len() > 253 {
    return false;
  }

  let labels = domain.split('.').collect::<Vec<_>>();
  labels.len() >= 2
    && domain.parse::<std::net::IpAddr>().is_err()
    && labels.iter().all(|label| {
      !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

pub(crate) fn certificate_covers_domain(
  certificate_domains: &[String],
  domain: &str,
) -> bool {
  certificate_domains.iter().any(|certificate_domain| {
    if certificate_domain == domain {
      return true;
    }
    let Some(suffix) = certificate_domain.strip_prefix("*.") else {
      return false;
    };
    domain
      .strip_suffix(suffix)
      .and_then(|prefix| prefix.strip_suffix('.'))
      .is_some_and(|label| !label.is_empty() && !label.contains('.'))
  })
}

#[cfg(test)]
mod tests {
  use super::{certificate_covers_domain, valid_domain};

  #[test]
  fn accepts_dns_names_and_wildcards() {
    assert!(valid_domain("example.com"));
    assert!(valid_domain("*.example.com"));
    assert!(valid_domain("service-1.example.com"));
  }

  #[test]
  fn rejects_malformed_dns_names() {
    assert!(!valid_domain(""));
    assert!(!valid_domain(".example.com"));
    assert!(!valid_domain("example..com"));
    assert!(!valid_domain("-example.com"));
    assert!(!valid_domain("*."));
    assert!(!valid_domain("two.*.example.com"));
    assert!(!valid_domain("localhost"));
    assert!(!valid_domain("192.0.2.1"));
  }

  #[test]
  fn matches_exact_and_single_label_wildcard_certificates() {
    assert!(certificate_covers_domain(
      &["app.example.com".into()],
      "app.example.com",
    ));
    assert!(certificate_covers_domain(
      &["*.example.com".into()],
      "app.example.com",
    ));
    assert!(!certificate_covers_domain(
      &["*.example.com".into()],
      "deep.app.example.com",
    ));
    assert!(!certificate_covers_domain(
      &["*.example.com".into()],
      "example.com",
    ));
    assert!(!certificate_covers_domain(
      &["*.example.com".into()],
      ".example.com",
    ));
  }
}
