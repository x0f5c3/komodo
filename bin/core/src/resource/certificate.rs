use std::{collections::HashMap, sync::{Arc, OnceLock}};

use anyhow::{Context, anyhow};
use database::mungos::{
  find::find_collect,
  mongodb::{Collection, bson::doc},
};
use indexmap::IndexSet;
use komodo_client::entities::{
  Operation, ResourceTarget, ResourceTargetVariant,
  certificate::{
    Certificate, CertificateConfig, CertificateConfigDiff,
    CertificateInfo, CertificateListItem, CertificateListItemInfo,
    CertificateQuerySpecifics, CertificateProvider,
    PartialCertificateConfig,
  },
  deployment::{Deployment, DeploymentState},
  permission::{PermissionLevel, SpecificPermission},
  resource::Resource,
  server::Server,
  stack::Stack,
  update::Update,
  user::User,
};

use crate::{
  helpers::periphery_client,
  permission::get_check_permissions,
  resource,
  state::{db_client, deployment_status_cache},
};

impl super::KomodoResource for Certificate {
  type Config = CertificateConfig;
  type PartialConfig = PartialCertificateConfig;
  type ConfigDiff = CertificateConfigDiff;
  type Info = CertificateInfo;
  type ListItem = CertificateListItem;
  type QuerySpecifics = CertificateQuerySpecifics;

  fn resource_type() -> ResourceTargetVariant {
    ResourceTargetVariant::Certificate
  }

  fn resource_target(id: impl Into<String>) -> ResourceTarget {
    ResourceTarget::Certificate(id.into())
  }

  fn coll() -> &'static Collection<Resource<Self::Config, Self::Info>> {
    &db_client().certificates
  }

  async fn to_list_item(
    certificate: Resource<Self::Config, Self::Info>,
  ) -> Self::ListItem {
    let server_name = resource::get::<Server>(&certificate.config.server_id)
      .await
      .map(|server| server.name)
      .unwrap_or_default();
    CertificateListItem {
      name: certificate.name,
      id: certificate.id,
      template: certificate.template,
      tags: certificate.tags,
      resource_type: ResourceTargetVariant::Certificate,
      info: CertificateListItemInfo {
        server_id: certificate.config.server_id,
        server_name,
        provider: certificate.config.provider,
        domains: certificate.config.domains,
        last_issued: certificate.info.last_issued,
        expires_at: certificate.info.expires_at,
        status: certificate.info.status,
      },
    }
  }

  async fn busy(_: &String) -> anyhow::Result<bool> {
    Ok(false)
  }

  fn creator_specific_permissions() -> IndexSet<SpecificPermission> {
    [SpecificPermission::Attach].into_iter().collect()
  }

  fn create_operation() -> Operation {
    Operation::CreateCertificate
  }

  fn user_can_create(user: &User) -> bool {
    user.admin || !crate::config::core_config().disable_non_admin_create
  }

  async fn validate_create_config(
    config: &mut Self::PartialConfig,
    user: &User,
  ) -> anyhow::Result<()> {
    validate_certificate_config(config, user, true, None).await
  }

  async fn post_create(
    created: &Resource<Self::Config, Self::Info>,
    update: &mut Update,
  ) -> anyhow::Result<()> {
    match ensure_certificate(created, false).await {
      Ok(changed) => update.push_simple_log(
        "Certificate issuance",
        if changed {
          "A new certificate version was installed on the host."
        } else {
          "The active certificate remains valid."
        },
      ),
      Err(error) => update.push_error_log(
        "Certificate issuance",
        format!("Certificate issuance will be retried: {error:#}"),
      ),
    }
    if let Err(error) = reconcile_proxy_for_server(&created.config.server_id).await {
      update.push_error_log(
        "Certificate proxy",
        format!("Proxy reconciliation will be retried: {error:#}"),
      );
    }
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
    let existing = resource::get::<Certificate>(id).await?;
    validate_certificate_config(config, user, false, Some(&existing.config))
      .await?;
    if config.server_id.is_none()
      && config.domains.is_none()
      && config.provider.is_none()
    {
      return Ok(());
    }
    let server_id = config
      .server_id
      .as_deref()
      .unwrap_or(&existing.config.server_id)
      .to_string();
    if let Some(server) = config.server_id.as_deref()
      && server != existing.config.server_id
    {
      return Err(anyhow!(
        "Certificate host changes require a new Certificate resource"
      ));
    }
    if !server_id.is_empty() {
      verify_unix_server(&server_id).await?;
    }
    Ok(())
  }

  async fn post_update(
    updated: &Self,
    update: &mut Update,
  ) -> anyhow::Result<()> {
    match ensure_certificate(updated, false).await {
      Ok(changed) => update.push_simple_log(
        "Certificate issuance",
        if changed {
          "A new certificate version was installed on the host."
        } else {
          "The active certificate remains valid."
        },
      ),
      Err(error) => update.push_error_log(
        "Certificate issuance",
        format!("Certificate issuance will be retried: {error:#}"),
      ),
    }
    if let Err(error) =
      reconcile_proxy_for_server(&updated.config.server_id).await
    {
      update.push_error_log(
        "Certificate proxy",
        format!("Proxy reconciliation will be retried: {error:#}"),
      );
    }
    Ok(())
  }

  fn rename_operation() -> Operation {
    Operation::RenameCertificate
  }

  fn delete_operation() -> Operation {
    Operation::DeleteCertificate
  }

  async fn pre_delete(
    certificate: &Resource<Self::Config, Self::Info>,
    _: &mut Update,
  ) -> anyhow::Result<()> {
    let deployments =
      resource::list_all_resources::<Deployment>(None, None, None).await?;
    if deployments.iter().any(|deployment| {
      deployment
        .config
        .certificate_mounts
        .iter()
        .any(|mount| mount.certificate == certificate.id)
    }) {
      return Err(anyhow!(
        "Cannot delete a certificate attached to a Deployment"
      ));
    }
    let stacks = resource::list_all_resources::<Stack>(None, None, None).await?;
    if stacks.iter().any(|stack| {
      stack
        .config
        .certificate_mounts
        .iter()
        .any(|mount| mount.certificate == certificate.id)
    }) {
      return Err(anyhow!(
        "Cannot delete a certificate attached to a Stack"
      ));
    }
    Ok(())
  }

  async fn post_delete(
    certificate: &Resource<Self::Config, Self::Info>,
    update: &mut Update,
  ) -> anyhow::Result<()> {
    if let Ok(server) = resource::get::<Server>(&certificate.config.server_id).await
      && let Ok(client) = periphery_client(&server).await
      && let Err(error) = client
        .request(periphery_client::api::DeleteCertificate {
          id: certificate.id.clone(),
        })
        .await
    {
      update.push_error_log(
        "Remove host certificate",
        format!("Failed to remove host certificate data: {error:#}"),
      );
    }
    if let Err(error) =
      reconcile_proxy_for_server(&certificate.config.server_id).await
    {
      update.push_error_log(
        "Certificate proxy",
        format!("Proxy reconciliation will be retried: {error:#}"),
      );
    }
    Ok(())
  }
}

async fn validate_certificate_config(
  config: &mut PartialCertificateConfig,
  user: &User,
  require_server: bool,
  existing: Option<&CertificateConfig>,
) -> anyhow::Result<()> {
  if let Some(server_id) = &config.server_id
    && !server_id.is_empty()
  {
    let server = get_check_permissions::<Server>(
      server_id,
      user,
      PermissionLevel::Read.attach(),
    )
    .await
    .context("Cannot attach Certificate to this Server")?;
    config.server_id = Some(server.id);
  }
  let server_id = config
    .server_id
    .as_deref()
    .or_else(|| existing.map(|config| config.server_id.as_str()))
    .unwrap_or_default();
  if require_server && server_id.is_empty() {
    return Err(anyhow!("A Server must be selected for a Certificate"));
  }
  if require_server
    && config
      .domains
      .as_ref()
      .or_else(|| existing.map(|config| &config.domains))
      .is_none_or(Vec::is_empty)
  {
    return Err(anyhow!("At least one DNS name is required for a Certificate"));
  }
  if require_server && config.provider.is_none() {
    config.provider = Some(CertificateProvider::default());
  }
  if !server_id.is_empty() {
    verify_unix_server(server_id).await?;
  }

  if let Some(domains) = &mut config.domains {
    let mut normalized = Vec::new();
    for domain in domains.iter() {
      let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
      if !valid_certificate_domain(&domain) {
        return Err(anyhow!("Invalid certificate DNS name: {domain}"));
      }
      if !normalized.contains(&domain) {
        normalized.push(domain);
      }
    }
    *domains = normalized;
  }
  let domains = config
    .domains
    .clone()
    .or_else(|| existing.map(|config| config.domains.clone()));

  let provider = config
    .provider
    .or_else(|| existing.map(|config| config.provider))
    .unwrap_or_default();
  let cloudflare_secret = config
    .cloudflare_token_secret
    .as_deref()
    .or_else(|| existing.map(|config| config.cloudflare_token_secret.as_str()))
    .unwrap_or_default();
  let email = config
    .email
    .as_deref()
    .or_else(|| existing.map(|config| config.email.as_str()))
    .unwrap_or_default();
  if matches!(provider, CertificateProvider::CloudflareDns01) {
    if cloudflare_secret.trim().is_empty() {
      return Err(anyhow!(
        "Cloudflare DNS-01 requires a periphery-local cloudflare_token_secret name"
      ));
    }
    if email.trim().is_empty() {
      return Err(anyhow!("ACME email is required for Cloudflare issuance"));
    }
  }
  if matches!(provider, CertificateProvider::Tailscale)
    && domains.as_ref().is_some_and(|domains| {
      domains.iter().any(|domain| domain.starts_with("*."))
    })
  {
    return Err(anyhow!(
      "Tailscale certificates do not support wildcard DNS names"
    ));
  }

  if let Some(routes) = &mut config.proxy_routes {
    for route in routes.iter_mut() {
      route.domain = route.domain.trim().trim_end_matches('.').to_ascii_lowercase();
      if !valid_exact_domain(&route.domain) {
        return Err(anyhow!(
          "Proxy routes must use an exact DNS hostname; wildcards are not supported"
        ));
      }
      if !domains.as_ref().is_some_and(|domains| domains.iter().any(|domain| {
          domain == &route.domain
            || domain.strip_prefix("*.").is_some_and(|suffix| {
              route.domain.ends_with(&format!(".{suffix}"))
            })
        }))
      {
        return Err(anyhow!(
          "Proxy route domain {} is not covered by this certificate",
          route.domain
        ));
      }
      if !valid_proxy_upstream(&route.upstream) {
        return Err(anyhow!(
          "Proxy route upstream must be an HTTP(S) URL or host:port"
        ));
      }
    }
  }
  Ok(())
}

async fn verify_unix_server(server_id: &str) -> anyhow::Result<()> {
      let server = resource::get::<Server>(server_id).await?;
      let platform = periphery_client(&server)
        .await?
        .request(periphery_client::api::GetHostPlatform {})
        .await
        .context("Failed to query Periphery host platform")?;
      if platform != "unix" {
        return Err(anyhow!(
          "Certificates and managed mounts require a Unix Periphery host"
        ));
}
      Ok(())
    }

fn valid_proxy_upstream(upstream: &str) -> bool {
      if upstream.trim() != upstream || upstream.contains(['\r', '\n']) {
        return false;
      }
      if upstream.starts_with("http://") || upstream.starts_with("https://") {
        return url::Url::parse(upstream).is_ok_and(|url| {
          matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
        });
      }
      upstream
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
}

pub async fn ensure_certificate(
      certificate: &Certificate,
      force: bool,
    ) -> anyhow::Result<bool> {
      let lock = certificate_lock(&certificate.id).await;
      let _lock = lock.lock().await;
      let server = resource::get::<Server>(&certificate.config.server_id).await?;
      let result = periphery_client(&server)
        .await?
        .request(periphery_client::api::EnsureCertificate {
          id: certificate.id.clone(),
          config: certificate.config.clone(),
          force,
        })
        .await
        .context("Periphery certificate issuance failed")?;

      let mut info = certificate.info.clone();
      if result.changed {
        info.last_issued = std::time::SystemTime::now()
          .duration_since(std::time::UNIX_EPOCH)
          .unwrap_or_default()
          .as_secs() as i64;
        info.status = "Restart pending".to_string();
        info.expires_at = result.expires_at;
        resource::update_info::<Certificate>(&certificate.id, &info).await?;
      }

      if result.changed || info.status == "Restart pending" {
        restart_certificate_workloads(certificate).await?;
        info.status = "Ready".to_string();
        resource::update_info::<Certificate>(&certificate.id, &info).await?;
      } else if info.status.is_empty() {
        info.status = "Ready".to_string();
        resource::update_info::<Certificate>(&certificate.id, &info).await?;
      }
      reconcile_proxy_for_server(&certificate.config.server_id).await?;
      Ok(result.changed)
}

async fn restart_certificate_workloads(
      certificate: &Certificate,
    ) -> anyhow::Result<()> {
      let server = resource::get::<Server>(&certificate.config.server_id).await?;
      let client = periphery_client(&server).await?;
      let deployments =
        find_collect(&db_client().deployments, None, None).await?;
      for deployment in deployments.into_iter().filter(|deployment| {
        deployment.config.server_id == certificate.config.server_id
          && deployment
            .config
            .certificate_mounts
            .iter()
            .any(|mount| mount.certificate == certificate.id)
      }) {
        let state = deployment_status_cache()
          .get(&deployment.id)
          .await
          .map(|status| status.curr.state)
          .unwrap_or_default();
        if matches!(state, DeploymentState::NotDeployed | DeploymentState::Unknown) {
          continue;
        }
        client
          .request(periphery_client::api::container::RestartContainer {
            name: deployment.deployed_name().to_string(),
          })
          .await
          .with_context(|| {
            format!("Failed to restart Deployment {}", deployment.name)
          })?;
      }

      let stacks = find_collect(&db_client().stacks, None, None).await?;
      for stack in stacks.into_iter().filter(|stack| {
        stack.config.server_id == certificate.config.server_id
          && stack
            .config
            .certificate_mounts
            .iter()
            .any(|mount| mount.certificate == certificate.id)
      }) {
        if !stack.info.deployed_services.as_ref().is_some_and(|services| {
          !services.is_empty()
        }) {
          continue;
        }
        let services = stack
          .config
          .certificate_mounts
          .iter()
          .filter(|mount| mount.certificate == certificate.id)
          .map(|mount| mount.service.clone())
          .collect::<std::collections::HashSet<_>>();
        if !services.is_empty() {
          let services = services
            .iter()
            .map(|service| service.clone())
            .collect::<Vec<_>>()
            .join(" ");
          client
            .request(periphery_client::api::compose::ComposeExecution {
              project: stack.project_name(false),
              command: format!("restart -- {services}"),
            })
            .await
            .with_context(|| format!("Failed to restart Stack {}", stack.name))?;
        }
      }
      Ok(())
}

pub async fn reconcile_proxy_for_server(
      server_id: &str,
    ) -> anyhow::Result<()> {
      let server = resource::get::<Server>(server_id).await?;
      let certificates = find_collect(
        &db_client().certificates,
        doc! { "config.server_id": server_id },
        None,
      )
      .await
      .context("Failed to list certificates for proxy reconciliation")?;
      let routes = certificates
        .iter()
        .flat_map(|certificate| {
          certificate
            .config
            .proxy_routes
            .iter()
            .map(|route| periphery_client::api::ManagedProxyRoute {
              certificate_id: certificate.id.clone(),
              domain: route.domain.clone(),
              upstream: route.upstream.clone(),
              tls_mode: route.tls_mode,
              redirect_http_to_https: route.redirect_http_to_https,
            })
            .collect::<Vec<_>>()
        })
        .collect();
      periphery_client(&server)
        .await?
        .request(periphery_client::api::ReconcileCertificateProxy {
          routes,
          listener: "0.0.0.0:443".to_string(),
          image: "ghcr.io/moghtech/komodo-pingora:2".to_string(),
        })
        .await
        .context("Failed to reconcile managed Pingora proxy")?;
      Ok(())
}

pub fn spawn_certificate_renewal_loop() {
      tokio::spawn(async {
        let mut interval =
          tokio::time::interval(std::time::Duration::from_secs(6 * 60 * 60));
        loop {
          interval.tick().await;
          let Ok(certificates) =
            resource::list_all_resources::<Certificate>(None, None, None).await
          else {
            error!("Failed to list Certificates during renewal");
            continue;
          };
          for certificate in certificates {
            if let Err(error) = ensure_certificate(&certificate, false).await {
              warn!(
                certificate = certificate.name,
                "Certificate renewal check failed; it will be retried | {error:#}"
              );
            }

          }
        }
      });
}

async fn certificate_lock(
  id: &str,
) -> Arc<tokio::sync::Mutex<()>> {
  static LOCKS: OnceLock<
    tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
  > = OnceLock::new();
  LOCKS
    .get_or_init(Default::default)
    .lock()
    .await
    .entry(id.to_string())
    .or_default()
    .clone()
}

fn valid_certificate_domain(domain: &str) -> bool {
  let domain = domain.strip_prefix("*.").unwrap_or(domain);
  valid_exact_domain(domain)
}

fn valid_exact_domain(domain: &str) -> bool {
  domain.contains('.')
    && !domain.is_empty()
    && domain.len() <= 253
    && domain.split('.').all(|label| {
      !label.is_empty()
        && label.len() <= 63
        && label
          .as_bytes()
          .first()
          .is_some_and(u8::is_ascii_alphanumeric)
        && label
          .as_bytes()
          .last()
          .is_some_and(u8::is_ascii_alphanumeric)
        && label.bytes().all(|byte| {
          byte.is_ascii_alphanumeric() || byte == b'-'
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{valid_certificate_domain, valid_exact_domain, valid_proxy_upstream};

    #[test]
    fn certificate_domains_allow_only_a_leading_wildcard() {
      assert!(valid_certificate_domain("example.com"));
      assert!(valid_certificate_domain("*.example.com"));
      assert!(!valid_certificate_domain("api.*.example.com"));
      assert!(!valid_certificate_domain("*.example..com"));
      assert!(!valid_certificate_domain("localhost"));
    }

    #[test]
    fn proxy_routes_require_exact_dns_names() {
      assert!(valid_exact_domain("api.example.com"));
      assert!(!valid_exact_domain("*.example.com"));
      assert!(!valid_exact_domain("api.example.com."));
      assert!(!valid_exact_domain("bad_domain.example.com"));
    }

    #[test]
    fn proxy_upstreams_are_http_urls_or_host_port_pairs() {
      assert!(valid_proxy_upstream("http://127.0.0.1:8080"));
      assert!(valid_proxy_upstream("https://upstream.example.com/api"));
      assert!(valid_proxy_upstream("127.0.0.1:8080"));
      assert!(!valid_proxy_upstream("******upstream.example.com"));
      assert!(!valid_proxy_upstream("javascript:alert(1)"));
      assert!(!valid_proxy_upstream("http://upstream.example.com\n"));
    }
}
