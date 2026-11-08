use std::str::FromStr;

use anyhow::Context;
use database::mungos::mongodb::{
  Collection,
  bson::{doc, oid::ObjectId},
};
use indexmap::IndexSet;
use komodo_client::entities::{
  Operation, ResourceTarget, ResourceTargetVariant, komodo_timestamp,
  optional_string,
  permission::SpecificPermission,
  resource::Resource,
  server::{
    PartialServerConfig, ReverseProxyConfig, ReverseProxyTlsMode,
    Server, ServerConfig, ServerConfigDiff, ServerInfo,
    ServerListItem, ServerListItemInfo, ServerQuerySpecifics,
  },
  update::Update,
  user::User,
};
use periphery_client::api;
use periphery_client::api::reverse_proxy::{
  EnsureReverseProxy, RemoveReverseProxy,
};

use crate::{
  config::core_config,
  helpers::periphery_client,
  monitor::refresh_server_cache,
  state::{
    action_states, db_client, periphery_connections,
    server_status_cache,
  },
};

impl super::KomodoResource for Server {
  type Config = ServerConfig;
  type PartialConfig = PartialServerConfig;
  type ConfigDiff = ServerConfigDiff;
  type Info = ServerInfo;
  type ListItem = ServerListItem;
  type QuerySpecifics = ServerQuerySpecifics;

  fn resource_type() -> ResourceTargetVariant {
    ResourceTargetVariant::Server
  }

  fn resource_target(id: impl Into<String>) -> ResourceTarget {
    ResourceTarget::Server(id.into())
  }

  fn creator_specific_permissions() -> IndexSet<SpecificPermission> {
    [
      SpecificPermission::Terminal,
      SpecificPermission::Inspect,
      SpecificPermission::Attach,
      SpecificPermission::Logs,
      SpecificPermission::Processes,
    ]
    .into_iter()
    .collect()
  }

  fn coll() -> &'static Collection<Resource<Self::Config, Self::Info>>
  {
    &db_client().servers
  }

  async fn to_list_item(
    server: Resource<Self::Config, Self::Info>,
  ) -> Self::ListItem {
    let status = server_status_cache().get(&server.id).await;
    let (periphery_info, system_info, system_stats) = status
      .as_ref()
      .map(|s| {
        (
          s.periphery_info.as_ref(),
          s.system_info.as_ref(),
          s.system_stats.as_ref(),
        )
      })
      .unwrap_or_default();
    let (
      version,
      public_key,
      public_ip,
      terminals_disabled,
      container_terminals_disabled,
    ) = match periphery_info {
      Some(info) => (
        Some(info.version.clone()),
        Some(info.public_key.clone()),
        info.public_ip.clone(),
        info.terminals_disabled,
        info.container_terminals_disabled,
      ),
      None => (None, None, None, true, true),
    };
    ServerListItem {
      name: server.name,
      id: server.id,
      template: server.template,
      tags: server.tags,
      resource_type: ResourceTargetVariant::Server,
      info: ServerListItemInfo {
        state: status.as_ref().map(|s| s.state).unwrap_or_default(),
        err: status.as_ref().and_then(|s| s.err.clone()),
        stats: system_stats.map(Into::into),
        alerting_thresholds: (&server.config).into(),
        core_count: system_info.and_then(|i| i.core_count),
        logical_core_count: system_info
          .and_then(|i| i.logical_core_count),
        region: server.config.region,
        address: optional_string(server.config.address),
        external_address: optional_string(
          server.config.external_address,
        ),
        send_unreachable_alerts: server
          .config
          .send_unreachable_alerts,
        send_cpu_alerts: server.config.send_cpu_alerts,
        send_mem_alerts: server.config.send_mem_alerts,
        send_disk_alerts: server.config.send_disk_alerts,
        send_version_mismatch_alerts: server
          .config
          .send_version_mismatch_alerts,
        version,
        public_key,
        attempted_public_key: optional_string(
          server.info.attempted_public_key,
        ),
        public_ip,
        terminals_disabled,
        container_terminals_disabled,
      },
    }
  }

  async fn busy(id: &String) -> anyhow::Result<bool> {
    action_states()
      .server
      .get(id)
      .await
      .unwrap_or_default()
      .busy()
  }

  // CREATE

  fn create_operation() -> Operation {
    Operation::CreateServer
  }

  fn user_can_create(user: &User) -> bool {
    user.admin
      || (!core_config().disable_non_admin_create
        && user.create_server_permissions)
  }

  async fn validate_create_config(
    config: &mut Self::PartialConfig,
    user: &User,
  ) -> anyhow::Result<()> {
    validate_reverse_proxy(config.reverse_proxy.as_mut(), "", user)
      .await
  }

  async fn post_create(
    created: &Resource<Self::Config, Self::Info>,
    _update: &mut Update,
  ) -> anyhow::Result<()> {
    refresh_server_cache(created, true).await;
    if created.config.reverse_proxy.enabled {
      reconcile_reverse_proxy(created, false).await?;
    }
    Ok(())
  }

  // UPDATE

  fn update_operation() -> Operation {
    Operation::UpdateServer
  }

  async fn validate_update_config(
    id: &str,
    config: &mut Self::PartialConfig,
    user: &User,
  ) -> anyhow::Result<()> {
    validate_reverse_proxy(config.reverse_proxy.as_mut(), id, user)
      .await
  }

  async fn post_update(
    updated: &Self,
    update: &mut Update,
  ) -> anyhow::Result<()> {
    refresh_server_cache(updated, true).await;
    let proxy_was_enabled =
      previous_reverse_proxy_enabled(&update.prev_toml)?;
    if updated.config.reverse_proxy.enabled || proxy_was_enabled {
      reconcile_reverse_proxy(updated, proxy_was_enabled).await?;
    }
    Ok(())
  }

  // RENAME

  fn rename_operation() -> Operation {
    Operation::RenameServer
  }

  // DELETE

  fn delete_operation() -> Operation {
    Operation::DeleteServer
  }

  async fn pre_delete(
    resource: &Resource<Self::Config, Self::Info>,
    _update: &mut Update,
  ) -> anyhow::Result<()> {
    if db_client()
      .certificates
      .find_one(doc! { "config.server_id": &resource.id })
      .await
      .context("Failed to check Server Certificates")?
      .is_some()
    {
      anyhow::bail!(
        "Delete this Server's Certificates before deleting the Server."
      );
    }
    if resource.config.reverse_proxy.enabled
      || resource.info.reverse_proxy_managed
    {
      periphery_client(resource)
        .await?
        .request(RemoveReverseProxy {
          server_id: resource.id.clone(),
        })
        .await
        .context("Failed to remove managed reverse proxy")?;
    }
    let db = db_client();

    let id = &resource.id;

    db.builders
      .update_many(
        doc! { "config.params.server_id": &id },
        doc! { "$set": { "config.params.server_id": "" } },
      )
      .await
      .context("failed to detach server from builders")?;

    db.deployments
      .update_many(
        doc! { "config.server_id": &id },
        doc! { "$set": { "config.server_id": "" } },
      )
      .await
      .context("failed to detach server from deployments")?;

    db.stacks
      .update_many(
        doc! { "config.server_id": &id },
        doc! { "$set": { "config.server_id": "" } },
      )
      .await
      .context("failed to detach server from stacks")?;

    db.repos
      .update_many(
        doc! { "config.server_id": &id },
        doc! { "$set": { "config.server_id": "" } },
      )
      .await
      .context("failed to detach server from repos")?;

    db.alerts
      .update_many(
        doc! { "target.type": "Server", "target.id": &id },
        doc! { "$set": {
          "resolved": true,
          "resolved_ts": komodo_timestamp()
        } },
      )
      .await
      .context("failed to close deleted server alerts")?;

    let _ = db_client()
      .onboarding_keys
      .update_many(
        doc! { "onboarded": &id },
        doc! { "$pull": { "onboarded": &id } },
      )
      .await;

    let _ = db_client()
      .onboarding_keys
      .update_many(
        doc! { "copy_server": &id },
        doc! { "$set": { "copy_server": "" } },
      )
      .await;

    Ok(())
  }

  async fn post_delete(
    resource: &Resource<Self::Config, Self::Info>,
    _update: &mut Update,
  ) -> anyhow::Result<()> {
    tokio::join!(
      server_status_cache().remove(&resource.id),
      periphery_connections().remove(&resource.id),
    );
    Ok(())
  }
}

async fn reconcile_reverse_proxy(
  server: &Server,
  previously_enabled: bool,
) -> anyhow::Result<()> {
  if server.config.reverse_proxy.enabled || previously_enabled {
    db_client()
      .servers
      .update_one(
        doc! { "_id": ObjectId::from_str(&server.id)? },
        doc! { "$set": { "info.reverse_proxy_managed": true } },
      )
      .await
      .context("Failed to persist proxy reconciliation intent")?;
  }
  let periphery = periphery_client(server).await?;
  if server.config.reverse_proxy.enabled {
    periphery
      .request(EnsureReverseProxy {
        server_id: server.id.clone(),
        config: server.config.reverse_proxy.clone(),
      })
      .await
      .context("Failed to reconcile managed reverse proxy")?;
  } else {
    periphery
      .request(RemoveReverseProxy {
        server_id: server.id.clone(),
      })
      .await
      .context("Failed to remove managed reverse proxy")?;
    db_client()
      .servers
      .update_one(
        doc! { "_id": ObjectId::from_str(&server.id)? },
        doc! { "$set": { "info.reverse_proxy_managed": false } },
      )
      .await
      .context("Failed to acknowledge proxy removal")?;
  }
  Ok(())
}

pub(super) async fn reconcile_reverse_proxies() {
  let _guard = super::CERTIFICATE_LIFECYCLE.lock().await;
  let servers = match database::mungos::find::find_collect(
    &db_client().servers,
    doc! { "$or": [
      { "config.reverse_proxy.enabled": true },
      { "info.reverse_proxy_managed": true }
    ] },
    None,
  )
  .await
  {
    Ok(servers) => servers,
    Err(error) => {
      error!(
        "Failed to load Servers for proxy reconciliation | {error:#}"
      );
      return;
    }
  };
  for server in servers {
    if let Err(error) = reconcile_reverse_proxy(&server, false).await
    {
      error!(
        "Managed proxy reconciliation failed | {} | {error:#}",
        server.name
      );
    }
  }
}

fn previous_reverse_proxy_enabled(
  previous_toml: &str,
) -> anyhow::Result<bool> {
  if previous_toml.is_empty() {
    return Ok(false);
  }
  let document = toml::from_str::<toml::Value>(previous_toml)
    .context("Failed to parse previous Server configuration")?;
  Ok(
    document
      .get("server")
      .and_then(toml::Value::as_array)
      .and_then(|servers| servers.first())
      .and_then(|server| server.get("config"))
      .and_then(|config| config.get("reverse_proxy"))
      .and_then(|proxy| proxy.get("enabled"))
      .and_then(toml::Value::as_bool)
      .unwrap_or(false),
  )
}

#[cfg(test)]
mod tests {
  use super::previous_reverse_proxy_enabled;

  #[test]
  fn detects_whether_proxy_was_enabled_before_update() {
    assert!(
      previous_reverse_proxy_enabled(
        r#"
[[server]]
name = "prod"
[server.config.reverse_proxy]
enabled = true
"#,
      )
      .unwrap()
    );
    assert!(
      !previous_reverse_proxy_enabled(
        r#"
[[server]]
name = "prod"
[server.config]
address = "https://periphery.example.com"
"#,
      )
      .unwrap()
    );
  }
}

async fn validate_reverse_proxy(
  config: Option<&mut ReverseProxyConfig>,
  server_id: &str,
  user: &User,
) -> anyhow::Result<()> {
  let Some(config) = config else {
    return Ok(());
  };
  if config.http_port == 0 || config.https_port == 0 {
    anyhow::bail!("Reverse proxy listener ports must be nonzero.");
  }
  if config.http_port == config.https_port {
    anyhow::bail!(
      "Reverse proxy HTTP and HTTPS listener ports must be different."
    );
  }

  let mut domains = std::collections::HashSet::new();
  for route in &mut config.routes {
    route.domain = route.domain.trim().to_ascii_lowercase();
    if route.domain.starts_with("*.")
      || !super::certificate::valid_domain(&route.domain)
    {
      anyhow::bail!(
        "Reverse proxy route domains must be valid, non-wildcard DNS names."
      );
    }
    if !domains.insert(route.domain.clone()) {
      anyhow::bail!("Reverse proxy route domains must be unique.");
    }
    route.upstream = route.upstream.trim().to_string();
    match &mut route.tls {
      ReverseProxyTlsMode::Terminate { certificate_id } => {
        validate_http_proxy_upstream(&route.upstream)?;
        if server_id.is_empty() {
          anyhow::bail!(
            "Create the Server first, then attach certificates to its proxy routes."
          );
        }
        *certificate_id = super::certificate::validate_attachment(
          certificate_id,
          server_id,
          user,
        )
        .await?;
        let certificate = super::get::<
          komodo_client::entities::certificate::Certificate,
        >(certificate_id)
        .await?;
        if certificate.info.status
          != komodo_client::entities::certificate::CertificateStatus::Ready
        {
          anyhow::bail!(
            "Reverse proxy routes can only use Ready Certificates."
          );
        }
        if !super::certificate::certificate_covers_domain(
          &certificate.config.domains,
          &route.domain,
        ) {
          anyhow::bail!(
            "Certificate '{}' does not cover proxy route domain '{}'.",
            certificate.name,
            route.domain
          );
        }
      }
      ReverseProxyTlsMode::Passthrough => {
        validate_tcp_proxy_upstream(&route.upstream)?;
      }
    }
  }
  Ok(())
}

fn validate_http_proxy_upstream(
  upstream: &str,
) -> anyhow::Result<()> {
  komodo_proxy_config::http_upstream(upstream).map(|_| ())
}

fn validate_tcp_proxy_upstream(upstream: &str) -> anyhow::Result<()> {
  komodo_proxy_config::tcp_upstream(upstream).map(|_| ())
}

pub async fn update_server_public_key(
  server_id: &str,
  public_key: &str,
) -> anyhow::Result<()> {
  db_client()
    .servers
    .update_one(
      doc! { "_id": ObjectId::from_str(server_id)? },
      doc! { "$set": { "info.public_key": public_key } },
    )
    .await
    .context("Failed to update Server public key on database")?;
  Ok(())
}

/// Rotates Periphery keys and updates
/// `server.info.public_key` to match new public key.
/// Does so without making a specific update.
pub async fn rotate_server_keys(
  server: &Server,
) -> anyhow::Result<()> {
  let periphery = periphery_client(server).await?;
  let public_key = periphery
    .request(api::keys::RotatePrivateKey {})
    .await
    .context("Failed to rotate Periphery private key")?
    .public_key;
  update_server_public_key(&server.id, &public_key).await?;
  Ok(())
}
