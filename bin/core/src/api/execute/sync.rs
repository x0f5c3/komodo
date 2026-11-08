use std::{
  collections::{HashMap, HashSet},
  str::FromStr,
};

use anyhow::{Context, anyhow};
use database::mungos::{
  by_id::update_one_by_id,
  mongodb::bson::{doc, oid::ObjectId},
};
use formatting::{Color, colored, format_serror};
use komodo_client::{
  api::{execute::RunSync, write::RefreshResourceSyncPending},
  entities::{
    self, ResourceTargetVariant,
    action::Action,
    alerter::Alerter,
    build::Build,
    builder::Builder,
    certificate::Certificate,
    deployment::Deployment,
    komodo_timestamp,
    permission::PermissionLevel,
    procedure::Procedure,
    repo::Repo,
    server::Server,
    stack::Stack,
    swarm::Swarm,
    sync::ResourceSync,
    update::{Log, Update},
    user::sync_user,
  },
};
use mogh_resolver::Resolve;

use crate::{
  api::write::WriteArgs,
  helpers::{
    all_resources::AllResourcesById, query::get_id_to_tags,
    update::update_update,
  },
  permission::get_check_permissions,
  state::{action_states, db_client},
  sync::{
    ResourceSyncTrait, SyncDeltas, ToUpdateItem,
    deploy::{
      SyncDeployParams, build_deploy_cache, deploy_from_cache,
    },
    execute::{ExecuteResourceSync, get_updates_for_execution},
    remote::RemoteResources,
  },
};

use super::ExecuteArgs;

impl Resolve<ExecuteArgs> for RunSync {
  #[instrument(
    "RunSync",
    skip_all,
    fields(
      task_id = task_id.to_string(),
      operator = user.id,
      update_id = update.id,
      sync = self.sync,
      resource_type = format!("{:?}", self.resource_type),
      resources = format!("{:?}", self.resources),
    )
  )]
  async fn resolve(
    self,
    ExecuteArgs {
      user,
      update,
      task_id,
    }: &ExecuteArgs,
  ) -> mogh_error::Result<Update> {
    let RunSync {
      sync,
      resource_type: match_resource_type,
      resources: match_resources,
    } = self;
    let sync = get_check_permissions::<entities::sync::ResourceSync>(
      &sync,
      user,
      PermissionLevel::Execute.into(),
    )
    .await?;

    let repo = if !sync.config.files_on_host
      && !sync.config.linked_repo.is_empty()
    {
      crate::resource::get::<Repo>(&sync.config.linked_repo)
        .await?
        .into()
    } else {
      None
    };

    // get the action state for the sync (or insert default).
    let action_state =
      action_states().sync.get_or_insert_default(&sync.id).await;

    // This will set action state back to default when dropped.
    // Will also check to ensure sync not already busy before updating.
    let action_guard =
      action_state.update(|state| state.syncing = true)?;

    let mut update = update.clone();

    // Send update here for FE to recheck action state
    update_update(update.clone()).await?;

    let RemoteResources {
      resources,
      logs,
      hash,
      message,
      file_errors,
      ..
    } =
      crate::sync::remote::get_remote_resources(&sync, repo.as_ref())
        .await
        .context("failed to get remote resources")?;

    update.logs.extend(logs);
    update_update(update.clone()).await?;

    if !file_errors.is_empty() {
      return Err(
        anyhow!("Found file errors. Cannot execute sync.").into(),
      );
    }

    let resources = resources?;

    let id_to_tags = get_id_to_tags(None).await?;
    let all_resources = AllResourcesById::load().await?;
    // Convert all match_resources to names
    let match_resources = match_resources.map(|resources| {
      resources
        .into_iter()
        .filter_map(|name_or_id| {
          let Some(resource_type) = match_resource_type else {
            return Some(name_or_id);
          };
          macro_rules! resolve_id_to_name {
            ($(($Variant:ident, $field:ident)),* $(,)?) => {
              match ObjectId::from_str(&name_or_id) {
                Ok(_) => match resource_type {
                  $(
                    ResourceTargetVariant::$Variant => all_resources
                      .$field
                      .get(&name_or_id)
                      .map(|r| r.name.clone()),
                  )*
                  ResourceTargetVariant::System => None,
                },
                Err(_) => Some(name_or_id),
              }
            };
          }
          // New resource types need to be added here manually.
          resolve_id_to_name!(
            (Server, servers),
            (Swarm, swarms),
            (Stack, stacks),
            (Deployment, deployments),
            (Build, builds),
            (Repo, repos),
            (Procedure, procedures),
            (Action, actions),
            (ResourceSync, syncs),
            (Builder, builders),
            (Alerter, alerters),
            (Certificate, certificates),
          )
        })
        .collect::<Vec<_>>()
    });

    let deployments_by_name = all_resources
      .deployments
      .values()
      .filter(|deployment| {
        Deployment::include_resource(
          &deployment.name,
          &deployment.config,
          match_resource_type,
          match_resources.as_deref(),
          &deployment.tags,
          &id_to_tags,
          &sync.config.match_tags,
        )
      })
      .map(|deployment| (deployment.name.clone(), deployment.clone()))
      .collect::<HashMap<_, _>>();
    let stacks_by_name = all_resources
      .stacks
      .values()
      .filter(|stack| {
        Stack::include_resource(
          &stack.name,
          &stack.config,
          match_resource_type,
          match_resources.as_deref(),
          &stack.tags,
          &id_to_tags,
          &sync.config.match_tags,
        )
      })
      .map(|stack| (stack.name.clone(), stack.clone()))
      .collect::<HashMap<_, _>>();

    let deploy_cache = build_deploy_cache(SyncDeployParams {
      deployments: &resources.deployments,
      deployment_map: &deployments_by_name,
      stacks: &resources.stacks,
      stack_map: &stacks_by_name,
    })
    .await?;

    let delete = sync.config.managed || sync.config.delete;

    macro_rules! get_deltas {
      ($(($var:ident, $Type:ident, $field:ident)),* $(,)?) => {
        $(
          let $var = if sync.config.include_resources {
            get_updates_for_execution::<$Type>(
              resources.$field,
              delete,
              match_resource_type,
              match_resources.as_deref(),
              &id_to_tags,
              &sync.config.match_tags,
            )
            .await?
          } else {
            Default::default()
          };
        )*
      };
    }
    // New resource types need to be added here manually.
    get_deltas!(
      (server_deltas, Server, servers),
      (swarm_deltas, Swarm, swarms),
      (stack_deltas, Stack, stacks),
      (deployment_deltas, Deployment, deployments),
      (build_deltas, Build, builds),
      (repo_deltas, Repo, repos),
      (procedure_deltas, Procedure, procedures),
      (action_deltas, Action, actions),
      (builder_deltas, Builder, builders),
      (alerter_deltas, Alerter, alerters),
      (certificate_deltas, Certificate, certificates),
      (resource_sync_deltas, ResourceSync, resource_syncs),
    );

    let (
      variables_to_create,
      variables_to_update,
      variables_to_delete,
    ) = if match_resource_type.is_none()
      && match_resources.is_none()
      && sync.config.include_variables
    {
      crate::sync::variables::get_updates_for_execution(
        resources.variables,
        delete,
      )
      .await?
    } else {
      Default::default()
    };
    let (
      user_groups_to_create,
      user_groups_to_update,
      user_groups_to_delete,
    ) = if match_resource_type.is_none()
      && match_resources.is_none()
      && sync.config.include_user_groups
    {
      crate::sync::user_groups::get_updates_for_execution(
        resources.user_groups,
        delete,
      )
      .await?
    } else {
      Default::default()
    };

    // New resource types need to be added here manually.
    if deploy_cache.is_empty()
      && resource_sync_deltas.no_changes()
      && server_deltas.no_changes()
      && swarm_deltas.no_changes()
      && deployment_deltas.no_changes()
      && stack_deltas.no_changes()
      && build_deltas.no_changes()
      && builder_deltas.no_changes()
      && alerter_deltas.no_changes()
      && repo_deltas.no_changes()
      && certificate_deltas.no_changes()
      && procedure_deltas.no_changes()
      && action_deltas.no_changes()
      && user_groups_to_create.is_empty()
      && user_groups_to_update.is_empty()
      && user_groups_to_delete.is_empty()
      && variables_to_create.is_empty()
      && variables_to_update.is_empty()
      && variables_to_delete.is_empty()
    {
      update.push_simple_log(
        "No Changes",
        format!(
          "{}. exiting.",
          colored("nothing to do", Color::Green)
        ),
      );
      update.finalize();

      // Drop action guard before updating
      // clients to requery action state
      drop(action_guard);
      update_update(update.clone()).await?;
      return Ok(update);
    }

    // =====================================================
    // The ordering these are executed does matter, since
    // latter resources may depend on prior synced resources
    // already being updated with the declared state.
    // =====================================================

    // No deps
    maybe_extend(
      &mut update.logs,
      crate::sync::variables::run_updates(
        variables_to_create,
        variables_to_update,
        variables_to_delete,
      )
      .await,
    );
    maybe_extend(
      &mut update.logs,
      crate::sync::user_groups::run_updates(
        user_groups_to_create,
        user_groups_to_update,
        user_groups_to_delete,
      )
      .await,
    );

    let (server_deltas, mut server_proxy_deltas) =
      split_server_proxy_deltas(server_deltas);
    let mut server_deltas = server_deltas;
    let server_deletes = std::mem::take(&mut server_deltas.to_delete);
    maybe_extend(
      &mut update.logs,
      Server::execute_sync_updates(server_deltas).await,
    );

    let mut changed_certificate_refs = HashSet::new();
    for certificate in &certificate_deltas.to_create {
      changed_certificate_refs.insert(certificate.name.clone());
    }
    for certificate in &certificate_deltas.to_update {
      changed_certificate_refs.insert(certificate.id.clone());
      changed_certificate_refs
        .insert(certificate.resource.name.clone());
    }
    let certificate_deletes = certificate_deltas.to_delete;
    maybe_extend(
      &mut update.logs,
      Certificate::execute_sync_updates(SyncDeltas {
        to_create: certificate_deltas.to_create,
        to_update: certificate_deltas.to_update,
        to_delete: Vec::new(),
      })
      .await,
    );

    let replaced_or_deleted_servers = server_proxy_deltas
      .to_create
      .iter()
      .map(|(name, _)| name.clone())
      .chain(
        server_proxy_deltas
          .to_update
          .iter()
          .map(|update| update.resource.name.clone()),
      )
      .chain(server_deletes.iter().cloned())
      .collect::<HashSet<_>>();
    let mut route_certificate_refs = server_proxy_deltas
      .to_create
      .iter()
      .flat_map(|(_, config)| {
        enabled_terminating_certificate_refs(config)
      })
      .chain(server_proxy_deltas.to_update.iter().flat_map(
        |update| {
          update
            .resource
            .config
            .reverse_proxy
            .as_ref()
            .into_iter()
            .flat_map(enabled_terminating_certificate_refs)
        },
      ))
      .collect::<HashSet<_>>();
    route_certificate_refs.extend(
      all_resources
        .servers
        .values()
        .filter(|server| {
          !replaced_or_deleted_servers.contains(&server.name)
        })
        .flat_map(|server| {
          enabled_terminating_certificate_refs(
            &server.config.reverse_proxy,
          )
        })
        .filter(|certificate_ref| {
          changed_certificate_refs.contains(certificate_ref)
        }),
    );

    if !route_certificate_refs.is_empty() {
      let mut log = String::from("reconciling synced Certificates");
      let mut has_error = false;
      let mut reconciled = 0;
      for certificate_ref in route_certificate_refs {
        match crate::resource::get::<Certificate>(&certificate_ref)
          .await
        {
          Ok(certificate) => {
            if certificate.info.status
              != entities::certificate::CertificateStatus::Ready
              && let Err(error) =
                crate::resource::reconcile_certificate(
                  &certificate.id,
                )
                .await
            {
              has_error = true;
              log.push_str(&format!(
                "\n{}: failed to reconcile Certificate '{}' | {error:#}",
                colored("ERROR", Color::Red),
                certificate.name
              ));
            } else if certificate.info.status
              != entities::certificate::CertificateStatus::Ready
            {
              reconciled += 1;
            }
          }
          Err(error) => {
            has_error = true;
            log.push_str(&format!(
              "\n{}: failed to find route Certificate '{}' | {error:#}",
              colored("ERROR", Color::Red),
              certificate_ref
            ));
          }
        }
      }
      if has_error || reconciled > 0 {
        update.logs.push(if has_error {
          Log::error("Reconcile Synced Certificates", log)
        } else {
          Log::simple("Reconcile Synced Certificates", log)
        });
      }
    }

    // Apply proxy changes only after any referenced Certificates have had a
    // chance to become Ready. The Server exists by this point, so attachment
    // validation also works for a Server and Certificate declared together.
    for (name, proxy_config) in server_proxy_deltas.to_create {
      match crate::resource::get::<Server>(&name).await {
        Ok(server) => {
          server_proxy_deltas.to_update.push(ToUpdateItem {
            id: server.id,
            resource: komodo_client::entities::toml::ResourceToml {
              name,
              description: String::new(),
              template: false,
              tags: Vec::new(),
              deploy: false,
              after: Vec::new(),
              config:
                komodo_client::entities::server::PartialServerConfig {
                  reverse_proxy: Some(proxy_config),
                  ..Default::default()
                },
            },
            update_description: false,
            update_template: false,
            update_tags: false,
          });
        }
        Err(error) => update.logs.push(Log::error(
          "Update Server Proxy",
          format!(
            "{}: failed to find synced Server '{}' | {error:#}",
            colored("ERROR", Color::Red),
            name
          ),
        )),
      }
    }
    maybe_extend(
      &mut update.logs,
      Server::execute_sync_updates(SyncDeltas {
        to_update: server_proxy_deltas.to_update,
        ..Default::default()
      })
      .await,
    );

    maybe_extend(
      &mut update.logs,
      Alerter::execute_sync_updates(alerter_deltas).await,
    );
    maybe_extend(
      &mut update.logs,
      Action::execute_sync_updates(action_deltas).await,
    );

    // Depends on server
    maybe_extend(
      &mut update.logs,
      Swarm::execute_sync_updates(swarm_deltas).await,
    );
    // Depends on server
    maybe_extend(
      &mut update.logs,
      Builder::execute_sync_updates(builder_deltas).await,
    );
    // Depends on server / builder
    maybe_extend(
      &mut update.logs,
      Repo::execute_sync_updates(repo_deltas).await,
    );

    // Depends on builder / repo
    maybe_extend(
      &mut update.logs,
      Build::execute_sync_updates(build_deltas).await,
    );
    // Depends on server / repo
    maybe_extend(
      &mut update.logs,
      Stack::execute_sync_updates(stack_deltas).await,
    );
    // Depends on repo
    maybe_extend(
      &mut update.logs,
      ResourceSync::execute_sync_updates(resource_sync_deltas).await,
    );
    // Depends on server / build
    maybe_extend(
      &mut update.logs,
      Deployment::execute_sync_updates(deployment_deltas).await,
    );
    // Depends on everything
    // Remove Certificates only after routes and workload attachments detach.
    maybe_extend(
      &mut update.logs,
      Certificate::execute_sync_updates(SyncDeltas {
        to_delete: certificate_deletes,
        ..Default::default()
      })
      .await,
    );
    maybe_extend(
      &mut update.logs,
      Server::execute_sync_updates(SyncDeltas {
        to_delete: server_deletes,
        ..Default::default()
      })
      .await,
    );
    maybe_extend(
      &mut update.logs,
      Procedure::execute_sync_updates(procedure_deltas).await,
    );

    // Execute the deploy cache
    deploy_from_cache(deploy_cache, &mut update.logs).await;

    let db = db_client();

    if let Err(e) = update_one_by_id(
      &db.resource_syncs,
      &sync.id,
      doc! {
        "$set": {
          "info.last_sync_ts": komodo_timestamp(),
          "info.last_sync_hash": hash,
          "info.last_sync_message": message,
        }
      },
      None,
    )
    .await
    {
      warn!(
        "failed to update resource sync {} info after sync | {e:#}",
        sync.name
      )
    }

    if let Err(e) = (RefreshResourceSyncPending { sync: sync.id })
      .resolve(&WriteArgs {
        user: sync_user().to_owned(),
      })
      .await
    {
      warn!(
        "failed to refresh sync {} after run | {:#}",
        sync.name, e.error
      );
      update.push_error_log(
        "refresh sync",
        format_serror(
          &e.error
            .context("failed to refresh sync pending after run")
            .into(),
        ),
      );
    }

    update.finalize();

    // Drop action guard before updating
    // clients to requery action state
    drop(action_guard);
    update_update(update.clone()).await?;

    Ok(update)
  }
}

fn maybe_extend(logs: &mut Vec<Log>, log: Option<Log>) {
  if let Some(log) = log {
    logs.push(log);
  }
}

fn enabled_terminating_certificate_refs(
  config: &komodo_client::entities::server::ReverseProxyConfig,
) -> Vec<String> {
  if !config.enabled {
    return Vec::new();
  }
  config
    .routes
    .iter()
    .filter_map(|route| match &route.tls {
      komodo_client::entities::server::ReverseProxyTlsMode::Terminate {
        certificate_id,
      } => Some(certificate_id.clone()),
      komodo_client::entities::server::ReverseProxyTlsMode::Passthrough => {
        None
      }
    })
    .collect()
}

struct ServerProxyDeltas {
  to_create: Vec<(
    String,
    komodo_client::entities::server::ReverseProxyConfig,
  )>,
  to_update: Vec<
    ToUpdateItem<
      komodo_client::entities::server::PartialServerConfig,
    >,
  >,
}

fn split_server_proxy_deltas(
  SyncDeltas {
    to_create,
    to_update,
    to_delete,
  }: SyncDeltas<
    komodo_client::entities::server::PartialServerConfig,
  >,
) -> (
  SyncDeltas<komodo_client::entities::server::PartialServerConfig>,
  ServerProxyDeltas,
) {
  use komodo_client::entities::{
    server::{PartialServerConfig, ReverseProxyConfig},
    toml::ResourceToml,
  };

  let mut basic = SyncDeltas {
    to_create: Vec::with_capacity(to_create.len()),
    to_update: Vec::with_capacity(to_update.len()),
    to_delete,
  };
  let mut proxy = ServerProxyDeltas {
    to_create: Vec::new(),
    to_update: Vec::new(),
  };

  for mut resource in to_create {
    let proxy_config = resource.config.reverse_proxy.take();
    if let Some(proxy_config) = proxy_config
      && proxy_config != ReverseProxyConfig::default()
    {
      proxy.to_create.push((resource.name.clone(), proxy_config));
    }
    basic.to_create.push(resource);
  }

  for ToUpdateItem {
    id,
    mut resource,
    update_description,
    update_template,
    update_tags,
  } in to_update
  {
    let proxy_config = resource.config.reverse_proxy.take();
    if let Some(proxy_config) = proxy_config {
      let config = PartialServerConfig {
        reverse_proxy: Some(proxy_config),
        ..Default::default()
      };
      proxy.to_update.push(ToUpdateItem {
        id: id.clone(),
        resource: ResourceToml {
          name: resource.name.clone(),
          description: String::new(),
          template: false,
          tags: Vec::new(),
          deploy: false,
          after: Vec::new(),
          config,
        },
        update_description: false,
        update_template: false,
        update_tags: false,
      });
    }
    basic.to_update.push(ToUpdateItem {
      id,
      resource,
      update_description,
      update_template,
      update_tags,
    });
  }

  (basic, proxy)
}

#[cfg(test)]
mod tests {
  use super::*;
  use komodo_client::entities::{
    server::{
      PartialServerConfig, ReverseProxyConfig, ReverseProxyRoute,
      ReverseProxyTlsMode,
    },
    toml::ResourceToml,
  };

  #[test]
  fn splits_proxy_updates_without_dropping_server_config_or_routes() {
    let proxy_config = ReverseProxyConfig {
      enabled: true,
      http_port: 80,
      https_port: 443,
      routes: vec![ReverseProxyRoute {
        domain: "app.example.com".to_string(),
        upstream: "http://app:8080".to_string(),
        tls: ReverseProxyTlsMode::Terminate {
          certificate_id: "certificate-id".to_string(),
        },
      }],
    };
    let deltas = SyncDeltas {
      to_create: vec![ResourceToml {
        name: "new-server".to_string(),
        description: String::new(),
        template: false,
        tags: Vec::new(),
        deploy: false,
        after: Vec::new(),
        config: PartialServerConfig {
          address: Some("https://periphery.example.com".to_string()),
          reverse_proxy: Some(proxy_config.clone()),
          ..Default::default()
        },
      }],
      to_update: vec![ToUpdateItem {
        id: "server-id".to_string(),
        resource: ResourceToml {
          name: "existing-server".to_string(),
          description: String::new(),
          template: false,
          tags: Vec::new(),
          deploy: false,
          after: Vec::new(),
          config: PartialServerConfig {
            address: Some(
              "https://new-periphery.example.com".to_string(),
            ),
            reverse_proxy: Some(proxy_config.clone()),
            ..Default::default()
          },
        },
        update_description: false,
        update_template: false,
        update_tags: false,
      }],
      to_delete: Vec::new(),
    };

    let (basic, proxy) = split_server_proxy_deltas(deltas);

    assert_eq!(
      basic.to_create[0].config.address.as_deref(),
      Some("https://periphery.example.com")
    );
    assert!(basic.to_create[0].config.reverse_proxy.is_none());
    assert_eq!(
      basic.to_update[0].resource.config.address.as_deref(),
      Some("https://new-periphery.example.com")
    );
    assert!(
      basic.to_update[0].resource.config.reverse_proxy.is_none()
    );
    assert_eq!(proxy.to_create[0].0, "new-server");
    assert_eq!(proxy.to_create[0].1, proxy_config);
    assert_eq!(
      enabled_terminating_certificate_refs(&proxy.to_create[0].1),
      vec!["certificate-id"]
    );
    let mut disabled_proxy = proxy.to_create[0].1.clone();
    disabled_proxy.enabled = false;
    assert!(
      enabled_terminating_certificate_refs(&disabled_proxy)
        .is_empty()
    );
    assert_eq!(proxy.to_update[0].id, "server-id");
    assert_eq!(
      proxy.to_update[0]
        .resource
        .config
        .reverse_proxy
        .as_ref()
        .unwrap(),
      &proxy_config
    );
    assert!(proxy.to_update[0].resource.config.address.is_none());
  }
}
