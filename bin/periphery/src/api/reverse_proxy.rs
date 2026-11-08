use std::{
  path::{Path, PathBuf},
  process::Stdio,
};

use anyhow::{Context, anyhow, bail};
use komodo_client::entities::server::{
  ReverseProxyConfig, ReverseProxyTlsMode,
};
use komodo_proxy_config::{ProxyConfig, ProxyRoute};
use mogh_resolver::Resolve;
use periphery_client::api::reverse_proxy::{
  EnsureReverseProxy, RemoveReverseProxy,
};
use tokio::{fs, process::Command};

use crate::{api::Args, config::periphery_config};

impl Resolve<Args> for EnsureReverseProxy {
  async fn resolve(
    self,
    _: &Args,
  ) -> anyhow::Result<komodo_client::entities::update::Log> {
    #[cfg(not(unix))]
    bail!("The managed reverse proxy requires a Unix Periphery host");

    #[cfg(unix)]
    {
      validate_server_id(&self.server_id)?;
      validate_config(&self.config)?;
      if !self.config.enabled {
        return remove_proxy(&self.server_id).await;
      }

      let root = periphery_config()
        .root_directory
        .join("reverse-proxy")
        .join(&self.server_id);
      secure_directory(&root).await?;
      let dynamic_directory = root.join("dynamic");
      secure_directory(&dynamic_directory).await?;
      let (dynamic, certificate_mounts) =
        generate_dynamic_config(&self.config).await?;
      atomic_write(
        &dynamic_directory.join("routes.json"),
        dynamic.as_bytes(),
        0o644,
      )
      .await?;
      ensure_proxy_container(
        &self.server_id,
        &root,
        &dynamic_directory,
        &certificate_mounts,
        &self.config,
      )
      .await
    }
  }
}

impl Resolve<Args> for RemoveReverseProxy {
  async fn resolve(
    self,
    _: &Args,
  ) -> anyhow::Result<komodo_client::entities::update::Log> {
    validate_server_id(&self.server_id)?;
    remove_proxy(&self.server_id).await
  }
}

fn validate_server_id(id: &str) -> anyhow::Result<()> {
  if id.is_empty()
    || !id.bytes().all(|byte| {
      byte.is_ascii_alphanumeric() || b"-_".contains(&byte)
    })
  {
    bail!("Invalid Server id for managed reverse proxy");
  }
  Ok(())
}

fn validate_config(
  config: &ReverseProxyConfig,
) -> anyhow::Result<()> {
  if config.http_port == 0 || config.https_port == 0 {
    bail!("Proxy listener ports must be between 1 and 65535");
  }
  if config.http_port == config.https_port {
    bail!("Proxy HTTP and HTTPS listener ports must be different");
  }
  let mut domains = std::collections::HashSet::new();
  for route in &config.routes {
    komodo_proxy_config::validate_domain(&route.domain)?;
    if !domains.insert(route.domain.to_ascii_lowercase()) {
      bail!(
        "Proxy route domains must be unique, non-wildcard DNS names"
      );
    }
    match &route.tls {
      ReverseProxyTlsMode::Terminate { .. } => {
        validate_http_upstream(&route.upstream)?;
      }
      ReverseProxyTlsMode::Passthrough => {
        validate_tcp_upstream(&route.upstream)?;
      }
    }
  }
  Ok(())
}

fn validate_http_upstream(upstream: &str) -> anyhow::Result<()> {
  komodo_proxy_config::http_upstream(upstream).map(|_| ())
}

fn validate_tcp_upstream(upstream: &str) -> anyhow::Result<()> {
  komodo_proxy_config::tcp_upstream(upstream).map(|_| ())
}

async fn generate_dynamic_config(
  config: &ReverseProxyConfig,
) -> anyhow::Result<(String, Vec<(String, PathBuf)>)> {
  let mut routes = Vec::new();
  let mut certificate_mounts = std::collections::BTreeMap::new();

  for route in &config.routes {
    let certificate_directory = match &route.tls {
      ReverseProxyTlsMode::Terminate { certificate_id } => {
        let mount_source =
          crate::api::certificate::certificate_mount_source(
            certificate_id,
          )
          .await
          .with_context(|| {
            format!(
              "Certificate for route '{}' is not available",
              route.domain
            )
          })?;
        certificate_mounts
          .insert(certificate_id.clone(), mount_source);
        Some(PathBuf::from(format!("/certificates/{certificate_id}")))
      }
      ReverseProxyTlsMode::Passthrough => None,
    };
    routes.push(ProxyRoute {
      domain: route.domain.clone(),
      upstream: route.upstream.clone(),
      certificate_directory,
    });
  }

  let dynamic = ProxyConfig {
    https_port: config.https_port,
    routes,
  };
  dynamic.validate()?;
  let dynamic = serde_json::to_string_pretty(&dynamic)
    .context("Failed to serialize managed proxy configuration")?;
  Ok((dynamic, certificate_mounts.into_iter().collect()))
}

async fn ensure_proxy_container(
  server_id: &str,
  root: &Path,
  dynamic_directory: &Path,
  certificate_mounts: &[(String, PathBuf)],
  config: &ReverseProxyConfig,
) -> anyhow::Result<komodo_client::entities::update::Log> {
  let port_state = root.join("ports");
  let image = match std::env::var("PERIPHERY_REVERSE_PROXY_IMAGE") {
    Ok(image) if !image.trim().is_empty() => image,
    Ok(_) => bail!("PERIPHERY_REVERSE_PROXY_IMAGE cannot be empty"),
    Err(std::env::VarError::NotPresent) => {
      format!("komodo-proxy:{}", env!("CARGO_PKG_VERSION"))
    }
    Err(error) => {
      return Err(error).context("Invalid proxy image setting");
    }
  };
  let mut desired_ports = format!(
    "pingora\n{image}\n{}:8080\n{}:8443\n",
    config.http_port, config.https_port
  );
  for (id, _) in certificate_mounts {
    desired_ports.push_str(id);
    desired_ports.push('\n');
  }
  let existing_ports = match fs::read_to_string(&port_state).await {
    Ok(state) => Some(state),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      None
    }
    Err(error) => {
      return Err(error)
        .context("Failed to read proxy container state");
    }
  };
  let container_name = format!("komodo-proxy-{server_id}");
  let exists = docker_container_exists(&container_name).await?;
  if exists && existing_ports.as_deref() != Some(&desired_ports) {
    run_docker(["rm", "-f", &container_name]).await?;
  }
  if exists && existing_ports.as_deref() == Some(&desired_ports) {
    run_docker(["start", &container_name]).await?;
    check_proxy(&container_name).await?;
    return Ok(komodo_client::entities::update::Log::simple(
      "Ensure Reverse Proxy",
      "Managed reverse proxy is running; route updates are watched automatically.".into(),
    ));
  }

  let dynamic_directory = path_arg(dynamic_directory)?;
  let http_publish = format!("{}:8080", config.http_port);
  let https_publish = format!("{}:8443", config.https_port);
  let mut arguments = vec![
    "run".to_string(),
    "--detach".to_string(),
    "--name".to_string(),
    container_name.clone(),
    "--restart".to_string(),
    "unless-stopped".to_string(),
    "--label".to_string(),
    "komodo.skip=true".to_string(),
    "--read-only".to_string(),
    "--cap-drop=ALL".to_string(),
    "--security-opt=no-new-privileges".to_string(),
    "--health-cmd=proxy --health".to_string(),
    "--health-interval=2s".to_string(),
    "--health-timeout=3s".to_string(),
    "--health-retries=3".to_string(),
    "--add-host".to_string(),
    "host.docker.internal:host-gateway".to_string(),
    "--publish".to_string(),
    http_publish,
    "--publish".to_string(),
    https_publish,
    "--volume".to_string(),
    format!("{dynamic_directory}:/etc/komodo-proxy:ro"),
  ];
  for (id, source) in certificate_mounts {
    let source = path_arg(source)?;
    arguments.push("--volume".to_string());
    arguments.push(format!("{source}:/certificates/{id}:ro"));
  }
  arguments.push(image);
  run_docker(arguments)
    .await
    .context("Failed to start managed reverse proxy container")?;
  check_proxy(&container_name).await?;
  atomic_write(&root.join("ports"), desired_ports.as_bytes(), 0o644)
    .await?;
  Ok(komodo_client::entities::update::Log::simple(
    "Ensure Reverse Proxy",
    "Managed reverse proxy container started.".into(),
  ))
}

async fn check_proxy(name: &str) -> anyhow::Result<()> {
  run_docker(["exec", name, "proxy", "--check"])
    .await
    .context("Managed proxy rejected its routes or certificates")?;
  for _ in 0..15 {
    let output = Command::new("docker")
      .args(["inspect", "--format", "{{.State.Health.Status}}", name])
      .stdin(Stdio::null())
      .output()
      .await
      .context("Failed to inspect managed proxy health")?;
    if !output.status.success() {
      bail!(
        "Failed to inspect managed proxy health: {}",
        String::from_utf8_lossy(&output.stderr)
      );
    }
    if String::from_utf8_lossy(&output.stdout).trim() == "healthy" {
      return Ok(());
    }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
  }
  bail!(
    "Managed proxy did not become healthy; inspect Docker logs for {name}"
  );
}

async fn docker_container_exists(
  container_name: &str,
) -> anyhow::Result<bool> {
  let output = Command::new("docker")
    .args(["container", "inspect", &container_name])
    .stdin(Stdio::null())
    .output()
    .await
    .context("Failed to inspect managed reverse proxy container")?;
  if output.status.success() {
    Ok(true)
  } else if String::from_utf8_lossy(&output.stderr)
    .to_ascii_lowercase()
    .contains("no such object")
  {
    Ok(false)
  } else {
    Err(anyhow!(
      "Docker could not inspect the managed reverse proxy container: {}",
      String::from_utf8_lossy(&output.stderr).trim()
    ))
  }
}

async fn remove_proxy(
  server_id: &str,
) -> anyhow::Result<komodo_client::entities::update::Log> {
  let container_name = format!("komodo-proxy-{server_id}");
  let output = Command::new("docker")
    .args(["rm", "-f", &container_name])
    .stdin(Stdio::null())
    .output()
    .await
    .context("Failed to remove managed reverse proxy container")?;
  if output.status.success()
    || String::from_utf8_lossy(&output.stderr)
      .to_ascii_lowercase()
      .contains("no such container")
  {
    return Ok(komodo_client::entities::update::Log::simple(
      "Remove Reverse Proxy",
      "Managed reverse proxy is stopped.".into(),
    ));
  }
  Err(anyhow!(
    "Failed to remove managed reverse proxy: {}",
    String::from_utf8_lossy(&output.stderr).trim()
  ))
}

async fn run_docker<I, S>(args: I) -> anyhow::Result<()>
where
  I: IntoIterator<Item = S>,
  S: AsRef<std::ffi::OsStr>,
{
  let output = Command::new("docker")
    .args(args)
    .stdin(Stdio::null())
    .output()
    .await
    .context("Failed to start Docker command")?;
  if !output.status.success() {
    let mut details =
      String::from_utf8_lossy(&output.stderr).to_string();
    details.truncate(4_000);
    bail!("Docker command failed: {}", details.trim());
  }
  Ok(())
}

fn path_arg(path: &Path) -> anyhow::Result<String> {
  let path = path
    .to_str()
    .context("Docker bind mount path is not valid UTF-8")?;
  if path.contains(':') || path.contains(',') {
    bail!("Docker bind mount path cannot contain commas or colons");
  }
  Ok(path.to_string())
}

async fn secure_directory(path: &Path) -> anyhow::Result<()> {
  fs::create_dir_all(path).await.with_context(|| {
    format!("Failed to create {}", path.display())
  })?;
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
      .await
      .with_context(|| {
        format!("Failed to secure {}", path.display())
      })?;
  }
  Ok(())
}

async fn atomic_write(
  path: &Path,
  contents: &[u8],
  mode: u32,
) -> anyhow::Result<()> {
  let temp = PathBuf::from(format!(
    "{}.{}.tmp",
    path.display(),
    uuid::Uuid::new_v4().simple()
  ));
  fs::write(&temp, contents)
    .await
    .with_context(|| format!("Failed to write {}", temp.display()))?;
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))
      .await
      .with_context(|| {
        format!("Failed to secure {}", temp.display())
      })?;
  }
  if let Err(error) = fs::rename(&temp, path).await {
    let _ = fs::remove_file(&temp).await;
    return Err(error).with_context(|| {
      format!("Failed to activate {}", path.display())
    });
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rejects_duplicate_domains_and_invalid_upstreams() {
    let duplicate_domains = ReverseProxyConfig {
      enabled: true,
      http_port: 80,
      https_port: 443,
      routes: vec![
        route("app.example.com", "http://upstream:3000", true),
        route("APP.example.com", "host:8443", false),
      ],
    };
    assert!(validate_config(&duplicate_domains).is_err());
    assert!(validate_http_upstream("ftp://upstream:3000").is_err());
    assert!(validate_tcp_upstream("upstream").is_err());
  }

  #[tokio::test]
  async fn generates_tls_passthrough_router_configuration() {
    let config = ReverseProxyConfig {
      enabled: true,
      http_port: 80,
      https_port: 443,
      routes: vec![route(
        "db.example.com",
        "database.internal:5432",
        false,
      )],
    };
    let (dynamic, mounts) =
      generate_dynamic_config(&config).await.unwrap();
    let parsed: ProxyConfig = serde_json::from_str(&dynamic).unwrap();
    assert_eq!(parsed.routes[0].domain, "db.example.com");
    assert_eq!(parsed.routes[0].upstream, "database.internal:5432");
    assert!(parsed.routes[0].certificate_directory.is_none());
    assert!(mounts.is_empty());
  }

  fn route(
    domain: &str,
    upstream: &str,
    terminate: bool,
  ) -> komodo_client::entities::server::ReverseProxyRoute {
    use komodo_client::entities::server::{
      ReverseProxyRoute, ReverseProxyTlsMode,
    };
    ReverseProxyRoute {
      domain: domain.to_string(),
      upstream: upstream.to_string(),
      tls: if terminate {
        ReverseProxyTlsMode::Terminate {
          certificate_id: "certificate".to_string(),
        }
      } else {
        ReverseProxyTlsMode::Passthrough
      },
    }
  }
}
