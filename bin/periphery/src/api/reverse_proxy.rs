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

static PROXY_RECONCILIATION: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

impl Resolve<Args> for EnsureReverseProxy {
  async fn resolve(
    self,
    _: &Args,
  ) -> anyhow::Result<komodo_client::entities::update::Log> {
    #[cfg(not(unix))]
    bail!("The managed reverse proxy requires a Unix Periphery host");

    #[cfg(unix)]
    {
      let _guard = PROXY_RECONCILIATION.lock().await;
      validate_server_id(&self.server_id)?;
      let _guard = PROXY_RECONCILIATION.lock().await;
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
      ensure_proxy_container(
        &self.server_id,
        &root,
        &dynamic_directory,
        &certificate_mounts,
        &self.config,
        dynamic.as_bytes(),
        &proxy_image()?,
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

fn proxy_image() -> anyhow::Result<String> {
  match std::env::var("PERIPHERY_REVERSE_PROXY_IMAGE") {
    Ok(image) if !image.trim().is_empty() => Ok(image),
    Ok(_) => bail!("PERIPHERY_REVERSE_PROXY_IMAGE cannot be empty"),
    Err(std::env::VarError::NotPresent) => {
      Ok(format!("komodo-proxy:{}", env!("CARGO_PKG_VERSION")))
    }
    Err(error) => Err(error).context("Invalid proxy image setting"),
  }
}

async fn ensure_proxy_container(
  server_id: &str,
  root: &Path,
  dynamic_directory: &Path,
  certificate_mounts: &[(String, PathBuf)],
  config: &ReverseProxyConfig,
  dynamic: &[u8],
  image: &str,
) -> anyhow::Result<komodo_client::entities::update::Log> {
  let port_state = root.join("ports");
  let mut desired_ports = format!(
    "pingora\n{image}\n{}:8080\n{}:8443\n",
    config.http_port, config.https_port
  );
  for (id, _) in certificate_mounts {
    desired_ports.push_str(id);
    desired_ports.push('\n');
  }
  let container_name = format!("komodo-proxy-{server_id}");
  let backup_name = format!("{container_name}-rollback");
  let routes_path = dynamic_directory.join("routes.json");
  let rollback_path = root.join("rollback-routes.json");
  let rollback_ports = root.join("rollback-ports");
  let committed_path = root.join("replacement-committed");
  if docker_container_exists(&backup_name).await? {
    if fs::try_exists(&committed_path).await? {
      run_docker(["rm", &backup_name]).await?;
    } else {
      // Recover a replacement interrupted before it was committed.
      let previous = fs::read(&rollback_path)
        .await
        .context("Failed to read proxy rollback configuration")?;
      let ports = fs::read(&rollback_ports)
        .await
        .context("Failed to read proxy rollback container state")?;
      if docker_container_exists(&container_name).await? {
        run_docker(["rm", "-f", &container_name]).await?;
      }
      atomic_write(&routes_path, &previous, 0o644).await?;
      atomic_write(&port_state, &ports, 0o644).await?;
      run_docker(["rename", &backup_name, &container_name]).await?;
      run_docker(["start", &container_name]).await?;
    }
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
  let exists = docker_container_exists(&container_name).await?;
  let previous = match fs::read(&routes_path).await {
    Ok(previous) => Some(previous),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      None
    }
    Err(error) => {
      return Err(error)
        .context("Failed to read existing proxy routes");
    }
  };
  let same_container =
    exists && existing_ports.as_deref() == Some(&desired_ports);
  if same_container && previous.as_deref() == Some(dynamic) {
    run_docker(["start", &container_name]).await?;
    check_proxy(&container_name).await?;
    return Ok(komodo_client::entities::update::Log::simple(
      "Ensure Reverse Proxy",
      "Managed reverse proxy is running; route updates are watched automatically.".into(),
    ));
  }

  let candidate = root.join("candidate");
  secure_directory(&candidate).await?;
  atomic_write(&candidate.join("routes.json"), dynamic, 0o644)
    .await?;
  let mut preflight = vec!["run".to_string(), "--rm".to_string()];
  preflight
    .extend(proxy_mount_arguments(&candidate, certificate_mounts)?);
  preflight.push(image.to_string());
  preflight.push("--check".to_string());
  run_docker(preflight).await.context(
    "Replacement proxy image/configuration failed preflight; active proxy unchanged",
  )?;

  if same_container {
    atomic_write(&routes_path, dynamic, 0o644).await?;
    let result = async {
      run_docker(["start", &container_name]).await?;
      check_proxy(&container_name).await
    }
    .await;
    if let Err(error) = result {
      if let Some(previous) = previous {
        atomic_write(&routes_path, &previous, 0o644)
          .await
          .context("Failed to restore previous proxy routes")?;
      }
      return Err(error);
    }
    return Ok(komodo_client::entities::update::Log::simple(
      "Ensure Reverse Proxy",
      "Managed proxy routes updated.".into(),
    ));
  }

  let runtime_mounts =
    proxy_mount_arguments(dynamic_directory, certificate_mounts)?;
  if exists {
    let previous = previous.as_deref().context(
      "Cannot replace active proxy without its rollback configuration",
    )?;
    atomic_write(&rollback_path, previous, 0o644).await?;
    let ports = existing_ports.as_deref().context(
      "Cannot replace active proxy without its container state",
    )?;
    atomic_write(&rollback_ports, ports.as_bytes(), 0o644).await?;
    match fs::remove_file(&committed_path).await {
      Ok(()) => {}
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(error) => {
        return Err(error)
          .context("Failed to reset replacement commit marker");
      }
    }
    run_docker(["stop", &container_name]).await?;
    if let Err(error) =
      run_docker(["rename", &container_name, &backup_name]).await
    {
      run_docker(["start", &container_name]).await.context(
        "Failed to restart proxy after unsuccessful backup rename",
      )?;
      return Err(error);
    }
  }
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
  ];
  arguments.extend(runtime_mounts);
  arguments.push(image.to_string());
  let replacement = async {
    atomic_write(&routes_path, dynamic, 0o644).await?;
    run_docker(arguments)
      .await
      .context("Failed to start managed reverse proxy container")?;
    check_proxy(&container_name).await?;
    atomic_write(&port_state, desired_ports.as_bytes(), 0o644)
      .await?;
    if exists {
      atomic_write(&committed_path, b"committed", 0o644).await?;
    }
    anyhow::Ok(())
  }
  .await;
  if let Err(error) = replacement {
    let rollback = async {
      if docker_container_exists(&container_name).await? {
        run_docker(["rm", "-f", &container_name]).await?;
      }
      if let Some(previous) = previous {
        atomic_write(&routes_path, &previous, 0o644).await?;
      }
      if exists {
        let ports = existing_ports
          .as_deref()
          .context("Missing rollback state")?;
        atomic_write(&port_state, ports.as_bytes(), 0o644).await?;
        run_docker(["rename", &backup_name, &container_name]).await?;
        run_docker(["start", &container_name]).await?;
      }
      anyhow::Ok(())
    }
    .await;
    return match rollback {
      Ok(()) => Err(error).context("Proxy replacement failed; previous container restored"),
      Err(rollback_error) => Err(error).context(format!(
        "Proxy replacement also failed to roll back: {rollback_error:#}"
      )),
    };
  }
  if exists {
    run_docker(["rm", &backup_name]).await.context(
      "Replacement is healthy but retired proxy cleanup failed",
    )?;
  }
  Ok(komodo_client::entities::update::Log::simple(
    "Ensure Reverse Proxy",
    "Managed reverse proxy container started.".into(),
  ))
}

fn proxy_mount_arguments(
  directory: &Path,
  certificates: &[(String, PathBuf)],
) -> anyhow::Result<Vec<String>> {
  let directory = path_arg(directory)?;
  let mut arguments = vec![
    "--read-only".into(),
    "--cap-drop=ALL".into(),
    "--security-opt=no-new-privileges".into(),
    "--volume".into(),
    format!("{directory}:/etc/komodo-proxy:ro"),
  ];
  for (id, source) in certificates {
    let source = path_arg(source)?;
    arguments.push("--volume".into());
    arguments.push(format!("{source}:/certificates/{id}:ro"));
  }
  Ok(arguments)
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
  for name in [&container_name, &format!("{container_name}-rollback")]
  {
    if docker_container_exists(name).await? {
      run_docker(["rm", "-f", name]).await.context(
        "Failed to remove managed reverse proxy container",
      )?;
    }
  }
  Ok(komodo_client::entities::update::Log::simple(
    "Remove Reverse Proxy",
    "Managed reverse proxy is stopped.".into(),
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

  #[cfg(unix)]
  #[tokio::test]
  #[ignore = "requires Unix Docker and the locally built komodo-proxy:0.0.0 image"]
  async fn preserves_active_proxy_on_preflight_and_startup_failure() {
    let id = format!("test-{}", uuid::Uuid::new_v4().simple());
    let root = std::env::temp_dir().join(&id);
    let dynamic_directory = root.join("dynamic");
    secure_directory(&dynamic_directory).await.unwrap();
    let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let https = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = ReverseProxyConfig {
      enabled: true,
      http_port: http.local_addr().unwrap().port(),
      https_port: https.local_addr().unwrap().port(),
      routes: vec![route("app.example.com", "localhost:9", false)],
    };
    drop((http, https));
    let (dynamic, mounts) =
      generate_dynamic_config(&config).await.unwrap();
    let name = format!("komodo-proxy-{id}");
    let result: anyhow::Result<()> = async {
      ensure_proxy_container(
        &id,
        &root,
        &dynamic_directory,
        &mounts,
        &config,
        dynamic.as_bytes(),
        "komodo-proxy:0.0.0",
      )
      .await?;
      let old = Command::new("docker")
        .args(["inspect", "--format", "{{.Id}}", &name])
        .output()
        .await?;
      let failure = ensure_proxy_container(
        &id,
        &root,
        &dynamic_directory,
        &mounts,
        &config,
        dynamic.as_bytes(),
        "INVALID",
      )
      .await;
      assert!(failure.is_err());
      check_proxy(&name).await?;
      assert!(
        ensure_proxy_container(
          &id,
          &root,
          &dynamic_directory,
          &mounts,
          &config,
          b"{invalid",
          "komodo-proxy:0.0.0",
        )
        .await
        .is_err()
      );
      check_proxy(&name).await?;
      let occupied = std::net::TcpListener::bind("0.0.0.0:0")?;
      let mut replacement = config.clone();
      replacement.https_port = occupied.local_addr()?.port();
      let (replacement_dynamic, mounts) =
        generate_dynamic_config(&replacement).await?;
      assert!(
        ensure_proxy_container(
          &id,
          &root,
          &dynamic_directory,
          &mounts,
          &replacement,
          replacement_dynamic.as_bytes(),
          "komodo-proxy:0.0.0",
        )
        .await
        .is_err()
      );
      check_proxy(&name).await?;
      let restored = Command::new("docker")
        .args(["inspect", "--format", "{{.Id}}", &name])
        .output()
        .await?;
      assert_eq!(old.stdout, restored.stdout);
      assert_eq!(
        fs::read(dynamic_directory.join("routes.json")).await?,
        dynamic.as_bytes()
      );
      Ok(())
    }
    .await;
    let cleanup = remove_proxy(&id).await;
    fs::remove_dir_all(&root).await.unwrap();
    cleanup.unwrap();
    result.unwrap();
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
