use std::{
  collections::HashSet,
  fs,
  io::ErrorKind,
  os::unix::fs::{PermissionsExt, symlink},
  path::{Path, PathBuf},
  process::Stdio,
  sync::OnceLock,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow};
use komodo_client::entities::{
  certificate::{CertificateProvider, CertificateTlsMode},
  update::Log,
};
use mogh_resolver::Resolve;
use periphery_client::api::{
  DeleteCertificate, EnsureCertificate, GetHostPlatform,
  ManagedProxyRoute, ReconcileCertificateProxy,
};
use tokio::process::Command;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

use crate::config::periphery_config;

impl Resolve<crate::api::Args> for GetHostPlatform {
  async fn resolve(
    self,
    _: &crate::api::Args,
  ) -> anyhow::Result<String> {
    Ok(std::env::consts::FAMILY.to_string())
  }
}

impl Resolve<crate::api::Args> for EnsureCertificate {
  #[instrument("EnsureCertificate", skip_all, fields(id = self.id))]
  async fn resolve(
    self,
    _: &crate::api::Args,
  ) -> anyhow::Result<periphery_client::api::CertificateIssueResult> {
    if !cfg!(unix) {
      return Err(anyhow!(
        "Certificate issuance and mounts require a Unix Periphery host"
      ));
    }

    validate_id(&self.id)?;
    if self.config.domains.is_empty() {
      return Err(anyhow!("At least one certificate domain is required"));
    }

    let root = periphery_config().root_directory.clone();
    let cert_root = root.join("certificates").join(&self.id);
    let versions = cert_root.join("versions");
    let current = cert_root.join("current");
    let certbot_root = root.join("certbot");
    fs::create_dir_all(&versions).context("Failed to prepare certificate storage")?;
    let identity_path = cert_root.join("issuance.json");
    let identity = CertificateIssuanceIdentity::from(&self.config);
    let previous_identity = fs::read(&identity_path)
      .ok()
      .and_then(|bytes| serde_json::from_slice::<CertificateIssuanceIdentity>(&bytes).ok());
    let identity_changed = previous_identity.as_ref() != Some(&identity);

    if !self.force && !identity_changed && current.join("fullchain.pem").is_file() {
      let output = Command::new("openssl")
        .args([
          "x509",
          "-in",
          current.join("fullchain.pem").to_string_lossy().as_ref(),
          "-noout",
          "-checkend",
          "2592000",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("Could not check the active certificate expiry")?;
      if output.success() {
        return Ok(Default::default());
      }
    }

    let version = format!(
      "{}-{}",
      SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs(),
      Uuid::new_v4()
    );
    let staging = versions.join(format!(".staging-{version}"));
    fs::create_dir(&staging).context("Failed to prepare certificate staging directory")?;

    let result = async {
      match self.config.provider {
        CertificateProvider::CloudflareDns01 => {
          let token = periphery_config()
            .secrets
            .get(&self.config.cloudflare_token_secret)
            .filter(|token| !token.is_empty())
            .context("Cloudflare token is not configured in Periphery secrets")?;
          if token.contains(['\r', '\n']) {
            return Err(anyhow!(
              "Periphery Cloudflare token contains invalid line breaks"
            ));
          }
          let credentials_dir = root.join("certbot-cloudflare");
          fs::create_dir_all(&credentials_dir)
            .context("Failed to prepare host-local Cloudflare credentials")?;
          set_mode(&credentials_dir, 0o700)?;
          let credentials = credentials_dir.join(format!("{}.ini", self.id));
          fs::write(
            &credentials,
            format!("dns_cloudflare_api_token = {token}\n"),
          )
          .context("Failed to write host-local Cloudflare credentials")?;
          set_mode(&credentials, 0o600)?;

          let cert_name = format!("komodo-{}", self.id);
          let live = certbot_root.join("live").join(&cert_name);
          let mut command = Command::new("certbot");
          command
            .arg(if live.exists() && !identity_changed && !self.force {
              "renew"
            } else {
              "certonly"
            })
            .arg("--non-interactive")
            .arg("--config-dir")
            .arg(&certbot_root)
            .arg("--work-dir")
            .arg(root.join("certbot-work"))
            .arg("--logs-dir")
            .arg(root.join("certbot-logs"))
            .arg("--cert-name")
            .arg(&cert_name);
          if !live.exists() || identity_changed || self.force {
            command
              .arg("--agree-tos")
              .arg("--email")
              .arg(&self.config.email)
              .arg("--authenticator")
              .arg("dns-cloudflare")
              .arg("--dns-cloudflare-credentials")
              .arg(&credentials)
              .arg("--dns-cloudflare-propagation-seconds")
              .arg("30")
              .arg("--force-renewal");
            if identity_changed {
              command.arg("--expand");
            }
            for domain in &self.config.domains {
              command.arg("--domain").arg(domain);
            }
          }
          run_secret_safe(command, "Certbot certificate renewal").await?;
          fs::copy(live.join("fullchain.pem"), staging.join("fullchain.pem"))
            .context("Certbot did not produce a full chain")?;
          fs::copy(live.join("privkey.pem"), staging.join("privkey.pem"))
            .context("Certbot did not produce a private key")?;
          copy_if_present(&live.join("cert.pem"), &staging.join("cert.pem"))?;
          copy_if_present(&live.join("chain.pem"), &staging.join("chain.pem"))?;
        }
        CertificateProvider::Tailscale => {
          let cert_name = if self.config.tailscale_cert_name.is_empty() {
            &self.config.domains[0]
          } else {
            &self.config.tailscale_cert_name
          };
          let cert = staging.join("fullchain.pem");
          let key = staging.join("privkey.pem");
          let mut command = Command::new("tailscale");
          command
            .arg("cert")
            .arg("--cert-file")
            .arg(&cert)
            .arg("--key-file")
            .arg(&key)
            .arg(cert_name);
          run_secret_safe(command, "Tailscale certificate retrieval").await?;
          fs::copy(&cert, staging.join("cert.pem"))
            .context("Tailscale did not produce a certificate")?;
        }
      }

      let fullchain = fs::read(staging.join("fullchain.pem"))
        .context("Failed to read issued certificate")?;
      let private_key = fs::read(staging.join("privkey.pem"))
        .context("Failed to read issued private key")?;
      if fullchain.is_empty() || private_key.is_empty() {
        return Err(anyhow!("Certificate provider produced empty certificate files"));
      }

      if current.join("fullchain.pem").is_file()
        && current.join("privkey.pem").is_file()
        && fs::read(current.join("fullchain.pem"))? == fullchain
        && fs::read(current.join("privkey.pem"))? == private_key
      {
        fs::remove_dir_all(&staging)?;
        fs::write(&identity_path, serde_json::to_vec(&identity)?)
          .context("Failed to save certificate issuance metadata")?;
        set_mode(&identity_path, 0o600)?;
        return Ok(periphery_client::api::CertificateIssueResult::default());
      }

      set_mode(&staging, 0o750)?;
      set_mode(&staging.join("fullchain.pem"), 0o644)?;
      set_mode(&staging.join("privkey.pem"), 0o600)?;
      for filename in ["cert.pem", "chain.pem"] {
        let path = staging.join(filename);
        if path.exists() {
          set_mode(&path, 0o644)?;
        }
      }
      let installed = versions.join(&version);
      fs::rename(&staging, &installed)
        .context("Failed to install immutable certificate version")?;

      let next_link = cert_root.join(format!(".current-{version}"));
      symlink(PathBuf::from("versions").join(&version), &next_link)
        .context("Failed to prepare active certificate pointer")?;
      fs::rename(&next_link, &current)
        .context("Failed to atomically activate certificate version")?;
      fs::write(&identity_path, serde_json::to_vec(&identity)?)
        .context("Failed to save certificate issuance metadata")?;
      set_mode(&identity_path, 0o600)?;

      Ok(periphery_client::api::CertificateIssueResult {
        changed: true,
        expires_at: 0,
      })
    }
    .await;

    if result.is_err() && staging.exists() {
      let _ = fs::remove_dir_all(&staging);
    }
    result
  }
}

impl Resolve<crate::api::Args> for DeleteCertificate {
  async fn resolve(
    self,
    _: &crate::api::Args,
  ) -> anyhow::Result<()> {
    validate_id(&self.id)?;
    let root = periphery_config().root_directory.clone();
    let cert_root = root.join("certificates").join(&self.id);
    let credentials = root
      .join("certbot-cloudflare")
      .join(format!("{}.ini", self.id));
    let mut certbot_delete = Command::new("certbot");
    certbot_delete
      .arg("delete")
      .arg("--non-interactive")
      .arg("--cert-name")
      .arg(format!("komodo-{}", self.id))
      .arg("--config-dir")
      .arg(root.join("certbot"))
      .arg("--work-dir")
      .arg(root.join("certbot-work"))
      .arg("--logs-dir")
      .arg(root.join("certbot-logs"));
    let _ = run_secret_safe(certbot_delete, "Certbot certificate removal").await;
    match fs::remove_file(credentials) {
      Ok(()) => {}
      Err(error) if error.kind() == ErrorKind::NotFound => {}
      Err(error) => return Err(error.into()),
    }
    match fs::remove_dir_all(cert_root) {
      Ok(()) => {}
      Err(error) if error.kind() == ErrorKind::NotFound => {}
      Err(error) => return Err(error.into()),
    }
    Ok(())
  }
}

impl Resolve<crate::api::Args> for ReconcileCertificateProxy {
  #[instrument("ReconcileCertificateProxy", skip_all)]
  async fn resolve(
    self,
    _: &crate::api::Args,
  ) -> anyhow::Result<Log> {
    validate_proxy_config(&self.routes, &self.listener, &self.image)?;
    reconcile_managed_proxy(self).await
  }
}

fn validate_proxy_config(
  routes: &[ManagedProxyRoute],
  listener: &str,
  image: &str,
) -> anyhow::Result<()> {
  if !cfg!(unix) {
    return Err(anyhow!("The managed proxy requires a Unix host"));
  }
  if listener.is_empty() || image.is_empty() {
    return Err(anyhow!("Proxy listener and image are required"));
  }
  let mut domains = HashSet::new();
  for route in routes {
    if route.domain.contains('*')
      || route.domain.is_empty()
      || !domains.insert(route.domain.to_ascii_lowercase())
    {
      return Err(anyhow!("Proxy route domains must be unique exact hostnames"));
    }
    if route.upstream.trim().is_empty()
      || route.upstream.contains(['\r', '\n'])
      || route.upstream.contains('@')
    {
      return Err(anyhow!("Proxy route upstream must not be empty"));
    }
    if matches!(route.tls_mode, CertificateTlsMode::Terminate) {
      let certificate_dir = certificate_mount_dir(&route.certificate_id)?;
      if !certificate_dir.join("current/fullchain.pem").is_file()
        || !certificate_dir.join("current/privkey.pem").is_file()
      {
        return Err(anyhow!(
          "Proxy route {} has no active Certificate",
          route.domain
        ));
      }
    }
    if matches!(route.tls_mode, CertificateTlsMode::SniPassthrough)
      && route.redirect_http_to_https
    {
      return Err(anyhow!(
        "HTTP redirects cannot be applied to an SNI passthrough route"
      ));
    }
  }
  Ok(())
}

async fn reconcile_managed_proxy(
  request: ReconcileCertificateProxy,
) -> anyhow::Result<Log> {
  static RECONCILE_LOCK: OnceLock<tokio::sync::Mutex<()>> =
    OnceLock::new();
  let _lock = RECONCILE_LOCK
    .get_or_init(Default::default)
    .lock()
    .await;
  let root = periphery_config().root_directory.join("pingora");
  fs::create_dir_all(&root)
    .context("Failed to prepare managed Pingora configuration directory")?;
  let routes_path = root.join("routes.json");
  let state_path = root.join("state.json");
  let next_path = root.join("routes.next.json");
  let container_name = "komodo-managed-pingora";
  let mut mount_ids = request
    .routes
    .iter()
    .filter(|route| matches!(route.tls_mode, CertificateTlsMode::Terminate))
    .map(|route| route.certificate_id.clone())
    .collect::<Vec<_>>();
  mount_ids.sort();
  mount_ids.dedup();
  let state = serde_json::json!({
    "listener": request.listener,
    "image": request.image,
    "mounts": mount_ids,
  });

  if request.routes.is_empty() {
    remove_managed_proxy(container_name).await?;
    for path in [&routes_path, &state_path, &next_path] {
      match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
      }
    }
    return Ok(Log::simple(
      "Managed Pingora proxy",
      "Removed the managed proxy because there are no configured routes.".to_string(),
    ));
  }

  let config = serde_json::json!({
    "https_listener": request.listener,
    "http_listener": "0.0.0.0:80",
    "routes": request.routes.iter().map(|route| {
      serde_json::json!({
        "domain": route.domain,
        "upstream": route.upstream,
        "tls_mode": route.tls_mode,
        "redirect_http_to_https": route.redirect_http_to_https,
        "certificate_dir": format!("/run/komodo/certs/{}", route.certificate_id),
      })
    }).collect::<Vec<_>>(),
  });
  let config_bytes = serde_json::to_vec_pretty(&config)
    .context("Failed to serialize managed Pingora routes")?;
  let previous_config = fs::read(&routes_path).ok();
  let previous_state = fs::read(&state_path)
    .ok()
    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
  let is_running = managed_proxy_exists(container_name).await?;
  let recreate = !is_running || previous_state.as_ref() != Some(&state);
  if !recreate && previous_config.as_deref() == Some(config_bytes.as_slice()) {
    let _ = fs::remove_file(&next_path);
    return Ok(Log::simple(
      "Managed Pingora proxy",
      "Managed Pingora routes and listener configuration are already current."
        .to_string(),
    ));
  }

  fs::write(&next_path, &config_bytes)
    .context("Failed to write candidate Pingora routes")?;
  if recreate {
    remove_managed_proxy(container_name).await?;
    fs::rename(&next_path, &routes_path)
      .context("Failed to install Pingora routes")?;
    if let Err(error) = start_managed_proxy(
      container_name,
      &request.listener,
      &request.image,
      &routes_path,
      &mount_ids,
    )
    .await
    {
      if let Some(previous_config) = previous_config {
        let _ = write_atomic(&routes_path, &previous_config);
      }
      return Err(error);
    }
  } else {
    fs::rename(&next_path, &routes_path)
      .context("Failed to atomically install Pingora routes")?;
    if let Err(error) = docker_command([
      "kill",
      "--signal=HUP",
      container_name,
    ])
    .await
    {
      if let Some(previous_config) = previous_config {
        let _ = write_atomic(&routes_path, &previous_config);
        let _ = docker_command([
          "kill",
          "--signal=HUP",
          container_name,
        ])
        .await;
      }
      return Err(error).context("Pingora rejected the route reload");
    }
  }
  write_atomic(&state_path, &serde_json::to_vec(&state)?)?;
  Ok(Log::simple(
    "Managed Pingora proxy",
    if recreate {
      "Recreated the managed Pingora container for its listener, image, or certificate mount changes.".to_string()
    } else {
      "Reloaded exact-domain routes without recreating the managed Pingora container.".to_string()
    },
  ))
}

async fn managed_proxy_exists(name: &str) -> anyhow::Result<bool> {
  let output = Command::new("docker")
    .arg("container")
    .arg("inspect")
    .arg("--format")
    .arg("{{ index .Config.Labels \"komodo.managed\" }}")
    .arg(name)
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .output()
    .await
    .context("Failed to inspect the managed Pingora container")?;
  if !output.status.success() {
    return Ok(false);
  }
  let label = String::from_utf8_lossy(&output.stdout).trim().to_string();
  if label != "pingora" {
    return Err(anyhow!(
      "Container name {name} is already used by an unmanaged container"
    ));
  }
  Ok(true)
}

async fn remove_managed_proxy(name: &str) -> anyhow::Result<()> {
  if managed_proxy_exists(name).await? {
    docker_command(["rm", "-f", name])
      .await
      .context("Failed to remove old managed Pingora container")?;
  }
  Ok(())
}

async fn start_managed_proxy(
  name: &str,
  listener: &str,
  image: &str,
  routes_path: &Path,
  mount_ids: &[String],
) -> anyhow::Result<()> {
  let mut command = Command::new("docker");
  command
    .arg("run")
    .arg("--detach")
    .arg("--name")
    .arg(name)
    .arg("--restart")
    .arg("unless-stopped")
    .arg("--label")
    .arg("komodo.managed=pingora")
    .arg("--label")
    .arg("komodo.skip=true")
    .arg("--publish")
    .arg(format!("{listener}:443"))
    .arg("--publish")
    .arg("0.0.0.0:80:80")
    .arg("--mount")
    .arg(format!(
      "type=bind,source={},target=/etc/komodo-pingora/routes.json,readonly",
      routes_path.display()
    ));
  for id in mount_ids {
    let source = certificate_mount_dir(id)?;
    if source.to_string_lossy().contains(',') {
      return Err(anyhow!(
        "Periphery certificate path cannot contain commas for Docker mounts"
      ));
    }
    command
      .arg("--mount")
      .arg(format!(
        "type=bind,source={},target=/run/komodo/certs/{id},readonly",
        source.display()
      ));
  }
  command
    .arg(image)
    .arg("--config")
    .arg("/etc/komodo-pingora/routes.json");
  run_secret_safe(command, "Managed Pingora container start").await
}

async fn docker_command<const N: usize>(
  args: [&str; N],
) -> anyhow::Result<()> {
  let mut command = Command::new("docker");
  command.args(args);
  run_secret_safe(command, "Docker managed proxy operation").await
}

fn write_atomic(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
  let next = path.with_extension("next");
  fs::write(&next, contents)?;
  fs::rename(next, path)?;
  Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CertificateIssuanceIdentity {
  provider: CertificateProvider,
  domains: Vec<String>,
  email: String,
  cloudflare_token_secret: String,
  tailscale_cert_name: String,
}

impl From<&komodo_client::entities::certificate::CertificateConfig>
  for CertificateIssuanceIdentity
{
  fn from(
    config: &komodo_client::entities::certificate::CertificateConfig,
  ) -> Self {
    Self {
      provider: config.provider,
      domains: config.domains.clone(),
      email: config.email.clone(),
      cloudflare_token_secret: config.cloudflare_token_secret.clone(),
      tailscale_cert_name: config.tailscale_cert_name.clone(),
    }
  }
}

fn validate_id(id: &str) -> anyhow::Result<()> {
  if id.len() != 24 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    return Err(anyhow!("Invalid certificate id"));
  }
  Ok(())
}

pub(super) fn certificate_mount_dir(id: &str) -> anyhow::Result<PathBuf> {
  validate_id(id)?;
  Ok(
    periphery_config()
      .root_directory
      .join("certificates")
      .join(id),
  )
}

pub(super) fn validate_mount_target(target: &str) -> anyhow::Result<()> {
  let path = Path::new(target);
  if !path.is_absolute()
    || path.components().any(|component| {
      matches!(
        component,
        std::path::Component::ParentDir | std::path::Component::CurDir
      )
    })
    || path == Path::new("/")
  {
    return Err(anyhow!(
      "Certificate mount path must be a non-root absolute path without dot segments"
    ));
  }
  Ok(())
}

fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
  fs::set_permissions(path, fs::Permissions::from_mode(mode))
    .with_context(|| format!("Failed to set permissions on {path:?}"))
}

fn copy_if_present(source: &Path, target: &Path) -> anyhow::Result<()> {
  match fs::copy(source, target) {
    Ok(_) => Ok(()),
    Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
    Err(error) => Err(error.into()),
  }
}

async fn run_secret_safe(
  mut command: Command,
  operation: &str,
) -> anyhow::Result<()> {
  let status = command
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .await
    .with_context(|| format!("{operation} could not be started"))?;
  if !status.success() {
    return Err(anyhow!("{operation} failed with status {status}"));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::{validate_id, validate_mount_target};

  #[test]
  fn certificate_ids_are_safe_path_components() {
    assert!(validate_id("0123456789abcdef01234567").is_ok());
    assert!(validate_id("../etc/passwd").is_err());
    assert!(validate_id("0123456789abcdef0123456g").is_err());
  }

  #[test]
  fn certificate_mount_targets_are_absolute_and_confined() {
    assert!(validate_mount_target("/run/certs/site").is_ok());
    assert!(validate_mount_target("relative/cert").is_err());
    assert!(validate_mount_target("/").is_err());
    assert!(validate_mount_target("/run/../etc").is_err());
  }
}
