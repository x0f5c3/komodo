use std::{
  path::{Path, PathBuf},
  process::Stdio,
};

use anyhow::{Context, anyhow, bail};
use komodo_client::entities::certificate::CertificateIssuer;
use mogh_resolver::Resolve;
use periphery_client::api::certificate::{
  EnsureCertificate, EnsureCertificateResponse, RemoveCertificate,
};
use tokio::{fs, process::Command};

use crate::{api::Args, config::periphery_config};

const CERTBOT_IMAGE: &str = "certbot/dns-cloudflare:latest";
const RENEW_BEFORE_SECONDS: i64 = 30 * 24 * 60 * 60;

impl Resolve<Args> for EnsureCertificate {
  async fn resolve(
    self,
    _: &Args,
  ) -> anyhow::Result<EnsureCertificateResponse> {
    validate_id(&self.id)?;
    validate_domains(&self.domains)?;
    let directory = certificate_directory(&self.id).await?;
    ensure_certificate(self, directory).await
  }
}

async fn ensure_certificate(
  request: EnsureCertificate,
  directory: PathBuf,
) -> anyhow::Result<EnsureCertificateResponse> {
  let domains_match =
    certificate_domains_match(&directory, &request.domains).await?;
  let issuer_match =
    certificate_issuer_matches(&directory, &request.issuer).await?;

  if !request.force
    && domains_match
    && issuer_match
    && let Some(expires_at) =
      certificate_expiry(&directory.join("current/tls.crt")).await?
    && expires_at
      > chrono::Utc::now().timestamp() + RENEW_BEFORE_SECONDS
  {
    return Ok(EnsureCertificateResponse {
      expires_at,
      changed: false,
      revision: certificate_revision(&directory).await?,
    });
  }

  let staging = directory
    .join(format!("issued-{}", uuid::Uuid::new_v4().simple()));
  fs::create_dir(&staging)
    .await
    .context("Failed to create certificate staging directory")?;
  set_certificate_directory_permissions(&staging).await?;
  let issued = match &request.issuer {
    CertificateIssuer::AcmeCloudflare {
      api_token_secret: _,
      email,
    } => {
      let token = request
        .cloudflare_token
        .as_deref()
        .context("Cloudflare API token was not provided")?;
      issue_acme_certificate(
        &request.id,
        &request.domains,
        email,
        token,
        &staging,
        request.force || !domains_match || !issuer_match,
      )
      .await
    }
    CertificateIssuer::Tailscale => {
      if request.domains.len() != 1
        || request.domains[0].starts_with("*.")
      {
        bail!("Tailscale requires exactly one non-wildcard DNS name");
      }
      issue_tailscale_certificate(&request.domains[0], &staging).await
    }
  };
  if let Err(error) = issued {
    let _ = fs::remove_dir_all(&staging).await;
    return Err(error);
  }

  let expires_at = match certificate_expiry(&staging.join("tls.crt"))
    .await
  {
    Ok(Some(expires_at)) => expires_at,
    Ok(None) => {
      let _ = fs::remove_dir_all(&staging).await;
      bail!(
        "Certificate issuer completed without writing a valid certificate"
      );
    }
    Err(error) => {
      let _ = fs::remove_dir_all(&staging).await;
      return Err(error);
    }
  };
  let mut domains = request.domains;
  domains.sort();
  atomic_write(
    &staging.join("domains"),
    domains.join("\n").as_bytes(),
    0o644,
  )
  .await
  .context("Failed to persist certificate domain set")?;
  atomic_write(
    &staging.join("issuer"),
    &serde_json::to_vec(&request.issuer)?,
    0o644,
  )
  .await
  .context("Failed to persist certificate issuer identity")?;
  publish_certificate(&directory, &staging).await?;
  Ok(EnsureCertificateResponse {
    expires_at,
    changed: true,
    revision: certificate_revision(&directory).await?,
  })
}

async fn certificate_domains_match(
  directory: &Path,
  domains: &[String],
) -> anyhow::Result<bool> {
  let stored =
    match fs::read_to_string(directory.join("current/domains")).await
    {
      Ok(stored) => stored,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
        return Ok(false);
      }
      Err(error) => {
        return Err(error)
          .context("Failed to read certificate domain set");
      }
    };
  let mut stored_domains =
    stored.lines().map(str::to_string).collect::<Vec<_>>();
  let mut requested_domains = domains.to_vec();
  stored_domains.sort();
  requested_domains.sort();
  Ok(stored_domains == requested_domains)
}

async fn certificate_issuer_matches(
  directory: &Path,
  issuer: &CertificateIssuer,
) -> anyhow::Result<bool> {
  let stored = match fs::read(directory.join("current/issuer")).await
  {
    Ok(stored) => stored,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return Ok(false);
    }
    Err(error) => {
      return Err(error)
        .context("Failed to read certificate issuer identity");
    }
  };
  let stored: CertificateIssuer = serde_json::from_slice(&stored)
    .context("Invalid certificate issuer identity")?;
  Ok(&stored == issuer)
}

async fn certificate_revision(
  directory: &Path,
) -> anyhow::Result<String> {
  // Issued directories are immutable and uniquely named, including across
  // Periphery restarts. Read the activated link, not a speculative version.
  let current = fs::read_link(directory.join("current"))
    .await
    .context("Failed to read published certificate version")?;
  let revision = current
    .to_str()
    .and_then(|name| name.strip_prefix("issued-"))
    .context("Invalid published certificate version")?;
  uuid::Uuid::parse_str(revision)
    .context("Invalid published certificate revision")?;
  Ok(revision.to_string())
}

#[cfg(unix)]
async fn atomic_write(
  path: &Path,
  contents: &[u8],
  mode: u32,
) -> anyhow::Result<()> {
  use std::os::unix::fs::PermissionsExt;
  let temp = path
    .with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
  fs::write(&temp, contents)
    .await
    .context("Failed to write certificate domain metadata")?;
  fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))
    .await
    .context("Failed to secure certificate domain metadata")?;
  if let Err(error) = fs::rename(&temp, path).await {
    let _ = fs::remove_file(&temp).await;
    return Err(error)
      .context("Failed to activate certificate metadata");
  }
  Ok(())
}

#[cfg(not(unix))]
async fn atomic_write(
  _: &Path,
  _: &[u8],
  _: u32,
) -> anyhow::Result<()> {
  bail!("Atomic certificate metadata updates require Unix")
}

impl Resolve<Args> for RemoveCertificate {
  async fn resolve(self, _: &Args) -> anyhow::Result<()> {
    validate_id(&self.id)?;
    let directory = certificate_directory_path(&self.id)?;
    remove_directory_if_present(&directory).await.with_context(
      || {
        format!("Failed to remove certificate files for {}", self.id)
      },
    )?;
    remove_directory_if_present(
      &periphery_config()
        .root_directory
        .join("acme")
        .join(&self.id),
    )
    .await
    .with_context(|| {
      format!("Failed to remove ACME state for {}", self.id)
    })
  }
}

async fn remove_directory_if_present(
  path: &Path,
) -> anyhow::Result<()> {
  match fs::remove_dir_all(path).await {
    Ok(()) => Ok(()),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      Ok(())
    }
    Err(error) => Err(error.into()),
  }
}

async fn certificate_directory(id: &str) -> anyhow::Result<PathBuf> {
  let directory = certificate_directory_path(id)?;
  fs::create_dir_all(&directory)
    .await
    .context("Failed to create certificate directory")?;
  let certificate_root =
    periphery_config().root_directory.join("certificates");
  fs::create_dir_all(&certificate_root)
    .await
    .context("Failed to create certificate storage root")?;
  set_directory_permissions(&certificate_root).await?;
  set_certificate_directory_permissions(&directory).await?;
  let canonical = fs::canonicalize(&directory)
    .await
    .context("Failed to resolve certificate directory")?;
  let root = fs::canonicalize(
    periphery_config().root_directory.join("certificates"),
  )
  .await
  .context("Failed to resolve certificate storage root")?;
  if !canonical.starts_with(root) {
    bail!(
      "Certificate directory is outside the configured storage root"
    );
  }
  Ok(canonical)
}

fn certificate_directory_path(id: &str) -> anyhow::Result<PathBuf> {
  validate_id(id)?;
  Ok(
    periphery_config()
      .root_directory
      .join("certificates")
      .join(id),
  )
}

pub(crate) async fn certificate_mount_source(
  id: &str,
) -> anyhow::Result<PathBuf> {
  let directory = certificate_directory_path(id)?;
  let canonical_directory = fs::canonicalize(&directory)
    .await
    .context("Certificate files are not available on this Server")?;
  let canonical_root = fs::canonicalize(
    periphery_config().root_directory.join("certificates"),
  )
  .await
  .context("Certificate storage root is unavailable")?;
  if !canonical_directory.starts_with(&canonical_root) {
    bail!("Certificate storage path is outside the configured root");
  }
  let current = fs::canonicalize(canonical_directory.join("current"))
    .await
    .context("Certificate is not ready for mounting")?;
  if !current.starts_with(&canonical_directory) {
    bail!(
      "Certificate version path is outside its storage directory"
    );
  }
  for file in ["tls.crt", "tls.key"] {
    if !current.join(file).is_file() {
      bail!("Certificate is missing required file '{file}'");
    }
  }
  Ok(canonical_directory)
}

async fn issue_acme_certificate(
  id: &str,
  domains: &[String],
  email: &str,
  token: &str,
  staging: &Path,
  force: bool,
) -> anyhow::Result<()> {
  #[cfg(not(unix))]
  bail!(
    "Cloudflare ACME certificate issuance requires a Unix Periphery host"
  );

  #[cfg(unix)]
  {
    if token.trim().is_empty()
      || token.contains('\n')
      || token.contains('\r')
    {
      bail!(
        "Cloudflare API token is empty or contains invalid characters"
      );
    }
    let state_directory =
      periphery_config().root_directory.join("acme").join(id);
    fs::create_dir_all(&state_directory)
      .await
      .context("Failed to create ACME state directory")?;
    set_directory_permissions(&state_directory).await?;
    let credentials = state_directory.join("cloudflare.ini");
    write_credentials(&credentials, token).await?;

    let result: anyhow::Result<()> = async {
      let command =
        certbot_command(&state_directory, id, domains, email, force)?;
      run_command(command, Some(token)).await?;

      let live = state_directory
        .join("acme")
        .join("config")
        .join("live")
        .join(format!("komodo-{id}"));
      copy_certificate_pair(
        &live.join("fullchain.pem"),
        &live.join("privkey.pem"),
        staging,
      )
      .await
    }
    .await;

    match fs::remove_file(&credentials).await {
      Ok(()) => result,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
        result
      }
      Err(error) => match result {
        Ok(()) => Err(error).context(
          "Failed to remove temporary Cloudflare credentials file",
        ),
        Err(issue_error) => Err(issue_error).context(format!(
          "Certificate issuance also failed to remove temporary Cloudflare credentials: {error}"
        )),
      },
    }
  }
}

#[cfg(unix)]
fn certbot_command(
  state_directory: &Path,
  id: &str,
  domains: &[String],
  email: &str,
  force: bool,
) -> anyhow::Result<Command> {
  let source = state_directory
    .to_str()
    .context("Certificate directory path is not valid UTF-8")?;
  if source.contains(',') || source.contains(':') {
    bail!("Certificate storage path cannot contain commas or colons");
  }
  let mut command = Command::new("docker");
  command
    .arg("run")
    .arg("--rm")
    .arg("--volume")
    .arg(format!("{source}:/cert-state"))
    .arg(CERTBOT_IMAGE)
    .arg("certonly")
    .arg("--non-interactive")
    .arg("--agree-tos")
    .arg("--dns-cloudflare")
    .arg("--dns-cloudflare-credentials")
    .arg("/cert-state/cloudflare.ini")
    .arg("--dns-cloudflare-propagation-seconds")
    .arg("30")
    .arg("--config-dir")
    .arg("/cert-state/acme/config")
    .arg("--work-dir")
    .arg("/cert-state/acme/work")
    .arg("--logs-dir")
    .arg("/cert-state/acme/logs")
    .arg("--cert-name")
    .arg(format!("komodo-{id}"));
  if force {
    command.arg("--force-renewal");
  } else {
    command.arg("--keep-until-expiring");
  }
  if email.trim().is_empty() {
    command.arg("--register-unsafely-without-email");
  } else {
    command.arg("--email").arg(email);
  }
  for domain in domains {
    command.arg("-d").arg(domain);
  }
  Ok(command)
}

async fn issue_tailscale_certificate(
  domain: &str,
  staging: &Path,
) -> anyhow::Result<()> {
  #[cfg(not(unix))]
  bail!(
    "Tailscale certificate retrieval requires a Unix Periphery host"
  );

  #[cfg(unix)]
  {
    let cert_path = staging.join("tls.crt");
    let key_path = staging.join("tls.key");
    let mut command = Command::new("tailscale");
    command
      .arg("cert")
      .arg("--cert-file")
      .arg(&cert_path)
      .arg("--key-file")
      .arg(&key_path)
      .arg(domain);
    run_command(command, None).await?;
    set_file_permissions(&key_path, 0o444).await?;
    set_file_permissions(&cert_path, 0o644).await?;
    Ok(())
  }
}

async fn copy_certificate_pair(
  cert_source: &Path,
  key_source: &Path,
  directory: &Path,
) -> anyhow::Result<()> {
  let cert_destination = directory.join("tls.crt");
  let key_destination = directory.join("tls.key");
  fs::copy(cert_source, &cert_destination)
    .await
    .context("Failed to copy issued certificate")?;
  fs::copy(key_source, &key_destination)
    .await
    .context("Failed to copy issued private key")?;
  set_file_permissions(&cert_destination, 0o444).await?;
  set_file_permissions(&key_destination, 0o444).await?;
  Ok(())
}

#[cfg(unix)]
async fn publish_certificate(
  directory: &Path,
  staging: &Path,
) -> anyhow::Result<()> {
  let next = directory
    .join(format!("current-next-{}", uuid::Uuid::new_v4().simple()));
  let current = directory.join("current");
  let name =
    staging.file_name().context("Invalid staging directory")?;
  let old_target = fs::read_link(&current).await.ok();
  fs::symlink(name, &next)
    .await
    .context("Failed to create certificate version link")?;
  if let Err(error) = fs::rename(&next, &current).await {
    let _ = fs::remove_file(&next).await;
    return Err(error)
      .context("Failed to atomically activate certificate");
  }
  if let Some(old_target) = old_target
    && old_target != name
  {
    let old = directory.join(old_target);
    if old.starts_with(directory)
      && old.file_name().is_some_and(|name| {
        name.to_string_lossy().starts_with("issued-")
      })
    {
      fs::remove_dir_all(old)
        .await
        .context("Failed to remove retired certificate version")?;
    }
  }
  Ok(())
}

#[cfg(not(unix))]
async fn publish_certificate(
  _: &Path,
  _: &Path,
) -> anyhow::Result<()> {
  bail!("Atomic certificate rotation requires a Unix Periphery host")
}

async fn run_command(
  mut command: Command,
  secret: Option<&str>,
) -> anyhow::Result<()> {
  let output = command
    .stdin(Stdio::null())
    .output()
    .await
    .context("Failed to start certificate issuer command")?;
  if output.status.success() {
    return Ok(());
  }
  let mut details =
    String::from_utf8_lossy(&output.stderr).to_string();
  if let Some(secret) = secret {
    details = details.replace(secret, "[redacted]");
  }
  details.truncate(4_000);
  Err(anyhow!(
    "Certificate issuer command failed ({}): {}",
    output.status,
    details.trim()
  ))
}

async fn certificate_expiry(
  path: &Path,
) -> anyhow::Result<Option<i64>> {
  let pem = match fs::read(path).await {
    Ok(pem) => pem,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return Ok(None);
    }
    Err(error) => {
      return Err(error).context("Failed to read certificate file");
    }
  };
  let (_, pem) = x509_parser::pem::parse_x509_pem(&pem)
    .map_err(|error| anyhow!("Invalid PEM certificate: {error}"))?;
  let (_, certificate) = x509_parser::parse_x509_certificate(
    &pem.contents,
  )
  .map_err(|error| anyhow!("Invalid X.509 certificate: {error}"))?;
  Ok(Some(certificate.validity().not_after.timestamp()))
}

fn validate_id(id: &str) -> anyhow::Result<()> {
  if id.is_empty()
    || id.len() > 128
    || !id
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
  {
    bail!("Invalid certificate id");
  }
  Ok(())
}

fn validate_domains(domains: &[String]) -> anyhow::Result<()> {
  if domains.is_empty() {
    bail!("At least one DNS name is required");
  }
  for domain in domains {
    let normalized = domain.strip_prefix("*.").unwrap_or(domain);
    if domain.len() > 253
      || normalized.is_empty()
      || normalized.parse::<std::net::IpAddr>().is_ok()
      || normalized.split('.').count() < 2
      || normalized.split('.').any(|label| {
        label.is_empty()
          || label.len() > 63
          || label.starts_with('-')
          || label.ends_with('-')
          || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
      })
    {
      bail!("Invalid DNS name: {domain}");
    }
  }
  Ok(())
}

#[cfg(unix)]
async fn write_credentials(
  path: &Path,
  token: &str,
) -> anyhow::Result<()> {
  use std::os::unix::fs::PermissionsExt;

  let mut file = fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .mode(0o600)
    .open(path)
    .await
    .context("Failed to create Cloudflare credentials file")?;
  use tokio::io::AsyncWriteExt;
  file
    .write_all(
      format!("dns_cloudflare_api_token = {token}\n").as_bytes(),
    )
    .await
    .context("Failed to write Cloudflare credentials file")?;
  file.flush().await?;
  fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    .await
    .context("Failed to protect Cloudflare credentials file")
}

#[cfg(unix)]
async fn set_directory_permissions(
  path: &Path,
) -> anyhow::Result<()> {
  use std::os::unix::fs::PermissionsExt;
  fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    .await
    .context("Failed to protect certificate directory")
}

#[cfg(unix)]
async fn set_certificate_directory_permissions(
  path: &Path,
) -> anyhow::Result<()> {
  use std::os::unix::fs::PermissionsExt;
  fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
    .await
    .context("Failed to set certificate mount directory permissions")
}

#[cfg(not(unix))]
async fn set_certificate_directory_permissions(
  _: &Path,
) -> anyhow::Result<()> {
  Ok(())
}

#[cfg(not(unix))]
async fn set_directory_permissions(_: &Path) -> anyhow::Result<()> {
  Ok(())
}

#[cfg(unix)]
async fn set_file_permissions(
  path: &Path,
  mode: u32,
) -> anyhow::Result<()> {
  use std::os::unix::fs::PermissionsExt;
  fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    .await
    .with_context(|| format!("Failed to protect {}", path.display()))
}

#[cfg(not(unix))]
async fn set_file_permissions(
  _: &Path,
  _: u32,
) -> anyhow::Result<()> {
  Ok(())
}

#[cfg(all(test, unix))]
mod tests {
  use super::*;

  fn test_directory() -> PathBuf {
    std::env::current_dir().unwrap().join(format!(
      "certificate-test-{}",
      uuid::Uuid::new_v4().simple()
    ))
  }

  async fn test_version(directory: &Path) -> PathBuf {
    let version = directory
      .join(format!("issued-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir_all(&version).await.unwrap();
    version
  }

  #[test]
  fn ensure_response_accepts_legacy_missing_revision() {
    let response: EnsureCertificateResponse =
      serde_json::from_str(r#"{"expires_at":123,"changed":false}"#)
        .unwrap();
    assert!(response.revision.is_empty());
  }

  #[tokio::test]
  async fn unforced_reuse_requires_the_same_issuer_and_returns_revision()
   {
    let directory = test_directory();
    let version = test_version(&directory).await;
    let issuer = CertificateIssuer::AcmeCloudflare {
      api_token_secret: "cloudflare".into(),
      email: "admin@example.com".into(),
    };
    fs::write(
      version.join("tls.crt"),
      include_bytes!("certificate-test.pem"),
    )
    .await
    .unwrap();
    atomic_write(&version.join("domains"), b"app.example.com", 0o644)
      .await
      .unwrap();
    atomic_write(
      &version.join("issuer"),
      &serde_json::to_vec(&issuer).unwrap(),
      0o644,
    )
    .await
    .unwrap();
    publish_certificate(&directory, &version).await.unwrap();
    let request = EnsureCertificate {
      id: "certificate".into(),
      domains: vec!["app.example.com".into()],
      issuer,
      force: false,
      cloudflare_token: None,
    };
    let reused =
      ensure_certificate(request.clone(), directory.clone())
        .await
        .unwrap();
    assert!(!reused.changed);
    assert_eq!(
      reused.revision,
      certificate_revision(&directory).await.unwrap()
    );
    assert!(reused.expires_at > chrono::Utc::now().timestamp());
    for previous_issuer in [
      CertificateIssuer::Tailscale,
      CertificateIssuer::AcmeCloudflare {
        api_token_secret: "another-secret".into(),
        email: "admin@example.com".into(),
      },
      CertificateIssuer::AcmeCloudflare {
        api_token_secret: "cloudflare".into(),
        email: "other@example.com".into(),
      },
    ] {
      atomic_write(
        &version.join("issuer"),
        &serde_json::to_vec(&previous_issuer).unwrap(),
        0o644,
      )
      .await
      .unwrap();
      // Missing credentials prove the ACME issuance path is reached instead
      // of silently reusing the still-valid certificate.
      let error =
        ensure_certificate(request.clone(), directory.clone())
          .await
          .unwrap_err();
      assert!(
        error
          .to_string()
          .contains("Cloudflare API token was not provided")
      );
      assert_eq!(
        reused.revision,
        certificate_revision(&directory).await.unwrap()
      );
    }
    fs::remove_dir_all(&directory).await.unwrap();
  }

  #[tokio::test]
  async fn issuer_identity_is_bound_to_the_published_certificate() {
    let directory = test_directory();
    let domains = vec!["app.example.com".to_string()];
    let cloudflare = CertificateIssuer::AcmeCloudflare {
      api_token_secret: "cloudflare".into(),
      email: "admin@example.com".into(),
    };
    let first = test_version(&directory).await;
    atomic_write(
      &first.join("domains"),
      domains.join("\n").as_bytes(),
      0o644,
    )
    .await
    .unwrap();
    atomic_write(
      &first.join("issuer"),
      &serde_json::to_vec(&cloudflare).unwrap(),
      0o644,
    )
    .await
    .unwrap();
    publish_certificate(&directory, &first).await.unwrap();
    assert!(
      certificate_domains_match(&directory, &domains)
        .await
        .unwrap()
    );
    assert!(
      certificate_issuer_matches(&directory, &cloudflare)
        .await
        .unwrap()
    );
    for issuer in [
      CertificateIssuer::Tailscale,
      CertificateIssuer::AcmeCloudflare {
        api_token_secret: "another-secret".into(),
        email: "admin@example.com".into(),
      },
      CertificateIssuer::AcmeCloudflare {
        api_token_secret: "cloudflare".into(),
        email: "other@example.com".into(),
      },
    ] {
      assert!(
        !certificate_issuer_matches(&directory, &issuer)
          .await
          .unwrap()
      );
    }
    let second = test_version(&directory).await;
    atomic_write(
      &second.join("issuer"),
      &serde_json::to_vec(&CertificateIssuer::Tailscale).unwrap(),
      0o644,
    )
    .await
    .unwrap();
    // Staged identity must not make an old certificate eligible for reuse.
    assert!(
      !certificate_issuer_matches(
        &directory,
        &CertificateIssuer::Tailscale
      )
      .await
      .unwrap()
    );
    publish_certificate(&directory, &second).await.unwrap();
    assert!(
      certificate_issuer_matches(
        &directory,
        &CertificateIssuer::Tailscale
      )
      .await
      .unwrap()
    );
    assert!(
      !certificate_issuer_matches(&directory, &cloudflare)
        .await
        .unwrap()
    );
    fs::remove_file(second.join("issuer")).await.unwrap();
    assert!(
      !certificate_issuer_matches(
        &directory,
        &CertificateIssuer::Tailscale
      )
      .await
      .unwrap()
    );
    fs::remove_dir_all(&directory).await.unwrap();
  }

  #[tokio::test]
  async fn publication_recovers_from_stale_links_and_reports_stable_revision()
   {
    let directory = test_directory();
    let first = test_version(&directory).await;
    publish_certificate(&directory, &first).await.unwrap();
    let first_revision =
      certificate_revision(&directory).await.unwrap();
    assert_eq!(
      first_revision,
      certificate_revision(&directory).await.unwrap()
    );
    let second = test_version(&directory).await;
    for stale in ["current-next", "current-next-abandoned"] {
      fs::symlink(first.file_name().unwrap(), directory.join(stale))
        .await
        .unwrap();
    }
    publish_certificate(&directory, &second).await.unwrap();
    let second_revision =
      certificate_revision(&directory).await.unwrap();
    assert_ne!(first_revision, second_revision);
    assert_eq!(
      format!("issued-{second_revision}"),
      second.file_name().unwrap().to_str().unwrap()
    );
    assert_eq!(
      fs::read_link(directory.join("current")).await.unwrap(),
      Path::new(second.file_name().unwrap())
    );
    assert_eq!(
      second_revision,
      certificate_revision(&directory).await.unwrap()
    );
    assert!(!first.exists());
    fs::remove_dir_all(&directory).await.unwrap();
  }

  #[test]
  fn certbot_mounts_state_and_keeps_account_data_outside_certificates()
   {
    let state = Path::new("/var/lib/komodo/acme/certificate");
    let command = certbot_command(
      state,
      "certificate",
      &["app.example.com".into(), "*.example.com".into()],
      "admin@example.com",
      true,
    )
    .unwrap();
    let args = command.as_std().get_args().collect::<Vec<_>>();
    let value = |flag: &str| {
      args.windows(2).find(|pair| pair[0] == flag).unwrap()[1]
        .to_str()
        .unwrap()
    };
    assert_eq!(
      value("--volume"),
      "/var/lib/komodo/acme/certificate:/cert-state"
    );
    let config = value("--config-dir");
    assert_eq!(
      state
        .join(config.strip_prefix("/cert-state/").unwrap())
        .join("live/komodo-certificate"),
      state.join("acme/config/live/komodo-certificate")
    );
    assert_eq!(value("--email"), "admin@example.com");
    assert!(args.contains(&std::ffi::OsStr::new("--force-renewal")));
    assert!(args.contains(&std::ffi::OsStr::new("*.example.com")));
  }

  #[test]
  fn certbot_rejects_ambiguous_mount_sources() {
    for path in ["/var/lib/komodo:other", "/var/lib/komodo,other"] {
      assert!(
        certbot_command(
          Path::new(path),
          "certificate",
          &["app.example.com".into()],
          "",
          false,
        )
        .is_err()
      );
    }
  }
}
