use komodo_client::entities::server::ReverseProxyConfig;
use komodo_client::entities::update::Log;
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(Log)]
#[error(anyhow::Error)]
pub struct EnsureReverseProxy {
  pub server_id: String,
  pub config: ReverseProxyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[response(Log)]
#[error(anyhow::Error)]
pub struct RemoveReverseProxy {
  pub server_id: String,
}
