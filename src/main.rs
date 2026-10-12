use std::{error::Error, sync::Arc};

use aether_server::{run_from_env, RejectAllAuthenticator, StaticDeviceAuthorizer};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("aether_server=info,tower_http=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init()?;

    let development_mode = std::env::var("AETHER_ENV")
        .map(|value| value == "development")
        .unwrap_or(false);
    let authorizer: Arc<dyn aether_server::DeviceAuthorizer> = if development_mode {
        Arc::new(StaticDeviceAuthorizer::from_env()?)
    } else {
        Arc::new(RejectAllAuthenticator)
    };
    if development_mode && std::env::var_os("AETHER_AUTHORIZED_DEVICES").is_none() {
        tracing::warn!("development mode has no device allowlist; WebSocket clients are rejected");
    }
    run_from_env(authorizer).await
}
