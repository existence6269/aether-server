use std::{error::Error, sync::Arc};

use aether_server::{run_from_env, StaticDeviceAuthorizer};
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

    let authorizer = StaticDeviceAuthorizer::from_env()?;
    if std::env::var_os("AETHER_AUTHORIZED_DEVICES").is_none() {
        tracing::warn!("no device allowlist is configured; WebSocket clients are rejected");
    }
    run_from_env(Arc::new(authorizer)).await
}
