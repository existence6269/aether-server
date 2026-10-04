mod accounts;
mod auth;
mod config;
mod error;
mod http;
mod protocol;
mod state;
mod websocket;

pub use auth::{DeviceAuthorizer, RejectAllAuthenticator, StaticDeviceAuthorizer};
pub use config::ServerConfig;
pub use error::ServerError;
pub use http::router;
pub use protocol::{
    AuthClientFrame, AuthServerFrame, ClientFrame, DeviceAddress, OpaqueEnvelope, ServerFrame,
};
pub use state::AppState;

use std::{error::Error, future::Future, io, sync::Arc};

use tokio::{net::TcpListener, signal};
use tracing::info;

/// Serves HTTP health/readiness routes and the authenticated WebSocket relay.
/// The shutdown future is the only trigger for graceful termination.
pub async fn serve(
    listener: TcpListener,
    state: AppState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let app = router(state.clone());
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.await;
            state.stop_accepting();
        })
        .await
}

/// Loads environment configuration, binds, and serves until Ctrl-C.
pub async fn run_from_env(
    authorizer: Arc<dyn DeviceAuthorizer>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = ServerConfig::from_env()?;
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!(bind_addr = %config.bind_addr, "Aether relay listening");
    let state = match accounts::AccountDirectory::connect_from_env(&config.server_id).await? {
        Some(directory) => AppState::with_account_directory(config, directory)?,
        None => AppState::new(config, authorizer)?,
    };
    serve(listener, state, shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = signal::ctrl_c() => {
                        if let Err(error) = result {
                            tracing::error!(%error, "failed to listen for interrupt signal");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::error!(%error, "failed to listen for termination signal");
                if let Err(error) = signal::ctrl_c().await {
                    tracing::error!(%error, "failed to listen for interrupt signal");
                }
            }
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for interrupt signal");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{net::TcpListener, sync::oneshot};

    use crate::{AppState, RejectAllAuthenticator, ServerConfig};

    use super::serve;

    #[tokio::test]
    async fn server_stops_readiness_and_exits_on_graceful_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state =
            AppState::new(ServerConfig::default(), Arc::new(RejectAllAuthenticator)).unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        assert!(!state.is_ready());
    }
}
