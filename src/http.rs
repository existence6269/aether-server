use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use crate::{websocket, AppState};

#[derive(Serialize)]
struct ServiceStatus {
    status: &'static str,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/ws", get(websocket::upgrade))
        .with_state(state)
}

async fn health() -> Json<ServiceStatus> {
    Json(ServiceStatus { status: "ok" })
}

async fn readiness(
    State(state): State<AppState>,
) -> Result<Json<ServiceStatus>, axum::http::StatusCode> {
    if state.is_ready() {
        Ok(Json(ServiceStatus { status: "ready" }))
    } else {
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::{auth::RejectAllAuthenticator, config::ServerConfig, state::AppState};

    use super::router;

    #[tokio::test]
    async fn health_and_readiness_track_shutdown_state() {
        let state =
            AppState::new(ServerConfig::default(), Arc::new(RejectAllAuthenticator)).unwrap();
        let app = router(state.clone());

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let ready = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);

        state.stop_accepting();
        let not_ready = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
