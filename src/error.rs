use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid request")]
    InvalidRequest,
    #[error("message exceeds configured size limit")]
    MessageTooLarge,
    #[error("recipient queue is full")]
    QueueFull,
    #[error("server resource limit reached")]
    ResourceLimit,
    #[error("message acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("server is shutting down")]
    ShuttingDown,
    #[error("account directory is not configured")]
    Unavailable,
    #[error("internal server error")]
    Internal,
}

impl ServerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration(_) => "invalid_configuration",
            Self::Unauthorized => "unauthorized",
            Self::InvalidRequest => "invalid_request",
            Self::MessageTooLarge => "message_too_large",
            Self::QueueFull => "queue_full",
            Self::ResourceLimit => "resource_limit",
            Self::InvalidAcknowledgement => "invalid_acknowledgement",
            Self::ShuttingDown => "shutting_down",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidConfiguration(_) | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidRequest | Self::InvalidAcknowledgement => StatusCode::BAD_REQUEST,
            Self::MessageTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::QueueFull | Self::ResourceLimit => StatusCode::TOO_MANY_REQUESTS,
            Self::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = Json(ErrorBody { error: self.code() });
        (status, body).into_response()
    }
}
