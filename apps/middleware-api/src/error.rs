use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{message}")]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub details: Option<Value>,
}

impl AppError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: None,
        }
    }
    pub fn bad(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }
    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }
    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }
    pub fn unprocessable(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }
    pub fn detail(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut error = json!({"code": self.code, "message": self.message});
        if let Some(details) = self.details {
            error["details"] = details;
        }
        (self.status, Json(json!({"error": error}))).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = ?error, "database operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Unexpected middleware failure.",
        )
    }
}
