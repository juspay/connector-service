use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug)]
pub struct HttpError {
    pub status: StatusCode,
    pub message: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    message: String,
    code: String,
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: ErrorDetail {
                message: self.message.clone(),
                code: format!("{}", self.status.as_u16()),
            },
        });
        (self.status, body).into_response()
    }
}

// Convert tonic::Status to HTTP error
impl From<tonic::Status> for HttpError {
    fn from(status: tonic::Status) -> Self {
        let http_status = match status.code() {
            tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
            tonic::Code::NotFound => StatusCode::NOT_FOUND,
            tonic::Code::AlreadyExists => StatusCode::CONFLICT,
            tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
            tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
            tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        Self {
            status: http_status,
            message: status.message().to_string(),
        }
    }
}
