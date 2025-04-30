use strum::Display;

#[derive(Debug, thiserror::Error, PartialEq, Clone)]
pub enum ApiClientError {
    #[error("Header map construction failed")]
    HeaderMapConstructionFailed,
    #[error("Invalid proxy configuration")]
    InvalidProxyConfiguration,
    #[error("Client construction failed")]
    ClientConstructionFailed,
    #[error("Certificate decode failed")]
    CertificateDecodeFailed,
    #[error("Request body serialization failed")]
    BodySerializationFailed,
    #[error("Unexpected state reached/Invariants conflicted")]
    UnexpectedState,

    #[error("URL encoding of request payload failed")]
    UrlEncodingFailed,
    #[error("Failed to send request to connector {0}")]
    RequestNotSent(String),
    #[error("Failed to decode response")]
    ResponseDecodingFailed,

    #[error("Server responded with Request Timeout")]
    RequestTimeoutReceived,

    #[error("connection closed before a message could complete")]
    ConnectionClosedIncompleteMessage,

    #[error("Server responded with Internal Server Error")]
    InternalServerErrorReceived,
    #[error("Server responded with Bad Gateway")]
    BadGatewayReceived,
    #[error("Server responded with Service Unavailable")]
    ServiceUnavailableReceived,
    #[error("Server responded with Gateway Timeout")]
    GatewayTimeoutReceived,
    #[error("Server responded with unexpected response")]
    UnexpectedServerResponse,
}

#[derive(Debug, Clone, thiserror::Error, Display)]
pub enum ApplicationErrorResponse {
    Unauthorized(ApiError),
    ForbiddenCommonResource(ApiError),
    ForbiddenPrivateResource(ApiError),
    Conflict(ApiError),
    Gone(ApiError),
    Unprocessable(ApiError),
    InternalServerError(ApiError),
    NotImplemented(ApiError),
    NotFound(ApiError),
    MethodNotAllowed(ApiError),
    BadRequest(ApiError),
    DomainError(ApiError),
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct ApiError {
    pub sub_code: String,
    pub error_identifier: u16,
    pub error_message: String,
    pub error_object: Option<serde_json::Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParsingError {
    #[error("Failed to parse struct: {0}")]
    StructParseFailure(&'static str),
    #[error("Failed to serialize to {0} format")]
    EncodeError(&'static str),
}
