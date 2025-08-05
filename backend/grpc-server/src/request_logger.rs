use axum::{
    body::Body,
    extract::Request,
    middleware::Next,
    response::Response,
};
use tracing::info;

pub async fn log_raw_request(req: Request, next: Next) -> Response {
    info!("🔥 RAW REQUEST MIDDLEWARE TRIGGERED 🔥");
    
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    
    // Extract request body for logging
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to read request body for logging: {e}");
            return Response::builder()
                .status(400)
                .body(Body::from("Failed to read request body"))
                .unwrap();
        }
    };
    
    // Log the raw request
    info!(
        method = %method,
        uri = %uri,
        headers = ?headers,
        body = %String::from_utf8_lossy(&body_bytes),
        "Raw HTTP request received"
    );
    
    // Reconstruct the request for the handler
    let req = Request::from_parts(parts, Body::from(body_bytes));
    
    // Call the next middleware/handler
    next.run(req).await
}