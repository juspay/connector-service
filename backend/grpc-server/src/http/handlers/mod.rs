pub mod payments;

pub async fn health() -> &'static str {
    "OK"
}