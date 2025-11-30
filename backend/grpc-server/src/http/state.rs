#[derive(Clone)]
pub struct AppState {
    pub payments_service: crate::server::payments::Payments,
}

impl AppState {
    pub fn new(payments_service: crate::server::payments::Payments) -> Self {
        Self { payments_service }
    }
}