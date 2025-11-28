#[derive(Clone)]
pub struct AppState {
    pub payments_service: crate::grpc::payments::Payments,
}

impl AppState {
    pub fn new(payments_service: crate::grpc::payments::Payments) -> Self {
        Self { payments_service }
    }
}
