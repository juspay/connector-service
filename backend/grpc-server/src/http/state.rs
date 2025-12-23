#[derive(Clone)]
pub struct AppState {
    pub payments_service: crate::server::payments::Payments,
    pub refunds_service: crate::server::refunds::Refunds,
    pub disputes_service: crate::server::disputes::Disputes,
}

impl AppState {
    pub fn new(
        payments_service: crate::server::payments::Payments,
        refunds_service: crate::server::refunds::Refunds,
        disputes_service: crate::server::disputes::Disputes,
    ) -> Self {
        Self {
            payments_service,
            refunds_service,
            disputes_service,
        }
    }
}
