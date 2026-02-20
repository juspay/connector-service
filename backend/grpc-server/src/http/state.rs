type CompositePaymentsService =
    composite_service::payments::Payments<crate::server::payments::Payments>;

#[derive(Clone)]
pub struct AppState {
    pub composite_payments_service: CompositePaymentsService,
    pub payments_service: crate::server::payments::Payments,
    pub refunds_service: crate::server::refunds::Refunds,
    pub disputes_service: crate::server::disputes::Disputes,
}

impl AppState {
    pub fn new(
        composite_payments_service: CompositePaymentsService,
        payments_service: crate::server::payments::Payments,
        refunds_service: crate::server::refunds::Refunds,
        disputes_service: crate::server::disputes::Disputes,
    ) -> Self {
        Self {
            composite_payments_service,
            payments_service,
            refunds_service,
            disputes_service,
        }
    }
}
