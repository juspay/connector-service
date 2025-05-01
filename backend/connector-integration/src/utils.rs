use domain_types::{
    connector_flow::{Authorize, SetupMandate},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, SetupMandateRequestData,
    },
};
use hyperswitch_domain_models::router_data_v2::RouterDataV2;

#[macro_export]
macro_rules! with_error_response_body {
    ($event_builder:ident, $response:ident) => {
        if let Some(body) = $event_builder {
            body.set_error_response_body(&$response);
        }
    };
}

#[macro_export]
macro_rules! with_response_body {
    ($event_builder:ident, $response:ident) => {
        if let Some(body) = $event_builder {
            body.set_response_body(&$response);
        }
    };
}

pub(crate) fn convert_setup_mandate_router_data_to_authorize_router_data(
    data: &RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData,
        PaymentsResponseData,
    >,
) -> RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
    let payments_authorize_data = PaymentsAuthorizeData {
        payment_method_data: data.request.payment_method_data.clone(),
        amount: data.request.amount.unwrap(),
        order_tax_amount: None,
        email: data.request.email.clone(),
        customer_name: data.request.customer_name.clone(),
        currency: data.request.currency.clone(),
        confirm: data.request.confirm.clone(),
        statement_descriptor_suffix: data.request.statement_descriptor_suffix.clone(),
        statement_descriptor: None,
        capture_method: data.request.capture_method.clone(),
        router_return_url: data.request.router_return_url.clone(),
        webhook_url: data.request.webhook_url.clone(),
        complete_authorize_url: data.request.complete_authorize_url.clone(),
        mandate_id: data.request.mandate_id.clone(),
        setup_future_usage: data.request.setup_future_usage.clone(),
        off_session: data.request.off_session.clone(),
        browser_info: data.request.browser_info.clone(),
        order_category: None,
        session_token: None,
        enrolled_for_3ds: false,
        related_transaction_id: None,
        payment_experience: None,
        payment_method_type: data.request.payment_method_type.clone(),
        customer_id: data.request.customer_id.clone(),
        request_incremental_authorization: data.request.request_incremental_authorization.clone(),
        metadata: data.request.metadata.clone(),
        minor_amount: data.request.minor_amount.clone().unwrap(),
        merchant_order_reference_id: None,
        shipping_cost: None,
        merchant_account_id: None,
        merchant_config_currency: None,
    };

    RouterDataV2 {
        flow: std::marker::PhantomData,
        resource_common_data: data.resource_common_data.clone(),
        connector_auth_type: data.connector_auth_type.clone(),
        request: payments_authorize_data,
        response: data.response.clone(),
    }
}
