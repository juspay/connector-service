use domain_types::connector_types::ConnectorEnum;
use grpc_api_types::payments::{
    CompositeAuthorizeRequest, CustomerServiceCreateRequest,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
};

use crate::utils::grpc_connector_from_connector_enum;

pub trait ForeignFrom<F>: Sized {
    fn foreign_from(item: F) -> Self;
}

impl ForeignFrom<(&CompositeAuthorizeRequest, &ConnectorEnum)>
    for MerchantAuthenticationServiceCreateAccessTokenRequest
{
    fn foreign_from((item, connector): (&CompositeAuthorizeRequest, &ConnectorEnum)) -> Self {
        Self {
            request_ref_id: item.merchant_transaction_id.clone(),
            connector: grpc_connector_from_connector_enum(connector),
            metadata: item.metadata.clone(),
            feature_data: item.feature_data.clone(),
            test_mode: item.test_mode,
        }
    }
}

impl ForeignFrom<&CompositeAuthorizeRequest> for CustomerServiceCreateRequest {
    fn foreign_from(item: &CompositeAuthorizeRequest) -> Self {
        let customer = item.customer.as_ref();
        Self {
            merchant_customer_id: customer.and_then(|c| c.id.clone()).map(|id| {
                grpc_api_types::payments::Identifier {
                    id_type: Some(grpc_api_types::payments::identifier::IdType::Id(id.clone())),
                }
            }),
            customer_name: customer.and_then(|c| c.name.clone()),
            email: customer.and_then(|c| c.email.clone()),
            phone_number: customer.and_then(|c| c.phone_number.clone()),
            address: item.address.clone(),
            metadata: item.metadata.clone(),
            feature_data: item.feature_data.clone(),
            test_mode: item.test_mode,
        }
    }
}

// impl
//     ForeignFrom<(
//         &CompositeAuthorizeRequest,
//         Option<&PaymentServiceCreateAccessTokenResponse>,
//         Option<&PaymentServiceCreateConnectorCustomerResponse>,
//     )> for PaymentServiceAuthorizeOnlyRequest
// {
//     fn foreign_from(
//         (item, access_token_response, create_customer_response): (
//             &CompositeAuthorizeRequest,
//             Option<&PaymentServiceCreateAccessTokenResponse>,
//             Option<&PaymentServiceCreateConnectorCustomerResponse>,
//         ),
//     ) -> Self {
//         let connector_customer_id_from_req = item.connector_customer_id.clone().or_else(|| {
//             item.state
//                 .as_ref()
//                 .and_then(|state| state.connector_customer_id.clone())
//         });

//         let connector_customer_id =
//             get_connector_customer_id(connector_customer_id_from_req, create_customer_response);

//         let access_token_from_req = item
//             .state
//             .as_ref()
//             .and_then(|state| state.access_token.clone());

//         let access_token = get_access_token(access_token_from_req, access_token_response);

//         let resolved_state = Some(ConnectorState {
//             access_token,
//             connector_customer_id: connector_customer_id.clone(),
//         });
//         Self {
//             request_ref_id: item.request_ref_id.clone(),
//             amount: item.amount,
//             currency: item.currency,
//             minor_amount: item.minor_amount,
//             order_tax_amount: item.order_tax_amount,
//             shipping_cost: item.shipping_cost,
//             payment_method: item.payment_method.clone(),
//             capture_method: item.capture_method,
//             email: item.email.clone(),
//             customer_name: item.customer_name.clone(),
//             customer_id: item.customer_id.clone(),
//             connector_customer_id,
//             address: item.address.clone(),
//             auth_type: item.auth_type,
//             enrolled_for_3ds: item.enrolled_for_3ds,
//             authentication_data: item.authentication_data.clone(),
//             metadata: item.metadata.clone(),
//             connector_metadata: item.connector_metadata.clone(),
//             return_url: item.return_url.clone(),
//             webhook_url: item.webhook_url.clone(),
//             complete_authorize_url: item.complete_authorize_url.clone(),
//             session_token: item.session_token.clone(),
//             order_category: item.order_category.clone(),
//             merchant_order_reference_id: item.merchant_order_reference_id.clone(),
//             setup_future_usage: item.setup_future_usage,
//             off_session: item.off_session,
//             request_incremental_authorization: item.request_incremental_authorization,
//             request_extended_authorization: item.request_extended_authorization,
//             enable_partial_authorization: item.enable_partial_authorization,
//             customer_acceptance: item.customer_acceptance.clone(),
//             browser_info: item.browser_info.clone(),
//             payment_experience: item.payment_experience,
//             description: item.description.clone(),
//             payment_channel: item.payment_channel,
//             test_mode: item.test_mode,
//             merchant_account_metadata: item.merchant_account_metadata.clone(),
//             setup_mandate_details: item.setup_mandate_details.clone(),
//             statement_descriptor_name: item.statement_descriptor_name.clone(),
//             statement_descriptor_suffix: item.statement_descriptor_suffix.clone(),
//             billing_descriptor: item.billing_descriptor.clone(),
//             state: resolved_state,
//             order_details: item.order_details.clone(),
//             payment_method_token: item.payment_method_token.clone(),
//             connector_order_reference_id: item.connector_order_reference_id.clone(),
//             locale: item.locale.clone(),
//             continue_redirection_url: item.continue_redirection_url.clone(),
//             threeds_completion_indicator: item.threeds_completion_indicator,
//             redirection_response: item.redirection_response.clone(),
//             tokenization_strategy: item.tokenization_strategy,
//         }
//     }
// }
