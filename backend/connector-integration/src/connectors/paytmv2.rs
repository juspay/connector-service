pub mod transformers;
pub mod constants;

use std::fmt::Debug;

use common_utils::{errors::CustomResult, types::StringMajorUnit};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
        ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use hyperswitch_masking::{Maskable, ExposeInterface};
use interfaces::{
    api::ConnectorCommon, connector_integration_v2::ConnectorIntegrationV2,
    events::connector_api_logs::ConnectorEvent, verification::SourceVerification,
};
use serde::Serialize;
use transformers::{Paytmv2PaymentsRequest, Paytmv2PaymentsResponse, Paytmv2PaymentsSyncRequest, Paytmv2PaymentsSyncResponse};

use crate::{connectors::macros, types::ResponseRouterData};

// Define connector prerequisites using macros - following the exact pattern from other connectors
macros::create_all_prerequisites!(
    connector_name: Paytmv2,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: Paytmv2PaymentsRequest,
            response_body: Paytmv2PaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: Paytmv2PaymentsSyncRequest,
            response_body: Paytmv2PaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMajorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![
                (
                    "Content-Type".to_string(),
                    "application/json".to_string().into(),
                )
            ])
        }

        pub fn connector_base_url_payments<'a, F, Req, Res>(
            &self,
            req: &'a RouterDataV2<F, PaymentFlowData, Req, Res>,
        ) -> &'a str {
            // Use a placeholder URL since paytmv2 is not in the Connectors struct
            "https://securegw.paytm.in"
        }



        fn build_authorize_request(
            &self,
            router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Paytmv2PaymentsRequest, errors::ConnectorError> {
            let amount = self.amount_converter.convert(router_data.request.minor_amount, router_data.request.currency)
                .map_err(|e| errors::ConnectorError::ParsingFailed)?;
            
            let payment_method_data = match &router_data.request.payment_method_data {
                domain_types::payment_method_data::PaymentMethodData::Upi(upi_data) => upi_data,
                _ => Err(errors::ConnectorError::NotSupported {
                    message: "Payment method not supported".to_string(),
                    connector: "Paytmv2",
                })?,
            };

            let upi_vpa = match payment_method_data {
                domain_types::payment_method_data::UpiData::UpiCollect(upi_collect) => {
                    upi_collect.vpa_id.clone().unwrap_or_default().expose().clone()
                },
                domain_types::payment_method_data::UpiData::UpiIntent(_) => {
                    return Err(errors::ConnectorError::NotSupported {
                        message: "UPI Intent not supported".to_string(),
                        connector: "Paytmv2",
                    }.into());
                },
            };

            Ok(Paytmv2PaymentsRequest {
                body: transformers::Paytmv2PaymentsRequestBody {
                    mid: "test_merchant".to_string(), // TODO: Get from config
                    order_id: router_data.resource_common_data.payment_id.clone(),
                    txn_amount: transformers::Paytmv2TxnAmount {
                        value: amount.get_amount_as_string(),
                        currency: router_data.request.currency.to_string(),
                    },
                    user_info: transformers::Paytmv2UserInfo {
                        cust_id: format!("{:?}", router_data.request.customer_id.clone().unwrap_or_default()),
                    },
                    payment_method: transformers::Paytmv2PaymentMethod {
                        upi: Some(transformers::Paytmv2Upi {
                            vpa: upi_vpa,
                            flow: "COLLECT".to_string(),
                        }),
                    },
                    callback_url: router_data.request.webhook_url.clone(),
                },
            })
        }

        fn build_sync_request(
            &self,
            router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Paytmv2PaymentsSyncRequest, errors::ConnectorError> {
            Ok(Paytmv2PaymentsSyncRequest {
                body: transformers::Paytmv2PaymentsSyncRequestBody {
                    mid: "test_merchant".to_string(), // TODO: Get from config
                    order_id: router_data.resource_common_data.payment_id.clone(),
                },
            })
        }

        fn handle_authorize_response(
            &self,
            response: Paytmv2PaymentsResponse,
            router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<PaymentsResponseData, errors::ConnectorError> {
            match response.body.status.as_str() {
                "PENDING" => Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(response.body.txn_id.clone()),
                    redirection_data: Some(Box::new(domain_types::router_response_types::RedirectForm::Form {
                        endpoint: response.body.txn_url.clone().unwrap_or_default(),
                        method: common_utils::Method::Get,
                        form_fields: std::collections::HashMap::new(),
                    })),
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: response.status_code,
                }),
                "SUCCESS" => Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(response.body.txn_id.clone()),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: response.status_code,
                }),
                "FAILURE" => Err(errors::ConnectorError::FailedAtConnector {
                    message: response.body.resp_msg,
                    code: "FAILURE".to_string(),
                }.into()),
                _ => Err(errors::ConnectorError::UnexpectedResponseError(
                    format!("Unexpected status: {}", response.body.status).into()
                ).into()),
            }
        }

        fn handle_sync_response(
            &self,
            response: Paytmv2PaymentsSyncResponse,
            router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<PaymentsResponseData, errors::ConnectorError> {
            match response.body.status.as_str() {
                "SUCCESS" => Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(response.body.txn_id.clone()),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: response.status_code,
                }),
                "PENDING" => Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(response.body.txn_id.clone()),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: response.status_code,
                }),
                "FAILURE" => Err(errors::ConnectorError::FailedAtConnector {
                    message: response.body.resp_msg,
                    code: "FAILURE".to_string(),
                }.into()),
                _ => Err(errors::ConnectorError::UnexpectedResponseError(
                    format!("Unexpected status: {}", response.body.status).into()
                ).into()),
            }
        }
    }
);

// Authorize flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paytmv2,
    curl_request: Json(Paytmv2PaymentsRequest),
    curl_response: Paytmv2PaymentsResponse,
    flow_name: Authorize,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsAuthorizeData<T>,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(constants::PAYTMV2_AUTHORIZE_URL.to_string())
        }

        fn get_headers(
            &self,
            router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            Ok(vec![
                ("Content-Type".to_string(), "application/json".to_string().into()),
            ])
        }


    }
);

// PSync flow implementation
macros::macro_connector_implementation!(
    connector_default_implementations: [get_content_type],
    connector: Paytmv2,
    curl_request: Json(Paytmv2PaymentsSyncRequest),
    curl_response: Paytmv2PaymentsSyncResponse,
    flow_name: PSync,
    resource_common_data: PaymentFlowData,
    flow_request: PaymentsSyncData,
    flow_response: PaymentsResponseData,
    http_method: Post,
    generic_type: T,
    [PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize],
    other_functions: {
        fn get_url(
            &self,
            _router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<String, errors::ConnectorError> {
            Ok(constants::PAYTMV2_SYNC_URL.to_string())
        }

        fn get_headers(
            &self,
            router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
            Ok(vec![
                ("Content-Type".to_string(), "application/json".to_string().into()),
            ])
        }
    }
);

// Implement ValidationTrait
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> interfaces::connector_types::ValidationTrait for Paytmv2<T> {
}

// Implement ConnectorCommon trait
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> ConnectorCommon for Paytmv2<T> {
    fn id(&self) -> &'static str {
        "paytmv2"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, _connectors: &'a Connectors) -> &'a str {
        // Return a placeholder URL since paytmv2 is not in the Connectors struct
        "https://securegw.paytm.in"
    }
}

// **STUB IMPLEMENTATIONS**: Source Verification Framework stubs
use common_utils::crypto;
use interfaces::verification::ConnectorSourceVerificationSecrets;

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> 
    for Paytmv2<T> 
{
    fn get_secrets(
        &self,
        _secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // STUB: Return empty secrets - will be implemented later
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        // STUB: Use NoAlgorithm - will be replaced with actual algorithm later
        Ok(Box::new(crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // STUB: Return empty signature - will extract actual signature later
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // STUB: Return payload as-is - will implement gateway-specific message format later
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> 
    for Paytmv2<T> 
{
    fn get_secrets(
        &self,
        _secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // STUB: Return empty secrets - will be implemented later
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        // STUB: Use NoAlgorithm - will be replaced with actual algorithm later
        Ok(Box::new(crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // STUB: Return empty signature - will extract actual signature later
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // STUB: Return payload as-is - will implement gateway-specific message format later
        Ok(payload.to_owned())
    }
}

// Add the missing trait implementations that are required by the framework
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::ConnectorServiceTrait<T> for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::PaymentAuthorizeV2<T> for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::PaymentSyncV2 for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::PaymentOrderCreate for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::PaymentSessionToken for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::PaymentVoidV2 for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::IncomingWebhook for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::RefundV2 for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::PaymentCapture for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::SetupMandateV2<T> for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::RepeatPaymentV2 for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::AcceptDispute for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::RefundSyncV2 for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::DisputeDefend for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_types::SubmitEvidenceV2 for Paytmv2<T>
{
}

// Empty implementations for remaining required ConnectorIntegrationV2 traits
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::SubmitEvidence,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::SubmitEvidenceData,
        domain_types::connector_types::DisputeResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::DefendDispute,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::DisputeDefendData,
        domain_types::connector_types::DisputeResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::RSync,
        domain_types::connector_types::RefundFlowData,
        domain_types::connector_types::RefundSyncData,
        domain_types::connector_types::RefundsResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::Accept,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::AcceptDisputeData,
        domain_types::connector_types::DisputeResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::RepeatPayment,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::RepeatPaymentData,
        domain_types::connector_types::PaymentsResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::SetupMandate,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::SetupMandateRequestData<T>,
        domain_types::connector_types::PaymentsResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::Capture,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::PaymentsCaptureData,
        domain_types::connector_types::PaymentsResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::Refund,
        domain_types::connector_types::RefundFlowData,
        domain_types::connector_types::RefundsData,
        domain_types::connector_types::RefundsResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::Void,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::PaymentVoidData,
        domain_types::connector_types::PaymentsResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::CreateSessionToken,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::SessionTokenRequestData,
        domain_types::connector_types::SessionTokenResponseData,
    > for Paytmv2<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::connector_integration_v2::ConnectorIntegrationV2<
        domain_types::connector_flow::CreateOrder,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::PaymentCreateOrderData,
        domain_types::connector_types::PaymentCreateOrderResponse,
    > for Paytmv2<T>
{
}

// Add missing SourceVerification implementations
impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::SubmitEvidence,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::SubmitEvidenceData,
        domain_types::connector_types::DisputeResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::SubmitEvidence, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::SubmitEvidenceData, domain_types::connector_types::DisputeResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::RepeatPayment,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::RepeatPaymentData,
        domain_types::connector_types::PaymentsResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::RepeatPayment, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::RepeatPaymentData, domain_types::connector_types::PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::RepeatPayment, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::RepeatPaymentData, domain_types::connector_types::PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::SetupMandate,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::SetupMandateRequestData<T>,
        domain_types::connector_types::PaymentsResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::SetupMandate, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SetupMandateRequestData<T>, domain_types::connector_types::PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::SetupMandate, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SetupMandateRequestData<T>, domain_types::connector_types::PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::Capture,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::PaymentsCaptureData,
        domain_types::connector_types::PaymentsResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Capture, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, domain_types::connector_types::PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Capture, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentsCaptureData, domain_types::connector_types::PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::Refund,
        domain_types::connector_types::RefundFlowData,
        domain_types::connector_types::RefundsData,
        domain_types::connector_types::RefundsResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Refund, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundsData, domain_types::connector_types::RefundsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::Void,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::PaymentVoidData,
        domain_types::connector_types::PaymentsResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Void, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentVoidData, domain_types::connector_types::PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Void, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentVoidData, domain_types::connector_types::PaymentsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::CreateSessionToken,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::SessionTokenRequestData,
        domain_types::connector_types::SessionTokenResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::CreateSessionToken, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::CreateSessionToken, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::SessionTokenRequestData, domain_types::connector_types::SessionTokenResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::CreateOrder,
        domain_types::connector_types::PaymentFlowData,
        domain_types::connector_types::PaymentCreateOrderData,
        domain_types::connector_types::PaymentCreateOrderResponse,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::CreateOrder, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::CreateOrder, domain_types::connector_types::PaymentFlowData, domain_types::connector_types::PaymentCreateOrderData, domain_types::connector_types::PaymentCreateOrderResponse>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::DefendDispute,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::DisputeDefendData,
        domain_types::connector_types::DisputeResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::DefendDispute, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::DisputeDefendData, domain_types::connector_types::DisputeResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::RSync,
        domain_types::connector_types::RefundFlowData,
        domain_types::connector_types::RefundSyncData,
        domain_types::connector_types::RefundsResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::RSync, domain_types::connector_types::RefundFlowData, domain_types::connector_types::RefundSyncData, domain_types::connector_types::RefundsResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> 
    interfaces::verification::SourceVerification<
        domain_types::connector_flow::Accept,
        domain_types::connector_types::DisputeFlowData,
        domain_types::connector_types::AcceptDisputeData,
        domain_types::connector_types::DisputeResponseData,
    > for Paytmv2<T>
{
    fn get_secrets(
        &self,
        _secrets: interfaces::verification::ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(common_utils::crypto::NoAlgorithm))
    }

    fn get_signature(
        &self,
        _payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(Vec::new())
    }

    fn get_message(
        &self,
        payload: &[u8],
        _router_data: &domain_types::router_data_v2::RouterDataV2<domain_types::connector_flow::Accept, domain_types::connector_types::DisputeFlowData, domain_types::connector_types::AcceptDisputeData, domain_types::connector_types::DisputeResponseData>,
        _secrets: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(payload.to_owned())
    }
}