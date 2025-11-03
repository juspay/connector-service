pub mod constants;
pub mod test;
pub mod transformers;

use std::marker::PhantomData;

use common_enums::{AttemptStatus, PaymentMethodType};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::RequestContent,
    types::StringMinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, PSync, RSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData, RefundSyncData, RefundsResponseData,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::Response,
    types::Connectors,
};
use error_stack::ResultExt;
use hyperswitch_masking::{Mask, Maskable, PeekInterface, Secret};
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
    connector_types,
    events::connector_api_logs::ConnectorEvent,
    verification::{ConnectorSourceVerificationSecrets, SourceVerification},
};
use serde::Serialize;

use self::transformers as easebuzz;
use super::macros;
use crate::{types::ResponseRouterData, with_error_response_body};

#[derive(Debug, Clone)]
pub struct EaseBuzz<T> {
    amount_converter: &'static (dyn AmountConverterTrait<Output = String> + Sync),
    connector_name: &'static str,
    payment_method_data: PhantomData<T>,
}

impl<T> ConnectorCommon for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn base_url(&self) -> &'static str {
        constants::get_base_url()
    }

    fn build_error_response(
        &self,
        res: Response,
        code: &str,
        message: &str,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        Ok(ErrorResponse {
            error_code: code.to_string(),
            error_message: message.to_string(),
            status_code: res.status_code,
            reason: None,
            retry: None,
        })
    }
}

impl<T> SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData> for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn verify_source_verification_data(
        &self,
        _request: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        _verification_data: &ConnectorSourceVerificationSecrets,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> SourceVerification<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn verify_source_verification_data(
        &self,
        _request: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        _verification_data: &ConnectorSourceVerificationSecrets,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> SourceVerification<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData> for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn verify_source_verification_data(
        &self,
        _request: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        _verification_data: &ConnectorSourceVerificationSecrets,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(true)
    }
}

impl<T> ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        Ok(auth.into_iter().map(|(k, v)| (k, v.mask_into())).collect())
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let endpoint = if req.request.payment_method_type == PaymentMethodType::Upi {
            constants::EaseBuzzEndpoints::EasebuzSeamlessTransaction
        } else {
            constants::EaseBuzzEndpoints::EaseBuzInitiatePayment
        };
        let base_url = self.base_url();
        let endpoint_url = constants::get_endpoint(endpoint, req.resource_common_data.test_mode.unwrap_or(false));
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzPaymentsRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(easebuzz_req)))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        res: Response,
    ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzPaymentsResponse = res
            .response
            .parse_struct("EaseBuzzPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let status = self.get_status(response.status, response.error_desc.as_deref());
        
        Ok(RouterDataV2 {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(response.data),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: res.status_code,
            }),
            ..req.clone()
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        Ok(auth.into_iter().map(|(k, v)| (k, v.mask_into())).collect())
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url();
        let endpoint_url = constants::get_endpoint(
            constants::EaseBuzzEndpoints::EasebuzTxnSync,
            req.resource_common_data.test_mode.unwrap_or(false),
        );
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzPaymentsSyncRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(easebuzz_req)))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        res: Response,
    ) -> CustomResult<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzPaymentsSyncResponse = res
            .response
            .parse_struct("EaseBuzzPaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let status = if response.status {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };
        
        Ok(RouterDataV2 {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: req.request.connector_transaction_id.clone(),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: res.status_code,
            }),
            ..req.clone()
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> ConnectorIntegrationV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>
    for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn get_headers(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = easebuzz::get_auth_header(&req.connector_auth_type)?;
        Ok(auth.into_iter().map(|(k, v)| (k, v.mask_into())).collect())
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url();
        let endpoint_url = constants::get_endpoint(
            constants::EaseBuzzEndpoints::EaseBuzRefundSync,
            req.resource_common_data.test_mode.unwrap_or(false),
        );
        Ok(format!("{}{}", base_url, endpoint_url))
    }

    fn get_request_body(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
    ) -> CustomResult<Option<RequestContent>, errors::ConnectorError> {
        let easebuzz_req = easebuzz::EaseBuzzRefundSyncRequest::try_from(req)?;
        Ok(Some(RequestContent::FormUrlEncoded(easebuzz_req)))
    }

    fn handle_response_v2(
        &self,
        req: &RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>,
        res: Response,
    ) -> CustomResult<RouterDataV2<RSync, PaymentFlowData, RefundSyncData, RefundsResponseData>, errors::ConnectorError> {
        let response: easebuzz::EaseBuzzRefundSyncResponseWrapper = res
            .response
            .parse_struct("EaseBuzzRefundSyncResponseWrapper")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        
        let (status, refund_status) = match response.response {
            easebuzz::EaseBuzzRefundSyncResponse::Success(resp) => {
                (common_enums::RefundStatus::Success, Some(resp.refunds.as_ref().and_then(|r| r.first().map(|ref_| ref_.refund_status.clone())).unwrap_or_default()))
            }
            easebuzz::EaseBuzzRefundSyncResponse::Failure(_) => {
                (common_enums::RefundStatus::Failure, None)
            }
            easebuzz::EaseBuzzRefundSyncResponse::ValidationError(_) => {
                (common_enums::RefundStatus::Failure, None)
            }
        };
        
        Ok(RouterDataV2 {
            response: Ok(RefundsResponseData {
                connector_refund_id: response.response.get_connector_refund_id().unwrap_or_default(),
                refund_status: status,
                status_code: res.status_code,
            }),
            ..req.clone()
        })
    }

    fn get_error_response_v2(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, "401", "Unauthorized")
    }
}

impl<T> EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    pub fn new() -> Self {
        Self {
            amount_converter: &StringMinorUnit,
            connector_name: "easebuzz",
            payment_method_data: PhantomData,
        }
    }

    fn get_status(&self, status: i32, error_desc: Option<&str>) -> AttemptStatus {
        match status {
            1 => AttemptStatus::AuthenticationPending,
            0 => match error_desc {
                Some("pending") => AttemptStatus::Pending,
                Some(_) => AttemptStatus::Failure,
                None => AttemptStatus::Failure,
            },
            _ => AttemptStatus::Failure,
        }
    }
}

impl<T> Default for EaseBuzz<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + serde::Serialize,
{
    fn default() -> Self {
        Self::new()
    }
}

// Mock trait for compilation
pub trait AmountConverterTrait<Output> {
    fn convert(&self, amount: i64, currency: common_enums::Currency) -> CustomResult<Output, errors::ConnectorError>;
}

impl AmountConverterTrait<String> for StringMinorUnit {
    fn convert(&self, amount: i64, _currency: common_enums::Currency) -> CustomResult<String, errors::ConnectorError> {
        Ok(amount.to_string())
    }
}