use common_enums::{self, AttemptStatus};
use common_utils::errors::CustomResult;
use domain_types::{
    errors::{self, ConnectorError},
    router_data_v2::RouterDataV2,
    connector_flow::{Authorize, PSync, Refund, RSync, Void, CreateOrder},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, RefundFlowData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    payment_method_data::PaymentMethodDataTypes,
};
use crate::types::ResponseRouterData;
use super::GigadatRouterData;
use interfaces::verification::SourceVerification;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Debug;
use std::marker::PhantomData;


#[derive(Debug, Serialize)]
pub struct GigadatAuthorizeRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    pub user_id: String,
    pub site: String,
    pub user_ip: String,
    pub currency: String,
    pub amount: i64,
    pub transaction_id: String,
    pub type_: String,
    pub sandbox: bool,
    pub name: String,
    pub email: String,
    pub mobile: String,
    _marker: PhantomData<T>,
}

#[derive(Debug, Serialize)]
pub struct GigadatPSyncRequest;

#[derive(Debug, Deserialize, Serialize)]
pub struct GigadatAuthorizeResponse {
    pub token: Option<String>,
    pub data: GigadatTransactionData,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GigadatTransactionData {
    pub transaction_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GigadatPSyncResponse {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct GigadatRSyncRequest;

#[derive(Debug, Deserialize, Serialize)]
pub struct GigadatRSyncResponse {
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct GigadatErrorResponse {
    pub err: Option<String>,
}


pub struct GigadatVoidRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatVoidResponse {
}

pub struct GigadatCreateOrderRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatCreateOrderResponse {
}

pub struct GigadatCreateSessionTokenRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatCreateSessionTokenResponse {
}

pub struct GigadatCreateAccessTokenRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatCreateAccessTokenResponse {
}

pub struct GigadatPaymentMethodTokenRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatPaymentMethodTokenResponse {
}

pub struct GigadatVoidPCRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatVoidPCResponse {
}

pub struct GigadatCaptureRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatCaptureResponse {
}

pub struct GigadatSetupMandateRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatSetupMandateResponse {
}

pub struct GigadatRepeatPaymentRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatRepeatPaymentResponse {
}

pub struct GigadatAcceptDisputeRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatAcceptDisputeResponse {
}

pub struct GigadatDisputeDefendRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatDisputeDefendResponse {
}

pub struct GigadatSubmitEvidenceRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatSubmitEvidenceResponse {
}

pub struct GigadatPreAuthenticateRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatPreAuthenticateResponse {
}

pub struct GigadatAuthenticateRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatAuthenticateResponse {
}

pub struct GigadatPostAuthenticateRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatPostAuthenticateResponse {
}

pub struct GigadatSdkSessionTokenRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    _marker: PhantomData<T>,
}

pub struct GigadatSdkSessionTokenResponse {
}

pub struct GigadatRefundRequest<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> {
    pub amount: i64,
    pub transaction_id: String,
    pub campaign_id: String,
    _marker: PhantomData<T>,
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    > for GigadatRefundRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: 0,
            transaction_id: String::new(),
            campaign_id: String::new(),
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                Void,
                PaymentFlowData,
                PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatVoidRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                Void,
                PaymentFlowData,
                PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentOrderData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatCreateOrderRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                CreateOrder,
                PaymentFlowData,
                PaymentOrderData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                CreateSessionToken,
                PaymentFlowData,
                SessionTokenRequestData,
                SessionTokenResponseData,
            >,
            T,
        >,
    > for GigadatCreateSessionTokenRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                CreateSessionToken,
                PaymentFlowData,
                SessionTokenRequestData,
                SessionTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                PaymentTokenizationData,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    > for GigadatCreateAccessTokenRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                CreateAccessToken,
                PaymentFlowData,
                PaymentTokenizationData,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    > for GigadatPaymentMethodTokenRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                VoidPC,
                PaymentFlowData,
                PaymentsCancelPostCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatVoidPCRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                VoidPC,
                PaymentFlowData,
                PaymentsCancelPostCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatCaptureRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatSetupMandateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatRepeatPaymentRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                AcceptDispute,
                DisputeFlowData,
                AcceptDisputeData,
                DisputeResponseData,
            >,
            T,
        >,
    > for GigadatAcceptDisputeRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                AcceptDispute,
                DisputeFlowData,
                AcceptDisputeData,
                DisputeResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                DisputeDefend,
                DisputeFlowData,
                DefendDisputeData,
                DisputeResponseData,
            >,
            T,
        >,
    > for GigadatDisputeDefendRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                DisputeDefend,
                DisputeFlowData,
                DefendDisputeData,
                DisputeResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                SubmitEvidence,
                DisputeFlowData,
                SubmitEvidenceData,
                DisputeResponseData,
            >,
            T,
        >,
    > for GigadatSubmitEvidenceRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                SubmitEvidence,
                DisputeFlowData,
                SubmitEvidenceData,
                DisputeResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatPreAuthenticateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                PreAuthenticate,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatAuthenticateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                Authenticate,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatPostAuthenticateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                PostAuthenticate,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                SdkSessionToken,
                PaymentFlowData,
                PaymentsSdkSessionTokenData,
                SessionTokenResponseData,
            >,
            T,
        >,
    > for GigadatSdkSessionTokenRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                SdkSessionToken,
                PaymentFlowData,
                PaymentsSdkSessionTokenData,
                SessionTokenResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: PhantomData,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GigadatRefundResponse {
    pub success: bool,
    pub data: GigadatTransactionData,
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for GigadatAuthorizeRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: GigadatRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let metadata = item
            .metadata
            .clone()
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "metadata",
            })?;
        let site = metadata
            .get("site")
            .and_then(Value::as_str)
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "metadata.site",
            })?
            .to_string();

        let amount = item
            .router_data
            .router_data
            .request
            .amount
            .to_string()
            .parse::<i64>()
            .map_err(|_| ConnectorError::InvalidDataValue {
                field_name: "amount",
            })?;

        let user_ip = item
            .router_data
            .router_data
            .request
            .browser_info
            .as_ref()
            .and_then(|info| info.ip_address.as_ref())
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "browser_info.ip_address",
            })?
            .clone();

        let name = item
            .router_data
            .router_data
            .resource_common_data
            .get_billing_full_name()
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "billing name",
            })?;

        let email = item
            .router_data
            .router_data
            .request
            .email
            .clone()
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "email",
            })?;

        let mobile = item
            .router_data
            .router_data
            .request
            .phone
            .as_ref()
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "phone",
            })?
            .to_string();

        Ok(Self {
            user_id: item.router_data.connector_customer_id.clone().unwrap_or_default(),
            site,
            user_ip,
            currency: item.router_data.request.currency.to_string(),
            amount,
            transaction_id: item.router_data.connector_transaction_id.clone().unwrap_or_default(),
            type_: "CPI".to_string(),
            sandbox: false,
            name,
            email,
            mobile,
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        ResponseRouterData<GigadatAuthorizeResponse, RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >>,
    > for RouterDataV2<
        Authorize,
        PaymentFlowData,
        PaymentsAuthorizeData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<GigadatAuthorizeResponse, RouterDataV2<
            Authorize,
            PaymentFlowData,
            PaymentsAuthorizeData<T>,
            PaymentsResponseData,
        >>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let status = if response.token.is_some() {
            AttemptStatus::AuthenticationPending
        } else {
            AttemptStatus::Failure
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    response.data.transaction_id.clone(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charge_id: None,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data.clone()
            },
            ..item.router_data
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<GigadatPSyncResponse, RouterDataV2<
            PSync,
            PaymentFlowData,
            domain_types::connector_types::PaymentsSyncData,
            PaymentsResponseData,
        >>,
    > for RouterDataV2<
        PSync,
        PaymentFlowData,
        domain_types::connector_types::PaymentsSyncData,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<GigadatPSyncResponse, RouterDataV2<
            PSync,
            PaymentFlowData,
            domain_types::connector_types::PaymentsSyncData,
            PaymentsResponseData,
        >>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let status = map_gigadat_status_to_attempt_status(&response.status);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(
                    item.router_data.connector_transaction_id.clone().unwrap_or_default(),
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charge_id: None,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data.clone()
            },
            ..item.router_data
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<GigadatRouterData<RouterDataV2<PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>, T>>
    for GigadatPSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        _item: GigadatRouterData<
            RouterDataV2<
                PSync,
                PaymentFlowData,
                domain_types::connector_types::PaymentsSyncData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        GigadatRouterData<
            RouterDataV2<
                Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    > for GigadatRefundRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: GigadatRouterData<
            RouterDataV2<
                Refund,
                RefundFlowData,
                RefundsData,
                RefundsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let campaign_id = item
            .metadata
            .clone()
            .and_then(|m| m.get("site"))
            .and_then(Value::as_str)
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "metadata.site",
            })?
            .to_string();

        Ok(Self {
            amount: item.router_data.request.refund_amount,
            transaction_id: item.router_data.connector_transaction_id.clone().unwrap_or_default(),
            campaign_id,
            _marker: PhantomData,
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    TryFrom<
        ResponseRouterData<GigadatRefundResponse, RouterDataV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        >>,
    > for RouterDataV2<
        Refund,
        RefundFlowData,
        RefundsData,
        RefundsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<GigadatRefundResponse, RouterDataV2<
            Refund,
            RefundFlowData,
            RefundsData,
            RefundsResponseData,
        >>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let status = if response.success {
            common_enums::RefundStatus::Success
        } else {
            common_enums::RefundStatus::Failure
        };

        Ok(Self {
            response: Ok(RefundsResponseData::RefundResponse {
                connector_refund_id: response.data.transaction_id,
                refund_status: status,
                connector_metadata: None,
                connector_response_reference_id: None,
                refund_error_message: None,
            }),
            ..item.router_data
        })
    }
}

pub fn map_gigadat_status_to_attempt_status(status: &str) -> common_enums::AttemptStatus {
    match status {
        "STATUS_SUCCESS" => common_enums::AttemptStatus::Charged,
        "STATUS_PENDING" | "STATUS_INITED" => common_enums::AttemptStatus::Pending,
        "STATUS_REJECTED"
        | "STATUS_EXPIRED"
        | "STATUS_ABORTED1"
        | "STATUS_FAILED" => common_enums::AttemptStatus::Failure,
        _ => common_enums::AttemptStatus::Pending,
    }
}

// BankRedirect implementation
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static> GigadatAuthorizeRequest<T> {
    pub fn is_bank_redirect(&self) -> bool {
        self.type_ == "CPI"
    }
}

// Basic SourceVerification implementations for Gigadat
impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    SourceVerification<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
    for super::Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    SourceVerification<domain_types::connector_flow::PSync, PaymentFlowData, domain_types::connector_types::PaymentsSyncData, PaymentsResponseData>
    for super::Gigadat<T>
{
}

impl<T: PaymentMethodDataTypes + Debug + Send + Sync + 'static>
    SourceVerification<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>
    for super::Gigadat<T>
{
}