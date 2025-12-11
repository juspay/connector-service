use std::collections::HashMap;

use common_enums::enums;
use common_utils::{ext_traits::ValueExt, request::Method};
use domain_types::{
    connector_flow::{Authorize, Capture, PaymentMethodToken, RSync, Refund, RepeatPayment, Void},
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentMethodTokenResponse,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, ResponseId,
    },
    errors,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::{requests, responses};
use crate::connectors::paysafe::PaysafeRouterData;
use crate::types::ResponseRouterData;

pub use super::requests::*;
pub use super::responses::*;

type ConnectorError = error_stack::Report<errors::ConnectorError>;

// Auth Type

#[derive(Debug, Clone)]
pub struct PaysafeAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PaysafeAuthType {
    type Error = ConnectorError;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                username: api_key.clone(),
                password: key1.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Connector Metadata

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct PaysafeConnectorMetadataObject {
    pub account_id: PaysafePaymentMethodDetails,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct PaysafePaymentMethodDetails {
    pub card: Option<HashMap<enums::Currency, CardAccountId>>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct CardAccountId {
    pub no_three_ds: Option<Secret<String>>,
    pub three_ds: Option<Secret<String>>,
}

impl PaysafePaymentMethodDetails {
    pub fn get_no_three_ds_account_id(
        &self,
        currency: enums::Currency,
    ) -> Result<Secret<String>, errors::ConnectorError> {
        self.card
            .as_ref()
            .and_then(|cards| cards.get(&currency))
            .and_then(|card| card.no_three_ds.clone())
            .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                config: "Missing no_3ds account_id",
            })
    }

    pub fn get_three_ds_account_id(
        &self,
        currency: enums::Currency,
    ) -> Result<Secret<String>, errors::ConnectorError> {
        self.card
            .as_ref()
            .and_then(|cards| cards.get(&currency))
            .and_then(|card| card.three_ds.clone())
            .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                config: "Missing 3ds account_id",
            })
    }
}

// Mandate Metadata

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PaysafeMandateMetadata {
    pub initial_transaction_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaysafeMeta {
    pub payment_handle_token: Secret<String>,
}

// Helper Functions

fn create_paysafe_billing_details(
    resource_common_data: &PaymentFlowData,
) -> Result<Option<requests::PaysafeBillingDetails>, ConnectorError> {
    let billing_address = resource_common_data.get_billing_address()?;
    // Only send billing details if billing mandatory fields are available
    if let (Some(zip), Some(country), Some(state)) = (
        resource_common_data.get_optional_billing_zip(),
        resource_common_data.get_optional_billing_country(),
        billing_address.to_state_code_as_optional()?,
    ) {
        Ok(Some(requests::PaysafeBillingDetails {
            nick_name: resource_common_data.get_optional_billing_first_name(),
            street: resource_common_data.get_optional_billing_line1(),
            street2: resource_common_data.get_optional_billing_line2(),
            city: resource_common_data.get_optional_billing_city(),
            zip,
            country,
            state,
        }))
    } else {
        Ok(None)
    }
}

// Status Mapping Functions

pub fn get_paysafe_payment_status(
    status: responses::PaysafePaymentStatus,
    capture_method: Option<enums::CaptureMethod>,
) -> enums::AttemptStatus {
    match status {
        responses::PaysafePaymentStatus::Completed => match capture_method {
            Some(enums::CaptureMethod::Manual) => enums::AttemptStatus::Authorized,
            Some(enums::CaptureMethod::Automatic) | None => enums::AttemptStatus::Charged,
            Some(enums::CaptureMethod::SequentialAutomatic)
            | Some(enums::CaptureMethod::ManualMultiple)
            | Some(enums::CaptureMethod::Scheduled) => enums::AttemptStatus::Unresolved,
        },
        responses::PaysafePaymentStatus::Failed => enums::AttemptStatus::Failure,
        responses::PaysafePaymentStatus::Pending | responses::PaysafePaymentStatus::Processing => {
            enums::AttemptStatus::Pending
        }
        responses::PaysafePaymentStatus::Cancelled => enums::AttemptStatus::Voided,
    }
}

impl TryFrom<responses::PaysafePaymentHandleStatus> for enums::AttemptStatus {
    type Error = ConnectorError;
    fn try_from(item: responses::PaysafePaymentHandleStatus) -> Result<Self, Self::Error> {
        match item {
            responses::PaysafePaymentHandleStatus::Completed => Ok(Self::Authorized),
            responses::PaysafePaymentHandleStatus::Failed
            | responses::PaysafePaymentHandleStatus::Expired
            | responses::PaysafePaymentHandleStatus::Error => Ok(Self::Failure),
            responses::PaysafePaymentHandleStatus::Initiated => Ok(Self::AuthenticationPending),
            responses::PaysafePaymentHandleStatus::Payable
            | responses::PaysafePaymentHandleStatus::Processing => Ok(Self::Pending),
        }
    }
}

impl From<responses::PaysafeSettlementStatus> for enums::AttemptStatus {
    fn from(item: responses::PaysafeSettlementStatus) -> Self {
        match item {
            responses::PaysafeSettlementStatus::Completed
            | responses::PaysafeSettlementStatus::Pending
            | responses::PaysafeSettlementStatus::Processing => Self::Charged,
            responses::PaysafeSettlementStatus::Failed => Self::Failure,
            responses::PaysafeSettlementStatus::Cancelled => Self::Voided,
        }
    }
}

impl From<responses::PaysafeVoidStatus> for enums::AttemptStatus {
    fn from(item: responses::PaysafeVoidStatus) -> Self {
        match item {
            responses::PaysafeVoidStatus::Completed
            | responses::PaysafeVoidStatus::Pending
            | responses::PaysafeVoidStatus::Processing => Self::Voided,
            responses::PaysafeVoidStatus::Failed => Self::Failure,
            responses::PaysafeVoidStatus::Cancelled => Self::Voided,
        }
    }
}

impl From<responses::PaysafeRefundStatus> for enums::RefundStatus {
    fn from(item: responses::PaysafeRefundStatus) -> Self {
        match item {
            responses::PaysafeRefundStatus::Completed => Self::Success,
            responses::PaysafeRefundStatus::Failed | responses::PaysafeRefundStatus::Cancelled => {
                Self::Failure
            }
            responses::PaysafeRefundStatus::Pending
            | responses::PaysafeRefundStatus::Processing => Self::Pending,
        }
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PaysafeRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    > for requests::PaysafePaymentMethodTokenRequest<T>
{
    type Error = ConnectorError;

    fn try_from(
        item: PaysafeRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let metadata: PaysafeConnectorMetadataObject = router_data
            .request
            .merchant_account_metadata
            .clone()
            .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                config: "merchant_account_metadata",
            })?
            .parse_value("PaysafeConnectorMetadataObject")
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "merchant_account_metadata",
            })?;

        let currency = router_data.request.currency;
        let amount = router_data.request.amount;
        let settle_with_auth = matches!(
            router_data.request.capture_method,
            Some(enums::CaptureMethod::Automatic) | None
        );

        // PaymentMethodToken is for no-3DS flow only
        let account_id = metadata.account_id.get_no_three_ds_account_id(currency)?;

        let payment_method = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(req_card) => {
                let card = requests::PaysafeCard {
                    card_num: req_card.card_number.clone(),
                    card_expiry: requests::PaysafeCardExpiry {
                        month: req_card.card_exp_month.clone(),
                        year: req_card.get_expiry_year_4_digit(),
                    },
                    cvv: if req_card.card_cvc.peek().is_empty() {
                        None
                    } else {
                        Some(req_card.card_cvc.clone())
                    },
                    holder_name: req_card.card_holder_name.clone().or_else(|| {
                        router_data
                            .resource_common_data
                            .get_optional_billing_full_name()
                    }),
                };
                requests::PaysafePaymentMethod::Card { card }
            }
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Only card payment methods are supported for PaymentMethodToken"
                        .to_string(),
                    connector: "Paysafe",
                }
                .into())
            }
        };

        let billing_details = create_paysafe_billing_details(&router_data.resource_common_data)?;

        // Paysafe requires return_links even for no-3DS flows
        let redirect_url = router_data.resource_common_data.get_return_url().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "return_url",
            },
        )?;

        let return_links = Some(vec![
            requests::ReturnLink {
                rel: requests::LinkType::Default,
                href: redirect_url.clone(),
                method: Method::Get.to_string(),
            },
            requests::ReturnLink {
                rel: requests::LinkType::OnCompleted,
                href: redirect_url.clone(),
                method: Method::Get.to_string(),
            },
            requests::ReturnLink {
                rel: requests::LinkType::OnFailed,
                href: redirect_url.clone(),
                method: Method::Get.to_string(),
            },
            requests::ReturnLink {
                rel: requests::LinkType::OnCancelled,
                href: redirect_url,
                method: Method::Get.to_string(),
            },
        ]);

        Ok(Self {
            merchant_ref_num: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
            settle_with_auth,
            payment_method,
            currency_code: currency,
            payment_type: requests::PaysafePaymentType::Card,
            transaction_type: requests::TransactionType::Payment,
            return_links,
            account_id,
            three_ds: None, // No 3DS for PaymentMethodToken
            profile: None,
            billing_details,
        })
    }
}

// PaymentMethodToken (No-3DS) Flow - Response

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            responses::PaysafePaymentMethodTokenResponse,
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
        >,
    >
    for RouterDataV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        PaymentMethodTokenResponse,
    >
{
    type Error = ConnectorError;

    fn try_from(
        item: ResponseRouterData<
            responses::PaysafePaymentMethodTokenResponse,
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                PaymentMethodTokenResponse,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = enums::AttemptStatus::try_from(item.response.status)?;

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;

        // Return the payment_handle_token as the payment method token
        Ok(Self {
            response: Ok(PaymentMethodTokenResponse {
                token: item.response.payment_handle_token.peek().to_string(),
            }),
            ..router_data
        })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PaysafeRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for requests::PaysafePaymentsRequest
{
    type Error = ConnectorError;

    fn try_from(
        item: PaysafeRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let amount = router_data.request.minor_amount;

        let metadata: PaysafeConnectorMetadataObject = router_data
            .request
            .merchant_account_metadata
            .clone()
            .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                config: "merchant_account_metadata",
            })?
            .parse_value("PaysafeConnectorMetadataObject")
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "merchant_account_metadata",
            })?;

        let payment_handle_token: Secret<String> = router_data
            .resource_common_data
            .payment_method_token
            .as_ref()
            .and_then(|token| match token {
                domain_types::router_data::PaymentMethodToken::Token(t) => Some(t.clone()),
                _ => None,
            })
            .or_else(|| {
                router_data
                    .resource_common_data
                    .connector_meta_data
                    .as_ref()
                    .and_then(|metadata_value| {
                        metadata_value
                            .clone()
                            .parse_value::<PaysafeMeta>("PaysafeMeta")
                            .ok()
                            .map(|meta| meta.payment_handle_token)
                    })
            })
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "payment_handle_token",
            })?;

        let customer_ip = router_data
            .request
            .get_browser_info()
            .ok()
            .and_then(|browser_info| browser_info.ip_address)
            .map(|ip| Secret::new(ip.to_string()));

        let settle_with_auth = matches!(
            router_data.request.capture_method,
            Some(enums::CaptureMethod::Automatic) | None
        );

        let account_id = Some(if router_data.resource_common_data.is_three_ds() {
            metadata
                .account_id
                .get_three_ds_account_id(router_data.request.currency)?
        } else {
            metadata
                .account_id
                .get_no_three_ds_account_id(router_data.request.currency)?
        });

        Ok(Self {
            merchant_ref_num: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            payment_handle_token,
            amount,
            settle_with_auth,
            currency_code: router_data.request.currency,
            customer_ip,
            stored_credential: None,
            account_id,
        })
    }
}

// Authorize Flow - Response

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            responses::PaysafeAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = ConnectorError;

    fn try_from(
        item: ResponseRouterData<
            responses::PaysafeAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let status = get_paysafe_payment_status(
            item.response.status,
            item.router_data.request.capture_method,
        );

        // Store payment_handle_token for mandate if present
        let mandate_reference =
            item.response
                .payment_handle_token
                .as_ref()
                .map(|token| MandateReference {
                    connector_mandate_id: Some(token.peek().to_string()),
                    payment_method_id: None,
                    connector_mandate_request_reference_id: None,
                });

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: mandate_reference.map(Box::new),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.merchant_ref_num),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..router_data
        })
    }
}

// RepeatPayment Flow - Request

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        PaysafeRouterData<
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
            T,
        >,
    > for requests::PaysafeRepeatPaymentRequest
{
    type Error = ConnectorError;

    fn try_from(
        item: PaysafeRouterData<
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;
        let amount = router_data.request.minor_amount;

        // Get mandate ID and metadata
        let (payment_handle_token, mandate_data) = match &router_data.request.mandate_reference {
            MandateReferenceId::ConnectorMandateId(mandate_data) => {
                let token = mandate_data
                    .get_connector_mandate_id()
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "connector_mandate_id",
                    })?
                    .into();
                (token, mandate_data)
            }
            MandateReferenceId::NetworkMandateId(_)
            | MandateReferenceId::NetworkTokenWithNTI(_) => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_mandate_id",
                }
                .into());
            }
        };

        let mandate_metadata: PaysafeMandateMetadata = mandate_data
            .get_mandate_metadata()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "mandate_metadata",
            })?
            .parse_value("PaysafeMandateMetadata")
            .change_context(errors::ConnectorError::ParsingFailed)?;

        let customer_ip = router_data
            .request
            .browser_info
            .as_ref()
            .and_then(|browser_info| browser_info.ip_address.as_ref())
            .map(|ip| Secret::new(ip.to_string()));

        let settle_with_auth = matches!(
            router_data.request.capture_method,
            Some(enums::CaptureMethod::Automatic) | None
        );

        // MIT (Merchant Initiated Transaction) stored credential
        let stored_credential = Some(requests::PaysafeStoredCredential {
            stored_credential_type: requests::PaysafeStoredCredentialType::Topup,
            occurrence: requests::MandateOccurrence::Subsequent,
            initial_transaction_id: Some(mandate_metadata.initial_transaction_id),
        });

        Ok(Self {
            merchant_ref_num: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            payment_handle_token,
            amount,
            settle_with_auth,
            currency_code: router_data.request.currency,
            customer_ip,
            stored_credential,
            account_id: None,
        })
    }
}

// RepeatPayment Flow - Response

impl
    TryFrom<
        ResponseRouterData<
            responses::PaysafeRepeatPaymentResponse,
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        >,
    > for RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
{
    type Error = ConnectorError;

    fn try_from(
        item: ResponseRouterData<
            responses::PaysafeRepeatPaymentResponse,
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = get_paysafe_payment_status(
            item.response.status,
            item.router_data.request.capture_method,
        );

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.merchant_ref_num),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..router_data
        })
    }
}

// PSync Flow - Response

impl
    TryFrom<
        ResponseRouterData<
            responses::PaysafeSyncResponse,
            RouterDataV2<
                domain_types::connector_flow::PSync,
                PaymentFlowData,
                domain_types::connector_types::PaymentsSyncData,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        domain_types::connector_flow::PSync,
        PaymentFlowData,
        domain_types::connector_types::PaymentsSyncData,
        PaymentsResponseData,
    >
{
    type Error = ConnectorError;

    fn try_from(
        item: ResponseRouterData<
            responses::PaysafeSyncResponse,
            RouterDataV2<
                domain_types::connector_flow::PSync,
                PaymentFlowData,
                domain_types::connector_types::PaymentsSyncData,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let (status, connector_transaction_id) = match &item.response {
            responses::PaysafeSyncResponse::SinglePayment(payment_response) => {
                let status = get_paysafe_payment_status(
                    payment_response.status,
                    item.router_data.request.capture_method,
                );
                (status, Some(payment_response.id.clone()))
            }
            responses::PaysafeSyncResponse::Payments(sync_response) => {
                let payment_response = sync_response
                    .payments
                    .first()
                    .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;
                let status = get_paysafe_payment_status(
                    payment_response.status,
                    item.router_data.request.capture_method,
                );
                (status, Some(payment_response.id.clone()))
            }
            responses::PaysafeSyncResponse::SinglePaymentHandle(payment_handle_response) => {
                let status = enums::AttemptStatus::try_from(payment_handle_response.status)?;
                (status, Some(payment_handle_response.id.clone()))
            }
            responses::PaysafeSyncResponse::PaymentHandle(sync_response) => {
                let payment_handle_response = sync_response
                    .payment_handles
                    .first()
                    .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;
                let status = enums::AttemptStatus::try_from(payment_handle_response.status)?;
                (status, Some(payment_handle_response.id.clone()))
            }
        };

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: connector_transaction_id
                    .map(ResponseId::ConnectorTransactionId)
                    .unwrap_or(ResponseId::NoResponseId),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..router_data
        })
    }
}

// Capture Flow - Request

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaysafeRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for requests::PaysafeCaptureRequest
{
    type Error = ConnectorError;

    fn try_from(
        item: PaysafeRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            merchant_ref_num: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: item.router_data.request.minor_amount_to_capture,
        })
    }
}

// Capture Flow - Response

impl
    TryFrom<
        ResponseRouterData<
            responses::PaysafeCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = ConnectorError;

    fn try_from(
        item: ResponseRouterData<
            responses::PaysafeCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = enums::AttemptStatus::from(item.response.status);

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.merchant_ref_num),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..router_data
        })
    }
}

// Void Flow - Request

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaysafeRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for requests::PaysafeVoidRequest
{
    type Error = ConnectorError;

    fn try_from(
        item: PaysafeRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item.router_data.request.amount.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "amount",
            },
        )?;
        Ok(Self {
            merchant_ref_num: item
                .router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
        })
    }
}

// Void Flow - Response

impl
    TryFrom<
        ResponseRouterData<
            responses::PaysafeVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = ConnectorError;

    fn try_from(
        item: ResponseRouterData<
            responses::PaysafeVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = enums::AttemptStatus::from(item.response.status);

        let mut router_data = item.router_data;
        router_data.resource_common_data.status = status;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.merchant_ref_num),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..router_data
        })
    }
}

// Refund Flow - Request

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        PaysafeRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for requests::PaysafeRefundRequest
{
    type Error = ConnectorError;

    fn try_from(
        item: PaysafeRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            merchant_ref_num: item.router_data.request.refund_id.clone(),
            amount: item.router_data.request.minor_refund_amount,
        })
    }
}

// Refund Flow - Response

impl
    TryFrom<
        ResponseRouterData<
            responses::PaysafeRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = ConnectorError;

    fn try_from(
        item: ResponseRouterData<
            responses::PaysafeRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status: enums::RefundStatus::from(item.response.status),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// RSync Flow - Response

impl
    TryFrom<
        ResponseRouterData<
            responses::PaysafeRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = ConnectorError;

    fn try_from(
        item: ResponseRouterData<
            responses::PaysafeRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.clone(),
                refund_status: enums::RefundStatus::from(item.response.status),
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}
