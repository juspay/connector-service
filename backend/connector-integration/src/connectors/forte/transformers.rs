use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    request::Method,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{self, Authorize, PSync, RSync, RepeatPayment, SetupMandate, Void, Capture},
    connector_types::{
        MandateReference, MandateReferenceId, PaymentFlowData, PaymentVoidData,
        PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData,
        RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData as WalletDataPaymentMethod,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
    utils,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, Secret, PeekInterface};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::{connectors::forte::ForteRouterData, types::ResponseRouterData};

// Auth type structure
#[derive(Debug, Clone)]
pub struct ForteAuthType {
    pub(super) organization_id: Secret<String>,
    pub(super) location_id: Secret<String>,
    pub(super) api_access_id: Secret<String>,
    pub(super) secure_key: Secret<String>,
}

// Authorize flow structures
#[derive(Debug, Serialize)]
pub struct FortePaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub action: String,
    pub authorization_amount: MinorUnit,
    pub card: ForteCard<T>,
    pub billing_address: ForteBillingAddress,
}

#[derive(Debug, Serialize)]
pub struct ForteCard<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    pub card_number: RawCardNumber<T>,
    pub expire_month: Secret<String>,
    pub expire_year: Secret<String>,
    pub card_verification_value: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct ForteBillingAddress {
    pub first_name: Secret<String>,
    pub last_name: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FortePaymentsResponse {
    pub transaction_id: String,
    pub response: ForteResponseDetails,
    pub authorization_amount: Option<MinorUnit>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteResponseDetails {
    pub response_code: String,
    pub response_desc: String,
    pub authorization_code: Option<String>,
}

// PSync flow structures
#[derive(Debug, Serialize, Default)]
pub struct ForteSyncRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

// Alias for compatibility
pub type FortePSyncRequest<T> = ForteSyncRequest<T>;

#[derive(Debug, Deserialize, Serialize)]
pub struct FortePaymentsSyncResponse {
    pub transaction_id: String,
    pub response: ForteResponseDetails,
    pub authorization_amount: Option<MinorUnit>,
}

// Refund flow structures
#[derive(Debug, Serialize)]
pub struct ForteRefundRequest {
    pub action: String,
    pub authorization_amount: MinorUnit,
    pub original_transaction_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefundResponse {
    pub transaction_id: String,
    pub response: ForteResponseDetails,
    pub authorization_amount: Option<MinorUnit>,
}

// RSync flow structures
#[derive(Debug, Serialize, Default)]
pub struct ForteRSyncRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefundSyncResponse {
    pub transaction_id: String,
    pub response: ForteResponseDetails,
    pub authorization_amount: Option<MinorUnit>,
}

// Capture flow structures
#[derive(Debug, Serialize)]
pub struct ForteCaptureRequest {
    pub action: String,
    pub authorization_amount: MinorUnit,
    pub original_transaction_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteCaptureResponse {
    pub transaction_id: String,
    pub response: ForteResponseDetails,
    pub authorization_amount: Option<MinorUnit>,
}

// Void flow structures
#[derive(Debug, Serialize)]
pub struct ForteCancelRequest {
    pub action: String,
    pub original_transaction_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForteCancelResponse {
    pub transaction_id: String,
    pub response: ForteResponseDetails,
}

// Error response structure
#[derive(Debug, Deserialize, Serialize)]
pub struct ForteErrorResponse {
    pub error_code: String,
    pub error_message: String,
    pub error_reason: Option<String>,
}

// Auth type conversion
impl TryFrom<&ConnectorAuthType> for ForteAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                organization_id: api_key.to_owned(),
                location_id: key1.to_owned(),
                api_access_id: api_secret.to_owned(),
                secure_key: key2.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Authorize request conversion
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ForteRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for FortePaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ForteRouterData<
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

        // Get card details from payment method data
        let card_details = match router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported by Forte".to_string(),
            )),
        }?;

        // Create card structure
        let card = ForteCard {
            card_number: card_details.card_number.clone(),
            expire_month: card_details.card_exp_month.clone(),
            expire_year: card_details.card_exp_year.clone(),
            card_verification_value: card_details.card_cvc,
        };

        // Create billing address
        let billing_address = ForteBillingAddress {
            first_name: router_data.get_billing_first_name()?,
            last_name: router_data.get_billing_last_name()?,
        };

        Ok(Self {
            action: "sale".to_string(),
            authorization_amount: router_data.request.minor_amount,
            card,
            billing_address,
        })
    }
}