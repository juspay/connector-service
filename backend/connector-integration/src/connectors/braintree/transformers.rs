use domain_types::{
    connector_flow::{Authorize, Capture},
    connector_types::{
        MandateReference, PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
};

use crate::connectors::braintree::BraintreeRouterData;
use crate::types::ResponseRouterData;
use common_utils::{
    pii,
    ext_traits::ValueExt,
    errors::ReportSwitchExt,
    request::Method,
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use error_stack::ResultExt;

use domain_types::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse, PaymentMethodToken},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};

use std::collections::HashMap;

use domain_types::errors::{self, ConnectorError};

use common_utils::consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE};

use common_enums::{Currency, AttemptStatus};

use cards::CardNumber;

use serde::{Deserialize, Serialize};

use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};

pub const CHANNEL_CODE: &str = "HyperSwitchBT_Ecom";
pub const CLIENT_TOKEN_MUTATION: &str = "mutation createClientToken($input: CreateClientTokenInput!) { createClientToken(input: $input) { clientToken}}";
pub const TOKENIZE_CREDIT_CARD: &str = "mutation  tokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { clientMutationId paymentMethod { id } } }";
pub const CHARGE_CREDIT_CARD_MUTATION: &str = "mutation ChargeCreditCard($input: ChargeCreditCardInput!) { chargeCreditCard(input: $input) { transaction { id legacyId createdAt amount { value currencyCode } status } } }";
pub const AUTHORIZE_CREDIT_CARD_MUTATION: &str = "mutation authorizeCreditCard($input: AuthorizeCreditCardInput!) { authorizeCreditCard(input: $input) {  transaction { id legacyId amount { value currencyCode } status } } }";
pub const CAPTURE_TRANSACTION_MUTATION: &str = "mutation captureTransaction($input: CaptureTransactionInput!) { captureTransaction(input: $input) { clientMutationId transaction { id legacyId amount { value currencyCode } status } } }";
pub const VOID_TRANSACTION_MUTATION: &str = "mutation voidTransaction($input:  ReverseTransactionInput!) { reverseTransaction(input: $input) { clientMutationId reversal { ...  on Transaction { id legacyId amount { value currencyCode } status } } } }";
pub const REFUND_TRANSACTION_MUTATION: &str = "mutation refundTransaction($input:  RefundTransactionInput!) { refundTransaction(input: $input) {clientMutationId refund { id legacyId amount { value currencyCode } status } } }";
pub const AUTHORIZE_AND_VAULT_CREDIT_CARD_MUTATION: &str="mutation authorizeCreditCard($input: AuthorizeCreditCardInput!) { authorizeCreditCard(input: $input) { transaction { id status createdAt paymentMethod { id } } } }";
pub const CHARGE_AND_VAULT_TRANSACTION_MUTATION: &str ="mutation ChargeCreditCard($input: ChargeCreditCardInput!) { chargeCreditCard(input: $input) { transaction { id status createdAt paymentMethod { id } } } }";
pub const DELETE_PAYMENT_METHOD_FROM_VAULT_MUTATION: &str = "mutation deletePaymentMethodFromVault($input: DeletePaymentMethodFromVaultInput!) { deletePaymentMethodFromVault(input: $input) { clientMutationId } }";
pub const TRANSACTION_QUERY: &str = "query($input: TransactionSearchInput!) { search { transactions(input: $input) { edges { node { id status } } } } }";
pub const REFUND_QUERY: &str = "query($input: RefundSearchInput!) { search { refunds(input: $input, first: 1) { edges { node { id status createdAt amount { value currencyCode } orderId } } } } }";

pub type CardPaymentRequest = GenericBraintreeRequest<VariablePaymentInput>;
pub type MandatePaymentRequest = GenericBraintreeRequest<VariablePaymentInput>;
pub type BraintreeClientTokenRequest = GenericBraintreeRequest<VariableClientTokenInput>;
pub type BraintreeTokenRequest = GenericBraintreeRequest<VariableInput>;
pub type BraintreeCaptureRequest = GenericBraintreeRequest<VariableCaptureInput>;
pub type BraintreeRefundRequest = GenericBraintreeRequest<BraintreeRefundVariables>;
pub type BraintreePSyncRequest = GenericBraintreeRequest<PSyncInput>;
pub type BraintreeRSyncRequest = GenericBraintreeRequest<RSyncInput>;

pub type BraintreeRefundResponse = GenericBraintreeResponse<RefundResponse>;
pub type BraintreeCaptureResponse = GenericBraintreeResponse<CaptureResponse>;
pub type BraintreePSyncResponse = GenericBraintreeResponse<PSyncResponse>;

pub type VariablePaymentInput = GenericVariableInput<PaymentInput>;
pub type VariableClientTokenInput = GenericVariableInput<InputClientTokenData>;
pub type VariableInput = GenericVariableInput<InputData>;
pub type VariableCaptureInput = GenericVariableInput<CaptureInputData>;
pub type BraintreeRefundVariables = GenericVariableInput<BraintreeRefundInput>;
pub type PSyncInput = GenericVariableInput<TransactionSearchInput>;
pub type RSyncInput = GenericVariableInput<RefundSearchInput>;

#[derive(Debug, Clone, Serialize)]
pub struct GenericBraintreeRequest<T> {
    query: String,
    variables: T,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum GenericBraintreeResponse<T> {
    SuccessResponse(Box<T>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}
#[derive(Debug, Clone, Serialize)]
pub struct GenericVariableInput<T> {
    input: T,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BraintreeApiErrorResponse {
    pub api_error_response: ApiErrorResponse,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorsObject {
    pub errors: Vec<ErrorObject>,

    pub transaction: Option<TransactionError>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionError {
    pub errors: Vec<ErrorObject>,
    pub credit_card: Option<CreditCardError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreditCardError {
    pub errors: Vec<ErrorObject>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorObject {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BraintreeErrorResponse {
    pub errors: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum ErrorResponses {
    BraintreeApiErrorResponse(Box<BraintreeApiErrorResponse>),
    BraintreeErrorResponse(Box<BraintreeErrorResponse>),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiErrorResponse {
    pub message: String,
    pub errors: ErrorsObject,
}

pub struct BraintreeAuthType {
    pub(super) public_key: Secret<String>,
    pub(super) private_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BraintreeAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::SignatureKey {
            api_key,
            api_secret,
            key1: _merchant_id,
        } = item
        {
            Ok(Self {
                public_key: api_key.to_owned(),
                private_key: api_secret.to_owned(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType)?
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInput {
    payment_method_id: Secret<String>,
    transaction: TransactionBody,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum BraintreePaymentsRequest {
    Card(CardPaymentRequest),
    CardThreeDs(BraintreeClientTokenRequest),
    Mandate(MandatePaymentRequest),
}

#[derive(Debug, Deserialize)]
pub struct BraintreeMeta {
    merchant_account_id: Secret<String>,
    merchant_config_currency: common_enums::Currency,
}

impl TryFrom<&Option<pii::SecretSerdeValue>> for BraintreeMeta {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<pii::SecretSerdeValue>) -> Result<Self, Self::Error> {
        let metadata: Self = to_connector_meta_from_secret::<Self>(meta_data.clone())
            .change_context(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata",
            })?;
        Ok(metadata)
    }
}

use serde_json::Value;
pub(crate) fn to_connector_meta_from_secret<T>(
    connector_meta: Option<Secret<Value>>,
) -> Result<T, error_stack::Report<errors::ConnectorError>>
where
    T: serde::de::DeserializeOwned,
{
    let connector_meta_secret =
        connector_meta.ok_or_else(missing_field_err("connector_meta_data"))?;
    let json = connector_meta_secret.expose();
    json.parse_value(std::any::type_name::<T>()).switch()
}
pub(crate) fn missing_field_err(
    message: &'static str,
) -> Box<dyn Fn() -> error_stack::Report<errors::ConnectorError> + 'static> {
    Box::new(move || {
        errors::ConnectorError::MissingRequiredField {
            field_name: message,
        }
        .into()
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerBody {
    email: pii::Email,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegularTransactionBody {
    amount: StringMajorUnit,
    merchant_account_id: Secret<String>,
    channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer_details: Option<CustomerBody>,
    order_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultTransactionBody {
    amount: StringMajorUnit,
    merchant_account_id: Secret<String>,
    vault_payment_method_after_transacting: TransactionTiming,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer_details: Option<CustomerBody>,
    order_id: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum TransactionBody {
    Regular(RegularTransactionBody),
    Vault(VaultTransactionBody),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionTiming {
    when: String,
}

impl
    TryFrom<
        BraintreeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    > for BraintreePaymentsRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: BraintreeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let metadata: BraintreeMeta = if let (
            Some(merchant_account_id),
            Some(merchant_config_currency),
        ) = (
            item.router_data.request.merchant_account_id.clone(),
            item.router_data.request.merchant_config_currency,
        ) {

            BraintreeMeta {
                merchant_account_id: Secret::new(merchant_account_id),
                merchant_config_currency,
            }
        } else {
            to_connector_meta_from_secret(item.router_data.resource_common_data.connector_meta_data.clone())
                .change_context(errors::ConnectorError::InvalidConnectorConfig {
                    config: "metadata",
                })?
        };
        validate_currency(
            item.router_data.request.currency,
            Some(metadata.merchant_config_currency),
        )?;
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(_) => {
                if item.router_data.request.enrolled_for_3ds {
                    Ok(Self::CardThreeDs(BraintreeClientTokenRequest::try_from(
                        metadata,
                    )?))
                } else {
                    Ok(Self::Card(CardPaymentRequest::try_from((item, metadata))?))
                }
            }
            PaymentMethodData::MandatePayment
            | PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    "Selected payment method through braintree".to_string()),
                )?
            }
        }
    }
}

pub(crate) fn validate_currency(
    request_currency: common_enums::Currency,
    merchant_config_currency: Option<common_enums::Currency>,
) -> Result<(), errors::ConnectorError> {
    let merchant_config_currency =
        merchant_config_currency.ok_or(errors::ConnectorError::NoConnectorMetaData)?;
    if request_currency != merchant_config_currency {
        Err(errors::ConnectorError::NotSupported {
            message: format!(
                "currency {request_currency} is not supported for this merchant account",
            ),
            connector: "Braintree",
        })?
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthResponse {
    data: DataAuthResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreeAuthResponse {
    AuthResponse(Box<AuthResponse>),
    ClientTokenResponse(Box<ClientTokenResponse>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreeCompleteAuthResponse {
    AuthResponse(Box<AuthResponse>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PaymentMethodInfo {
    id: Secret<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionAuthChargeResponseBody {
    id: String,
    status: BraintreePaymentStatus,
    payment_method: Option<PaymentMethodInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataAuthResponse {
    authorize_credit_card: AuthChargeCreditCard,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthChargeCreditCard {
    transaction: TransactionAuthChargeResponseBody,
}

impl<F> TryFrom<ResponseRouterData<BraintreePaymentResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BraintreePaymentResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        match router_data.request.capture_method {
            Some(common_enums::CaptureMethod::Automatic) => {
                match response {
                    BraintreePaymentResponse::BraintreePaymentsResponse(inner) => {
                        match inner {
                            BraintreePaymentsResponse::ErrorResponse(error_response) => Ok(Self {
                                response: build_error_response(&error_response.errors.clone(), item.http_code)
                                    .map_err(|err| *err),
                                ..router_data
                            }),
                            BraintreePaymentsResponse::PaymentsResponse(payment_response) => {
                                let transaction_data = payment_response.data.charge_credit_card.transaction;
                                let status = common_enums::AttemptStatus::from(transaction_data.status.clone());
                                let response = if is_payment_failure(status) {
                                    Err(ErrorResponse {
                                        code: transaction_data.status.to_string().clone(),
                                        message: transaction_data.status.to_string().clone(),
                                        reason: Some(transaction_data.status.to_string().clone()),
                                        attempt_status: None,
                                        connector_transaction_id: Some(transaction_data.id),
                                        status_code: item.http_code,
                                        network_advice_code: None,
                                        network_decline_code: None,
                                        network_error_message: None,
                                    })
                                } else {
                                    Ok(PaymentsResponseData::TransactionResponse {
                                        resource_id: ResponseId::ConnectorTransactionId(transaction_data.id),
                                        redirection_data: Box::new(None),
                                        mandate_reference: Box::new(transaction_data.payment_method.as_ref().map(
                                            |pm| MandateReference {
                                                connector_mandate_id: Some(pm.id.clone().expose()),
                                                payment_method_id: None,
                                            },
                                        )),
                                        connector_metadata: None,
                                        network_txn_id: None,
                                        connector_response_reference_id: None,
                                        incremental_authorization_allowed: None,
                                        raw_connector_response: None,
                                    })
                                };
                                Ok(Self {
                                    response,
                                    resource_common_data: PaymentFlowData {
                                        status,
                                        ..router_data.resource_common_data
                                    },
                                    ..router_data
                                })
                            }
                            BraintreePaymentsResponse::ClientTokenResponse(client_token_data) => Ok(Self {                             
                                response: Ok(PaymentsResponseData::TransactionResponse {
                                    resource_id: ResponseId::NoResponseId,
                                    redirection_data: Box::new(Some(get_braintree_redirect_form(
                                        *client_token_data,
                                        router_data.resource_common_data.payment_method_token.clone()
                                        .ok_or_else(missing_field_err("payment_method_token"))?,
                                        router_data.request.payment_method_data.clone(),
                                        router_data.request.get_complete_authorize_url()?,
                                    )?)),
                                    mandate_reference: Box::new(None),
                                    connector_metadata: None,
                                    network_txn_id: None,
                                    connector_response_reference_id: None,
                                    incremental_authorization_allowed: None,
                                    raw_connector_response: None,
                                }),
                                resource_common_data: PaymentFlowData {
                                    status: common_enums::AttemptStatus::AuthenticationPending,
                                    ..router_data.resource_common_data
                                },  
                                ..router_data
                            }),
                        }
                    },
                    _ => Err(ConnectorError::ResponseDeserializationFailed)?
                }
            }
            Some(common_enums::CaptureMethod::Manual) => {
                match response {
                    BraintreePaymentResponse::BraintreeAuthResponse(inner) => {
                        match inner {
                            BraintreeAuthResponse::ErrorResponse(error_response) => Ok(Self {
                                response: build_error_response(&error_response.errors, item.http_code)
                                    .map_err(|err| *err),
                                ..router_data
                            }),
                            BraintreeAuthResponse::AuthResponse(auth_response) => {
                                let transaction_data = auth_response.data.authorize_credit_card.transaction;
                                let status = common_enums::AttemptStatus::from(transaction_data.status.clone());
                                let response = if is_payment_failure(status) {
                                    Err(ErrorResponse {
                                        code: transaction_data.status.to_string().clone(),
                                        message: transaction_data.status.to_string().clone(),
                                        reason: Some(transaction_data.status.to_string().clone()),
                                        attempt_status: None,
                                        connector_transaction_id: Some(transaction_data.id),
                                        status_code: item.http_code,
                                        network_advice_code: None,
                                        network_decline_code: None,
                                        network_error_message: None,
                                    })
                                } else {
                                    Ok(PaymentsResponseData::TransactionResponse {
                                        resource_id: ResponseId::ConnectorTransactionId(transaction_data.id),
                                        redirection_data: Box::new(None),
                                        mandate_reference: Box::new(transaction_data.payment_method.as_ref().map(
                                            |pm| MandateReference {
                                                connector_mandate_id: Some(pm.id.clone().expose()),
                                                payment_method_id: None,
                                            },
                                        )),
                                        connector_metadata: None,
                                        network_txn_id: None,
                                        connector_response_reference_id: None,
                                        incremental_authorization_allowed: None,
                                        raw_connector_response: None,
                                    })
                                };
                                Ok(Self {
                                    response,
                                    resource_common_data: PaymentFlowData {
                                        status,
                                        ..router_data.resource_common_data
                                    },
                                    ..router_data
                                })
                            }
                            BraintreeAuthResponse::ClientTokenResponse(client_token_data) => Ok(Self {
                                response: Ok(PaymentsResponseData::TransactionResponse {
                                    resource_id: ResponseId::NoResponseId,
                                    redirection_data: Box::new(Some(get_braintree_redirect_form(
                                        *client_token_data,
                                        router_data.resource_common_data.payment_method_token.clone()
                                        .ok_or_else(missing_field_err("payment_method_token"))?,
                                        router_data.request.payment_method_data.clone(),
                                        router_data.request.get_complete_authorize_url()?,
                                    )?)),
                                    mandate_reference: Box::new(None),
                                    connector_metadata: None,
                                    network_txn_id: None,
                                    connector_response_reference_id: None,
                                    incremental_authorization_allowed: None,
                                    raw_connector_response: None,
                                }),
                                resource_common_data: PaymentFlowData {
                                    status: common_enums::AttemptStatus::AuthenticationPending,
                                    ..router_data.resource_common_data
                                }, 
                                ..router_data
                            }),
                        }
                    },
                    _ => Err(ConnectorError::ResponseDeserializationFailed)?
                }
            }
            _ => {
                Err(ConnectorError::ResponseDeserializationFailed)?
            }
        }
    }
}

fn build_error_response<T>(
    response: &[ErrorDetails],
    http_code: u16,
) -> Result<T, Box<ErrorResponse>> {
    let error_messages = response
        .iter()
        .map(|error| error.message.to_string())
        .collect::<Vec<String>>();

    let reason = match !error_messages.is_empty() {
        true => Some(error_messages.join(" ")),
        false => None,
    };

    get_error_response(
        response
            .first()
            .and_then(|err_details| err_details.extensions.as_ref())
            .and_then(|extensions| extensions.legacy_code.clone()),
        response
            .first()
            .map(|err_details| err_details.message.clone()),
        reason,
        http_code,
    )
}

fn get_error_response<T>(
    error_code: Option<String>,
    error_msg: Option<String>,
    error_reason: Option<String>,
    http_code: u16,
) -> Result<T, Box<ErrorResponse>> {
    Err(Box::new(
        ErrorResponse {
            code: error_code.unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: error_msg.unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: error_reason,
            status_code: http_code,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        },
    ))
}

#[derive(Debug, Clone, Deserialize, Serialize, strum::Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BraintreePaymentStatus {
    Authorized,
    Authorizing,
    AuthorizedExpired,
    Failed,
    ProcessorDeclined,
    GatewayRejected,
    Voided,
    Settling,
    Settled,
    SettlementPending,
    SettlementDeclined,
    SettlementConfirmed,
    SubmittedForSettlement,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorDetails {
    pub message: String,
    pub extensions: Option<AdditionalErrorDetails>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionalErrorDetails {
    pub legacy_code: Option<String>,
}

impl From<BraintreePaymentStatus> for common_enums::AttemptStatus {
    fn from(item: BraintreePaymentStatus) -> Self {
        match item {
            BraintreePaymentStatus::Settling
            | BraintreePaymentStatus::Settled
            | BraintreePaymentStatus::SettlementConfirmed
            | BraintreePaymentStatus::SubmittedForSettlement
            | BraintreePaymentStatus::SettlementPending => Self::Charged,
            BraintreePaymentStatus::Authorizing => Self::Authorizing,
            BraintreePaymentStatus::AuthorizedExpired => Self::AuthorizationFailed,
            BraintreePaymentStatus::Failed
            | BraintreePaymentStatus::GatewayRejected
            | BraintreePaymentStatus::ProcessorDeclined
            | BraintreePaymentStatus::SettlementDeclined => Self::Failure,
            BraintreePaymentStatus::Authorized => Self::Authorized,
            BraintreePaymentStatus::Voided => Self::Voided,
        }
    }
}
/* 
impl<F>
    TryFrom<
        ResponseRouterData<
            F,
            BraintreePaymentsResponse,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    > for RouterData<F, PaymentsAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            F,
            BraintreePaymentsResponse,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BraintreePaymentsResponse::ErrorResponse(error_response) => Ok(Self {
                response: build_error_response(&error_response.errors.clone(), item.http_code)
                    .map_err(|err| *err),
                ..item.data
            }),
            BraintreePaymentsResponse::PaymentsResponse(payment_response) => {
                let transaction_data = payment_response.data.charge_credit_card.transaction;
                let status = common_enums::AttemptStatus::from(transaction_data.status.clone());
                let response = if utils::is_payment_failure(status) {
                    Err(ErrorResponse {
                        code: transaction_data.status.to_string().clone(),
                        message: transaction_data.status.to_string().clone(),
                        reason: Some(transaction_data.status.to_string().clone()),
                        attempt_status: None,
                        connector_transaction_id: Some(transaction_data.id),
                        status_code: item.http_code,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    })
                } else {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(transaction_data.id),
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(transaction_data.payment_method.as_ref().map(
                            |pm| MandateReference {
                                connector_mandate_id: Some(pm.id.clone().expose()),
                                payment_method_id: None,
                                mandate_metadata: None,
                                connector_mandate_request_reference_id: None,
                            },
                        )),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        charges: None,
                    })
                };
                Ok(Self {
                    status,
                    response,
                    ..item.data
                })
            }
            BraintreePaymentsResponse::ClientTokenResponse(client_token_data) => Ok(Self {
                status: common_enums::AttemptStatus::AuthenticationPending,
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::NoResponseId,
                    redirection_data: Box::new(Some(get_braintree_redirect_form(
                        *client_token_data,
                        item.data.get_payment_method_token()?,
                        item.data.request.payment_method_data.clone(),
                        item.data.request.get_complete_authorize_url()?,
                    )?)),
                    mandate_reference: Box::new(None),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    charges: None,
                }),
                ..item.data
            }),
        }
    }
}

impl<F>
    TryFrom<
        ResponseRouterData<
            F,
            BraintreeCompleteChargeResponse,
            CompleteAuthorizeData,
            PaymentsResponseData,
        >,
    > for RouterData<F, CompleteAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            F,
            BraintreeCompleteChargeResponse,
            CompleteAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BraintreeCompleteChargeResponse::ErrorResponse(error_response) => Ok(Self {
                response: build_error_response(&error_response.errors.clone(), item.http_code)
                    .map_err(|err| *err),
                ..item.data
            }),
            BraintreeCompleteChargeResponse::PaymentsResponse(payment_response) => {
                let transaction_data = payment_response.data.charge_credit_card.transaction;
                let status = common_enums::AttemptStatus::from(transaction_data.status.clone());
                let response = if utils::is_payment_failure(status) {
                    Err(ErrorResponse {
                        code: transaction_data.status.to_string().clone(),
                        message: transaction_data.status.to_string().clone(),
                        reason: Some(transaction_data.status.to_string().clone()),
                        attempt_status: None,
                        connector_transaction_id: Some(transaction_data.id),
                        status_code: item.http_code,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    })
                } else {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(transaction_data.id),
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(transaction_data.payment_method.as_ref().map(
                            |pm| MandateReference {
                                connector_mandate_id: Some(pm.id.clone().expose()),
                                payment_method_id: None,
                                mandate_metadata: None,
                                connector_mandate_request_reference_id: None,
                            },
                        )),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        charges: None,
                    })
                };
                Ok(Self {
                    status,
                    response,
                    ..item.data
                })
            }
        }
    }
}

impl<F>
    TryFrom<
        ResponseRouterData<
            F,
            BraintreeCompleteAuthResponse,
            CompleteAuthorizeData,
            PaymentsResponseData,
        >,
    > for RouterData<F, CompleteAuthorizeData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            F,
            BraintreeCompleteAuthResponse,
            CompleteAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BraintreeCompleteAuthResponse::ErrorResponse(error_response) => Ok(Self {
                response: build_error_response(&error_response.errors, item.http_code)
                    .map_err(|err| *err),
                ..item.data
            }),
            BraintreeCompleteAuthResponse::AuthResponse(auth_response) => {
                let transaction_data = auth_response.data.authorize_credit_card.transaction;
                let status = common_enums::AttemptStatus::from(transaction_data.status.clone());
                let response = if utils::is_payment_failure(status) {
                    Err(ErrorResponse {
                        code: transaction_data.status.to_string().clone(),
                        message: transaction_data.status.to_string().clone(),
                        reason: Some(transaction_data.status.to_string().clone()),
                        attempt_status: None,
                        connector_transaction_id: Some(transaction_data.id),
                        status_code: item.http_code,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    })
                } else {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(transaction_data.id),
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(transaction_data.payment_method.as_ref().map(
                            |pm| MandateReference {
                                connector_mandate_id: Some(pm.id.clone().expose()),
                                payment_method_id: None,
                                mandate_metadata: None,
                                connector_mandate_request_reference_id: None,
                            },
                        )),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        charges: None,
                    })
                };
                Ok(Self {
                    status,
                    response,
                    ..item.data
                })
            }
        }
    }
}
*/


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaymentsResponse {
    data: DataResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreePaymentsResponse {
    PaymentsResponse(Box<PaymentsResponse>),
    ClientTokenResponse(Box<ClientTokenResponse>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreePaymentResponse {
    BraintreePaymentsResponse(BraintreePaymentsResponse),
    BraintreeAuthResponse(BraintreeAuthResponse),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreeCompleteChargeResponse {
    PaymentsResponse(Box<PaymentsResponse>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataResponse {
    charge_credit_card: AuthChargeCreditCard,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundInputData {
    amount: StringMajorUnit,
    merchant_account_id: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    order_id: Option<String>,
}
#[derive(Serialize, Debug, Clone)]
struct IdFilter {
    is: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionSearchInput {
    id: IdFilter,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BraintreeRefundInput {
    transaction_id: String,
    refund: RefundInputData,
}

/* 

impl<F> TryFrom<BraintreeRouterData<&RefundsRouterData<F>>> for BraintreeRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: BraintreeRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        let metadata: BraintreeMeta = if let (
            Some(merchant_account_id),
            Some(merchant_config_currency),
        ) = (
            item.router_data.request.merchant_account_id.clone(),
            item.router_data.request.merchant_config_currency,
        ) {
            router_env::logger::info!(
                "BRAINTREE: Picking merchant_account_id and merchant_config_currency from payments request"
            );

            BraintreeMeta {
                merchant_account_id,
                merchant_config_currency,
            }
        } else {
            utils::to_connector_meta_from_secret(item.router_data.connector_meta_data.clone())
                .change_context(errors::ConnectorError::InvalidConnectorConfig {
                    config: "metadata",
                })?
        };

        utils::validate_currency(
            item.router_data.request.currency,
            Some(metadata.merchant_config_currency),
        )?;
        let query = REFUND_TRANSACTION_MUTATION.to_string();
        let variables = BraintreeRefundVariables {
            input: BraintreeRefundInput {
                transaction_id: item.router_data.request.connector_transaction_id.clone(),
                refund: RefundInputData {
                    amount: item.amount,
                    merchant_account_id: metadata.merchant_account_id,
                    order_id: item.router_data.refund_id.clone(),
                },
            },
        };
        Ok(Self { query, variables })
    }
}

*/

#[derive(Debug, Clone, Deserialize, Serialize, strum::Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BraintreeRefundStatus {
    SettlementPending,
    Settling,
    Settled,
    SubmittedForSettlement,
    Failed,
}

impl From<BraintreeRefundStatus> for common_enums::RefundStatus {
    fn from(item: BraintreeRefundStatus) -> Self {
        match item {
            BraintreeRefundStatus::Settled
            | BraintreeRefundStatus::Settling
            | BraintreeRefundStatus::SubmittedForSettlement
            | BraintreeRefundStatus::SettlementPending => Self::Success,
            BraintreeRefundStatus::Failed => Self::Failure,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BraintreeRefundTransactionBody {
    pub id: String,
    pub status: BraintreeRefundStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BraintreeRefundTransaction {
    pub refund: BraintreeRefundTransactionBody,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BraintreeRefundResponseData {
    pub refund_transaction: BraintreeRefundTransaction,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefundResponse {
    pub data: BraintreeRefundResponseData,
}
/* 
impl TryFrom<RefundsResponseRouterData<Execute, BraintreeRefundResponse>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, BraintreeRefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: match item.response {
                BraintreeRefundResponse::ErrorResponse(error_response) => {
                    build_error_response(&error_response.errors, item.http_code).map_err(|err| *err)
                }
                BraintreeRefundResponse::SuccessResponse(refund_data) => {
                    let refund_data = refund_data.data.refund_transaction.refund;
                    let refund_status = common_enums::RefundStatus::from(refund_data.status.clone());
                    if utils::is_refund_failure(refund_status) {
                        Err(ErrorResponse {
                            code: refund_data.status.to_string().clone(),
                            message: refund_data.status.to_string().clone(),
                            reason: Some(refund_data.status.to_string().clone()),
                            attempt_status: None,
                            connector_transaction_id: Some(refund_data.id),
                            status_code: item.http_code,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        })
                    } else {
                        Ok(RefundsResponseData {
                            connector_refund_id: refund_data.id.clone(),
                            refund_status,
                        })
                    }
                }
            },
            ..item.data
        })
    }
}
*/

#[derive(Debug, Clone, Serialize)]
pub struct RefundSearchInput {
    id: IdFilter,
}
/* 
impl TryFrom<&types::RefundSyncRouterData> for BraintreeRSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::RefundSyncRouterData) -> Result<Self, Self::Error> {
        let metadata: BraintreeMeta = if let (
            Some(merchant_account_id),
            Some(merchant_config_currency),
        ) = (
            item.request.merchant_account_id.clone(),
            item.request.merchant_config_currency,
        ) {
            router_env::logger::info!(
                "BRAINTREE: Picking merchant_account_id and merchant_config_currency from payments request"
            );

            BraintreeMeta {
                merchant_account_id,
                merchant_config_currency,
            }
        } else {
            utils::to_connector_meta_from_secret(item.connector_meta_data.clone()).change_context(
                errors::ConnectorError::InvalidConnectorConfig { config: "metadata" },
            )?
        };
        utils::validate_currency(
            item.request.currency,
            Some(metadata.merchant_config_currency),
        )?;
        let refund_id = item.request.get_connector_refund_id()?;
        Ok(Self {
            query: REFUND_QUERY.to_string(),
            variables: RSyncInput {
                input: RefundSearchInput {
                    id: IdFilter { is: refund_id },
                },
            },
        })
    }
}
    */

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RSyncNodeData {
    id: String,
    status: BraintreeRefundStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RSyncEdgeData {
    node: RSyncNodeData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefundData {
    edges: Vec<RSyncEdgeData>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RSyncSearchData {
    refunds: RefundData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RSyncResponseData {
    search: RSyncSearchData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RSyncResponse {
    data: RSyncResponseData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreeRSyncResponse {
    RSyncResponse(Box<RSyncResponse>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}

/* 
impl TryFrom<RefundsResponseRouterData<RSync, BraintreeRSyncResponse>>
    for RefundsRouterData<RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, BraintreeRSyncResponse>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BraintreeRSyncResponse::ErrorResponse(error_response) => Ok(Self {
                response: build_error_response(&error_response.errors, item.http_code)
                    .map_err(|err| *err),
                ..item.data
            }),
            BraintreeRSyncResponse::RSyncResponse(rsync_response) => {
                let edge_data = rsync_response
                    .data
                    .search
                    .refunds
                    .edges
                    .first()
                    .ok_or(errors::ConnectorError::MissingConnectorRefundID)?;
                let connector_refund_id = &edge_data.node.id;
                let response = Ok(RefundsResponseData {
                    connector_refund_id: connector_refund_id.to_string(),
                    refund_status: common_enums::RefundStatus::from(edge_data.node.status.clone()),
                });
                Ok(Self {
                    response,
                    ..item.data
                })
            }
        }
    }
}
    */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardData {
    number: cards::CardNumber,
    expiration_year: Secret<String>,
    expiration_month: Secret<String>,
    cvv: Secret<String>,
    cardholder_name: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientTokenInput {
    merchant_account_id: Secret<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    credit_card: CreditCardData,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputClientTokenData {
    client_token: ClientTokenInput,
}


/* 
impl TryFrom<&types::TokenizationRouterData> for BraintreeTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::TokenizationRouterData) -> Result<Self, Self::Error> {
        match item.request.payment_method_data.clone() {
            PaymentMethodData::Card(card_data) => Ok(Self {
                query: TOKENIZE_CREDIT_CARD.to_string(),
                variables: VariableInput {
                    input: InputData {
                        credit_card: CreditCardData {
                            number: card_data.card_number,
                            expiration_year: card_data.card_exp_year,
                            expiration_month: card_data.card_exp_month,
                            cvv: card_data.card_cvc,
                            cardholder_name: item
                                .get_optional_billing_full_name()
                                .unwrap_or(Secret::new("".to_string())),
                        },
                    },
                },
            }),
            PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("braintree"),
                )
                .into())
            }
        }
    }
}
    */

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenizePaymentMethodData {
    id: Secret<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenizeCreditCardData {
    payment_method: TokenizePaymentMethodData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientToken {
    client_token: Secret<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenizeCreditCard {
    tokenize_credit_card: TokenizeCreditCardData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientTokenData {
    create_client_token: ClientToken,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientTokenResponse {
    data: ClientTokenData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    data: TokenizeCreditCard,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorResponseBraintree {
    errors: Vec<ErrorDetails>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreeTokenResponse {
    TokenResponse(Box<TokenResponse>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}

/* 
impl<F, T> TryFrom<ResponseRouterData<F, BraintreeTokenResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, BraintreeTokenResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: match item.response {
                BraintreeTokenResponse::ErrorResponse(error_response) => {
                    build_error_response(error_response.errors.as_ref(), item.http_code)
                        .map_err(|err| *err)
                }

                BraintreeTokenResponse::TokenResponse(token_response) => {
                    Ok(PaymentsResponseData::TokenizationResponse {
                        token: token_response
                            .data
                            .tokenize_credit_card
                            .payment_method
                            .id
                            .expose()
                            .clone(),
                    })
                }
            },
            ..item.data
        })
    }
} */

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureTransactionBody {
    amount: StringMajorUnit,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureInputData {
    transaction_id: String,
    transaction: CaptureTransactionBody,
}

impl TryFrom<&BraintreeRouterData<&types::PaymentsCaptureRouterData>> for BraintreeCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &BraintreeRouterData<&types::PaymentsCaptureRouterData>,
    ) -> Result<Self, Self::Error> {
        let query = CAPTURE_TRANSACTION_MUTATION.to_string();
        let variables = VariableCaptureInput {
            input: CaptureInputData {
                transaction_id: item.router_data.request.connector_transaction_id.clone(),
                transaction: CaptureTransactionBody {
                    amount: item.amount.to_owned(),
                },
            },
        };
        Ok(Self { query, variables })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureResponseTransactionBody {
    id: String,
    status: BraintreePaymentStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureTransactionData {
    transaction: CaptureResponseTransactionBody,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResponseData {
    capture_transaction: CaptureTransactionData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureResponse {
    data: CaptureResponseData,
}
/*

impl TryFrom<PaymentsCaptureResponseRouterData<BraintreeCaptureResponse>>
    for types::PaymentsCaptureRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: PaymentsCaptureResponseRouterData<BraintreeCaptureResponse>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BraintreeCaptureResponse::SuccessResponse(capture_data) => {
                let transaction_data = capture_data.data.capture_transaction.transaction;
                let status = common_enums::AttemptStatus::from(transaction_data.status.clone());
                let response = if utils::is_payment_failure(status) {
                    Err(ErrorResponse {
                        code: transaction_data.status.to_string().clone(),
                        message: transaction_data.status.to_string().clone(),
                        reason: Some(transaction_data.status.to_string().clone()),
                        attempt_status: None,
                        connector_transaction_id: Some(transaction_data.id),
                        status_code: item.http_code,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    })
                } else {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(transaction_data.id),
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(None),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        charges: None,
                    })
                };
                Ok(Self {
                    status,
                    response,
                    ..item.data
                })
            }
            BraintreeCaptureResponse::ErrorResponse(error_data) => Ok(Self {
                response: build_error_response(&error_data.errors, item.http_code)
                    .map_err(|err| *err),
                ..item.data
            }),
        }
    }
}

    */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletePaymentMethodFromVaultInputData {
    payment_method_id: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct VariableDeletePaymentMethodFromVaultInput {
    input: DeletePaymentMethodFromVaultInputData,
}

#[derive(Debug, Serialize)]
pub struct BraintreeRevokeMandateRequest {
    query: String,
    variables: VariableDeletePaymentMethodFromVaultInput,
}




#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreeRevokeMandateResponse {
    RevokeMandateResponse(Box<RevokeMandateResponse>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevokeMandateResponse {
    data: DeletePaymentMethodFromVault,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletePaymentMethodFromVault {
    client_mutation_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelInputData {
    transaction_id: String,
}

#[derive(Debug, Serialize)]
pub struct VariableCancelInput {
    input: CancelInputData,
}

#[derive(Debug, Serialize)]
pub struct BraintreeCancelRequest {
    query: String,
    variables: VariableCancelInput,
}

// impl TryFrom<&types::PaymentsCancelRouterData> for BraintreeCancelRequest {
//     type Error = error_stack::Report<errors::ConnectorError>;
//     fn try_from(item: &types::PaymentsCancelRouterData) -> Result<Self, Self::Error> {
//         let query = VOID_TRANSACTION_MUTATION.to_string();
//         let variables = VariableCancelInput {
//             input: CancelInputData {
//                 transaction_id: item.request.connector_transaction_id.clone(),
//             },
//         };
//         Ok(Self { query, variables })
//     }
// }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CancelResponseTransactionBody {
    id: String,
    status: BraintreePaymentStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CancelTransactionData {
    reversal: CancelResponseTransactionBody,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelResponseData {
    reverse_transaction: CancelTransactionData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CancelResponse {
    data: CancelResponseData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BraintreeCancelResponse {
    CancelResponse(Box<CancelResponse>),
    ErrorResponse(Box<ErrorResponseBraintree>),
}

/* 

impl<F, T> TryFrom<ResponseRouterData<F, BraintreeCancelResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, BraintreeCancelResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BraintreeCancelResponse::ErrorResponse(error_response) => Ok(Self {
                response: build_error_response(&error_response.errors, item.http_code)
                    .map_err(|err| *err),
                ..item.data
            }),
            BraintreeCancelResponse::CancelResponse(void_response) => {
                let void_data = void_response.data.reverse_transaction.reversal;
                let status = common_enums::AttemptStatus::from(void_data.status.clone());
                let response = if utils::is_payment_failure(status) {
                    Err(ErrorResponse {
                        code: void_data.status.to_string().clone(),
                        message: void_data.status.to_string().clone(),
                        reason: Some(void_data.status.to_string().clone()),
                        attempt_status: None,
                        connector_transaction_id: None,
                        status_code: item.http_code,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    })
                } else {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::NoResponseId,
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(None),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        charges: None,
                    })
                };
                Ok(Self {
                    status,
                    response,
                    ..item.data
                })
            }
        }
    }
}

    */

impl TryFrom<&types::PaymentsSyncRouterData> for BraintreePSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsSyncRouterData) -> Result<Self, Self::Error> {
        let transaction_id = item
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(Self {
            query: TRANSACTION_QUERY.to_string(),
            variables: PSyncInput {
                input: TransactionSearchInput {
                    id: IdFilter { is: transaction_id },
                },
            },
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeData {
    id: String,
    status: BraintreePaymentStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EdgeData {
    node: NodeData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransactionData {
    edges: Vec<EdgeData>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchData {
    transactions: TransactionData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PSyncResponseData {
    search: SearchData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PSyncResponse {
    data: PSyncResponseData,
}

/* 
impl<F, T> TryFrom<ResponseRouterData<F, BraintreePSyncResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, BraintreePSyncResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BraintreePSyncResponse::ErrorResponse(error_response) => Ok(Self {
                response: build_error_response(&error_response.errors, item.http_code)
                    .map_err(|err| *err),
                ..item.data
            }),
            BraintreePSyncResponse::SuccessResponse(psync_response) => {
                let edge_data = psync_response
                    .data
                    .search
                    .transactions
                    .edges
                    .first()
                    .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
                let status = common_enums::AttemptStatus::from(edge_data.node.status.clone());
                let response = if utils::is_payment_failure(status) {
                    Err(ErrorResponse {
                        code: edge_data.node.status.to_string().clone(),
                        message: edge_data.node.status.to_string().clone(),
                        reason: Some(edge_data.node.status.to_string().clone()),
                        attempt_status: None,
                        connector_transaction_id: None,
                        status_code: item.http_code,
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    })
                } else {
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(edge_data.node.id.clone()),
                        redirection_data: Box::new(None),
                        mandate_reference: Box::new(None),
                        connector_metadata: None,
                        network_txn_id: None,
                        connector_response_reference_id: None,
                        incremental_authorization_allowed: None,
                        charges: None,
                    })
                };
                Ok(Self {
                    status,
                    response,
                    ..item.data
                })
            }
        }
    }
} */

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BraintreeThreeDsResponse {
    pub nonce: Secret<String>,
    pub liability_shifted: bool,
    pub liability_shift_possible: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BraintreeThreeDsErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct BraintreeRedirectionResponse {
    pub authentication_response: String,
}

impl TryFrom<BraintreeMeta> for BraintreeClientTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(metadata: BraintreeMeta) -> Result<Self, Self::Error> {
        Ok(Self {
            query: CLIENT_TOKEN_MUTATION.to_owned(),
            variables: VariableClientTokenInput {
                input: InputClientTokenData {
                    client_token: ClientTokenInput {
                        merchant_account_id: metadata.merchant_account_id,
                    },
                },
            },
        })
    }
}

impl
    TryFrom<(
        BraintreeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
        BraintreeMeta,
    )> for CardPaymentRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, metadata): (
            BraintreeRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        >,
            BraintreeMeta,
        ),
    ) -> Result<Self, Self::Error> {
        let (query, transaction_body) = if item.router_data.request.is_mandate_payment() {
            (
                match item.router_data.request.is_auto_capture()? {
                    true => CHARGE_AND_VAULT_TRANSACTION_MUTATION.to_string(),
                    false => AUTHORIZE_AND_VAULT_CREDIT_CARD_MUTATION.to_string(),
                },
                TransactionBody::Vault(VaultTransactionBody {
                    amount: item.amount.to_owned(),
                    merchant_account_id: metadata.merchant_account_id,
                    vault_payment_method_after_transacting: TransactionTiming {
                        when: "ALWAYS".to_string(),
                    },
                    customer_details: item
                        .router_data
                        .get_billing_email()
                        .ok()
                        .map(|email| CustomerBody { email }),
                    order_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                }),
            )
        } else {
            (
                match item.router_data.request.is_auto_capture()? {
                    true => CHARGE_CREDIT_CARD_MUTATION.to_string(),
                    false => AUTHORIZE_CREDIT_CARD_MUTATION.to_string(),
                },
                TransactionBody::Regular(RegularTransactionBody {
                    amount: item.amount.to_owned(),
                    merchant_account_id: metadata.merchant_account_id,
                    channel: CHANNEL_CODE.to_string(),
                    customer_details: item
                        .router_data
                        .get_billing_email()
                        .ok()
                        .map(|email| CustomerBody { email }),
                    order_id: item.router_data.resource_common_data.connector_request_reference_id.clone(),
                }),
            )
        };
        Ok(Self {
            query,
            variables: VariablePaymentInput {
                input: PaymentInput {
                    payment_method_id: match item.router_data.get_payment_method_token()? {
                        PaymentMethodToken::Token(token) => token,
                        PaymentMethodToken::ApplePayDecrypt(_) => Err(
                            unimplemented_payment_method!("Apple Pay", "Simplified", "Braintree"),
                        )?,
                        PaymentMethodToken::PazeDecrypt(_) => {
                            Err(unimplemented_payment_method!("Paze", "Braintree"))?
                        }
                        PaymentMethodToken::GooglePayDecrypt(_) => {
                            Err(unimplemented_payment_method!("Google Pay", "Braintree"))?
                        }
                    },
                    transaction: transaction_body,
                },
            },
        })
    }
}

impl TryFrom<&BraintreeRouterData<&types::PaymentsCompleteAuthorizeRouterData>>
    for CardPaymentRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &BraintreeRouterData<&types::PaymentsCompleteAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let metadata: BraintreeMeta = if let (
            Some(merchant_account_id),
            Some(merchant_config_currency),
        ) = (
            item.router_data.request.merchant_account_id.clone(),
            item.router_data.request.merchant_config_currency,
        ) {
            router_env::logger::info!(
                "BRAINTREE: Picking merchant_account_id and merchant_config_currency from payments request"
            );

            BraintreeMeta {
                merchant_account_id,
                merchant_config_currency,
            }
        } else {
            utils::to_connector_meta_from_secret(item.router_data.connector_meta_data.clone())
                .change_context(errors::ConnectorError::InvalidConnectorConfig {
                    config: "metadata",
                })?
        };
        utils::validate_currency(
            item.router_data.request.currency,
            Some(metadata.merchant_config_currency),
        )?;
        let payload_data = PaymentsCompleteAuthorizeRequestData::get_redirect_response_payload(
            &item.router_data.request,
        )?
        .expose();
        let redirection_response: BraintreeRedirectionResponse = serde_json::from_value(
            payload_data,
        )
        .change_context(errors::ConnectorError::MissingConnectorRedirectionPayload {
            field_name: "redirection_response",
        })?;
        let three_ds_data = serde_json::from_str::<BraintreeThreeDsResponse>(
            &redirection_response.authentication_response,
        )
        .change_context(errors::ConnectorError::MissingConnectorRedirectionPayload {
            field_name: "three_ds_data",
        })?;

        let (query, transaction_body) = if item.router_data.request.is_mandate_payment() {
            (
                match item.router_data.request.is_auto_capture()? {
                    true => CHARGE_AND_VAULT_TRANSACTION_MUTATION.to_string(),
                    false => AUTHORIZE_AND_VAULT_CREDIT_CARD_MUTATION.to_string(),
                },
                TransactionBody::Vault(VaultTransactionBody {
                    amount: item.amount.to_owned(),
                    merchant_account_id: metadata.merchant_account_id,
                    vault_payment_method_after_transacting: TransactionTiming {
                        when: "ALWAYS".to_string(),
                    },
                    customer_details: item
                        .router_data
                        .get_billing_email()
                        .ok()
                        .map(|email| CustomerBody { email }),
                    order_id: item.router_data.connector_request_reference_id.clone(),
                }),
            )
        } else {
            (
                match item.router_data.request.is_auto_capture()? {
                    true => CHARGE_CREDIT_CARD_MUTATION.to_string(),
                    false => AUTHORIZE_CREDIT_CARD_MUTATION.to_string(),
                },
                TransactionBody::Regular(RegularTransactionBody {
                    amount: item.amount.to_owned(),
                    merchant_account_id: metadata.merchant_account_id,
                    channel: CHANNEL_CODE.to_string(),
                    customer_details: item
                        .router_data
                        .get_billing_email()
                        .ok()
                        .map(|email| CustomerBody { email }),
                    order_id: item.router_data.connector_request_reference_id.clone(),
                }),
            )
        };
        Ok(Self {
            query,
            variables: VariablePaymentInput {
                input: PaymentInput {
                    payment_method_id: three_ds_data.nonce,
                    transaction: transaction_body,
                },
            },
        })
    }
}

fn get_braintree_redirect_form(
    client_token_data: ClientTokenResponse,
    payment_method_token: PaymentMethodToken,
    card_details: PaymentMethodData,
    complete_authorize_url: String,
) -> Result<RedirectForm, error_stack::Report<errors::ConnectorError>> {
    Ok(RedirectForm::Braintree {
        client_token: client_token_data
            .data
            .create_client_token
            .client_token
            .expose(),
        card_token: match payment_method_token {
            PaymentMethodToken::Token(token) => token.expose(),
            PaymentMethodToken::ApplePayDecrypt(_) => Err(unimplemented_payment_method!(
                "Apple Pay",
                "Simplified",
                "Braintree"
            ))?,
            PaymentMethodToken::PazeDecrypt(_) => {
                Err(unimplemented_payment_method!("Paze", "Braintree"))?
            }
            PaymentMethodToken::GooglePayDecrypt(_) => {
                Err(unimplemented_payment_method!("Google Pay", "Braintree"))?
            }
        },
        bin: match card_details {
            PaymentMethodData::Card(card_details) => card_details.card_number.get_card_isin(),
            PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_) => Err(
                errors::ConnectorError::NotImplemented("given payment method".to_owned()),
            )?,
        },
        acs_url: complete_authorize_url,
    })
}

#[derive(Debug, Deserialize)]
pub struct BraintreeWebhookResponse {
    pub bt_signature: String,
    pub bt_payload: String,
}

/*

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Notification {
    pub kind: String, // xml parse only string to fields
    pub timestamp: String,
    pub dispute: Option<BraintreeDisputeData>,
}


pub(crate) fn get_status(status: &str) -> IncomingWebhookEvent {
    match status {
        "dispute_opened" => IncomingWebhookEvent::DisputeOpened,
        "dispute_lost" => IncomingWebhookEvent::DisputeLost,
        "dispute_won" => IncomingWebhookEvent::DisputeWon,
        "dispute_accepted" | "dispute_auto_accepted" => IncomingWebhookEvent::DisputeAccepted,
        "dispute_expired" => IncomingWebhookEvent::DisputeExpired,
        "dispute_disputed" => IncomingWebhookEvent::DisputeChallenged,
        _ => IncomingWebhookEvent::EventNotSupported,
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BraintreeDisputeData {
    pub amount_disputed: MinorUnit,
    pub amount_won: Option<String>,
    pub case_number: Option<String>,
    pub chargeback_protection_level: Option<String>,
    pub currency_iso_code: common_enums::Currency,
    #[serde(default, with = "common_utils::custom_serde::iso8601::option")]
    pub created_at: Option<PrimitiveDateTime>,
    pub evidence: Option<DisputeEvidence>,
    pub id: String,
    pub kind: String, // xml parse only string to fields
    pub status: String,
    pub reason: Option<String>,
    pub reason_code: Option<String>,
    #[serde(default, with = "common_utils::custom_serde::iso8601::option")]
    pub updated_at: Option<PrimitiveDateTime>,
    #[serde(default, with = "common_utils::custom_serde::iso8601::option")]
    pub reply_by_date: Option<PrimitiveDateTime>,
    pub transaction: DisputeTransaction,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DisputeTransaction {
    pub amount: StringMajorUnit,
    pub id: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct DisputeEvidence {
    pub comment: String,
    pub id: Secret<String>,
    pub created_at: Option<PrimitiveDateTime>,
    pub url: url::Url,
}

pub(crate) fn get_dispute_stage(code: &str) -> Result<common_enums::DisputeStage, errors::ConnectorError> {
    match code {
        "CHARGEBACK" => Ok(common_enums::DisputeStage::Dispute),
        "PRE_ARBITRATION" => Ok(common_enums::DisputeStage::PreArbitration),
        "RETRIEVAL" => Ok(common_enums::DisputeStage::PreDispute),
        _ => Err(errors::ConnectorError::WebhookBodyDecodingFailed),
    }
}
*/



pub(crate) fn is_payment_failure(status: common_enums::AttemptStatus) -> bool {
    match status {
        AttemptStatus::AuthenticationFailed
        | AttemptStatus::AuthorizationFailed
        | AttemptStatus::CaptureFailed
        | AttemptStatus::VoidFailed
        | AttemptStatus::Failure 
        | AttemptStatus::Unknown => true,
        AttemptStatus::Started
        | AttemptStatus::RouterDeclined
        | AttemptStatus::AuthenticationPending
        | AttemptStatus::AuthenticationSuccessful
        | AttemptStatus::Authorized
        | AttemptStatus::Charged
        | AttemptStatus::Authorizing
        | AttemptStatus::CodInitiated
        | AttemptStatus::Voided
        | AttemptStatus::VoidInitiated
        | AttemptStatus::CaptureInitiated
        | AttemptStatus::AutoRefunded
        | AttemptStatus::PartialCharged
        | AttemptStatus::PartialChargedAndChargeable
        | AttemptStatus::Unresolved
        | AttemptStatus::Pending
        | AttemptStatus::PaymentMethodAwaited
        | AttemptStatus::ConfirmationAwaited
        | AttemptStatus::DeviceDataCollectionPending
        | AttemptStatus::IntegrityFailure => false,
    }
}