use crate::types::ResponseRouterData;
use base64::{engine::general_purpose::STANDARD, Engine};
use common_enums::AttemptStatus;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, Refund, RSync, Void},
    connector_types::{PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, PaymentVoidData, RefundFlowData, RefundsData, RefundsResponseData, RefundSyncData, ResponseId},
    errors,
    payment_method_data::{
        BankRedirectData, Card, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData,
    },
    router_data::ConnectorAuthType,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct WorldpayAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WorldpayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                username: api_key.to_owned(),
                password: key1.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

impl WorldpayAuthType {
    pub fn generate_authorization_header(&self) -> String {
        let credentials = format!("{}:{}", self.username.peek(), self.password.peek());
        let encoded_credentials = STANDARD.encode(credentials);
        format!("Basic {}", encoded_credentials)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldpayErrorResponse {
    #[serde(rename = "errorName")]
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayPaymentsRequest<T: PaymentMethodDataTypes> {
    #[serde(rename = "transactionReference")]
    pub transaction_reference: String,
    pub merchant: WorldpayMerchant,
    pub instruction: WorldpayInstruction<T>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayMerchant {
    pub entity: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayInstruction<T: PaymentMethodDataTypes> {
    pub method: String,
    #[serde(rename = "paymentInstrument")]
    pub payment_instrument: WorldpayPaymentInstrument<T>,
    pub narrative: WorldpayNarrative,
    pub value: WorldpayValue,
    #[serde(rename = "settlementCurrency", skip_serializing_if = "Option::is_none")]
    pub settlement_currency: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum WorldpayPaymentInstrument<T: PaymentMethodDataTypes> {
    Card(WorldpayCardInstrument<T>),
    Wallet(WorldpayWalletInstrument),
    BankRedirect(WorldpayBankRedirectInstrument),
    _Phantom(std::marker::PhantomData<T>),
}

#[derive(Debug, Serialize)]
pub struct WorldpayCardInstrument<T: PaymentMethodDataTypes> {
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(rename = "cardNumber")]
    pub card_number: RawCardNumber<T>,
    #[serde(rename = "cardHolderName")]
    pub card_holder_name: Option<Secret<String>>,
    #[serde(rename = "expiryDate")]
    pub expiry_date: WorldpayExpiryDate,
    pub cvc: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayWalletInstrument {
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(rename = "walletToken", skip_serializing_if = "Option::is_none")]
    pub wallet_token: Option<Secret<String>>,
    #[serde(rename = "returnUrl", skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayBankRedirectInstrument {
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(rename = "bankCode", skip_serializing_if = "Option::is_none")]
    pub bank_code: Option<String>,
    #[serde(rename = "countryCode", skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayExpiryDate {
    pub month: u8,
    pub year: u16,
}

#[derive(Debug, Serialize)]
pub struct WorldpayNarrative {
    pub line1: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayValue {
    pub amount: i64,
    pub currency: String,
}

#[derive(Debug, Serialize)]
pub struct WorldpayCaptureRequest {
    // Per WorldPay OpenAPI spec, SettleRequest is an empty object
}

#[derive(Debug, Serialize)]
pub struct WorldpayPartialCaptureRequest {
    pub reference: String,
    pub value: WorldpayValue,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayCaptureResponse {
    pub outcome: String,
    #[serde(rename = "_links")]
    pub links: Option<WorldpayCaptureLinks>,
    #[serde(rename = "_actions")]
    pub actions: Option<WorldpayCaptureActions>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayCaptureLinks {
    #[serde(rename = "self")]
    pub self_link: Option<WorldpayLink>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayCaptureActions {
    #[serde(rename = "refundPayment")]
    pub refund_payment: Option<WorldpayLink>,
    #[serde(rename = "partiallyRefundPayment")]
    pub partially_refund_payment: Option<WorldpayLink>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayPartialCaptureResponse {
    pub outcome: String,
    #[serde(rename = "_links")]
    pub links: Option<WorldpayCaptureLinks>,
    #[serde(rename = "_actions")]
    pub actions: Option<WorldpayCaptureActions>,
}

#[derive(Debug, Serialize)]
pub struct WorldpaySyncRequest {
    // Per WorldPay OpenAPI spec, GET request has no body
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpaySyncResponse {
    #[serde(rename = "lastEvent")]
    pub last_event: String,
    #[serde(rename = "_actions")]
    pub actions: Option<WorldpaySyncActions>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpaySyncActions {
    #[serde(rename = "cancelPayment")]
    pub cancel_payment: Option<WorldpayLink>,
    #[serde(rename = "settlePayment")]
    pub settle_payment: Option<WorldpayLink>,
    #[serde(rename = "partiallySettlePayment")]
    pub partially_settle_payment: Option<WorldpayLink>,
    #[serde(rename = "refundPayment")]
    pub refund_payment: Option<WorldpayLink>,
    #[serde(rename = "partiallyRefundPayment")]
    pub partially_refund_payment: Option<WorldpayLink>,
}

#[derive(Debug, Serialize)]
pub struct WorldpayVoidRequest {
    // Per WorldPay OpenAPI spec, CancelRequest is an empty object
}

#[derive(Debug, Serialize)]
pub struct WorldpayRefundRequest {
    // Per WorldPay OpenAPI spec, RefundRequest is an empty object
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayRefundResponse {
    pub outcome: String,
    #[serde(rename = "_links")]
    pub links: Option<WorldpayRefundLinks>,
    #[serde(rename = "_actions")]
    pub actions: Option<WorldpayRefundActions>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayRefundLinks {
    #[serde(rename = "self")]
    pub self_link: Option<WorldpayLink>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayRefundActions {
    // Refund actions if any are available
}

#[derive(Debug, Serialize)]
pub struct WorldpayRSyncRequest {
    // Per WorldPay OpenAPI spec, GET request has no body
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayRSyncResponse {
    #[serde(rename = "lastEvent")]
    pub last_event: String,
    #[serde(rename = "_actions")]
    pub actions: Option<WorldpayRSyncActions>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayRSyncActions {
    // Refund sync actions if any are available
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayVoidResponse {
    pub outcome: String,
    #[serde(rename = "_links")]
    pub links: Option<WorldpayVoidLinks>,
    #[serde(rename = "_actions")]
    pub actions: Option<WorldpayVoidActions>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayVoidLinks {
    #[serde(rename = "self")]
    pub self_link: Option<WorldpayLink>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayVoidActions {
    // After cancellation, no actions are typically available
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayPaymentsResponse {
    #[serde(rename = "_links")]
    pub links: WorldpayLinks,
    pub outcome: WorldpayOutcome,
    #[serde(rename = "paymentInstrument")]
    pub payment_instrument: Option<WorldpayResponsePaymentInstrument>,
    #[serde(rename = "riskFactors")]
    pub risk_factors: Option<Vec<WorldpayRiskFactor>>,
    #[serde(rename = "issuer")]
    pub issuer: Option<WorldpayIssuer>,
    #[serde(rename = "scheme")]
    pub scheme: Option<WorldpayScheme>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayLinks {
    #[serde(rename = "payments:settle")]
    pub payments_settle: Option<WorldpayLink>,
    #[serde(rename = "payments:cancel")]
    pub payments_cancel: Option<WorldpayLink>,
    #[serde(rename = "payments:events")]
    pub payments_events: Option<WorldpayLink>,
    #[serde(rename = "payments:cardOnFileToken")]
    pub payments_card_on_file_token: Option<WorldpayLink>,
    #[serde(rename = "curies")]
    pub curies: Option<Vec<WorldpayCurie>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayLink {
    pub href: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayCurie {
    pub name: String,
    pub href: String,
    pub templated: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayOutcome {
    #[serde(rename = "authorizeOnly")]
    pub authorize_only: Option<bool>,
    #[serde(rename = "networkTransactionReference")]
    pub network_transaction_reference: Option<String>,
    pub reason: Option<String>,
    #[serde(rename = "riskScore")]
    pub risk_score: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayResponsePaymentInstrument {
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(rename = "maskedCardNumber")]
    pub masked_card_number: Option<String>,
    #[serde(rename = "cardHolderName")]
    pub card_holder_name: Option<String>,
    #[serde(rename = "cardExpiryDate")]
    pub card_expiry_date: Option<WorldpayResponseExpiryDate>,
    pub brand: Option<String>,
    #[serde(rename = "fundingType")]
    pub funding_type: Option<String>,
    #[serde(rename = "issuerName")]
    pub issuer_name: Option<String>,
    #[serde(rename = "issuerCountryCode")]
    pub issuer_country_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayResponseExpiryDate {
    pub month: u8,
    pub year: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayRiskFactor {
    #[serde(rename = "type")]
    pub risk_type: String,
    pub detail: String,
    #[serde(rename = "riskScore")]
    pub risk_score: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayIssuer {
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
    #[serde(rename = "responseCode")]
    pub response_code: Option<String>,
    #[serde(rename = "responseDescription")]
    pub response_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldpayScheme {
    #[serde(rename = "reference")]
    pub reference: Option<String>,
    #[serde(rename = "responseCode")]
    pub response_code: Option<String>,
    #[serde(rename = "responseDescription")]
    pub response_description: Option<String>,
}

impl<T: PaymentMethodDataTypes + Debug + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for WorldpayPaymentsRequest<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let currency = item.request.currency.to_string();
        let payment_id = item.resource_common_data.connector_request_reference_id.clone();

        // Extract merchant entity from auth or use default
        let merchant_entity = "default".to_string();

        let payment_instrument = match &item.request.payment_method_data {
            PaymentMethodData::Card(card_data) => {
                WorldpayPaymentInstrument::Card(build_card_instrument(card_data)?)
            }
            PaymentMethodData::Wallet(wallet_data) => {
                WorldpayPaymentInstrument::Wallet(build_wallet_instrument(wallet_data, item)?)
            }
            PaymentMethodData::BankRedirect(bank_data) => {
                WorldpayPaymentInstrument::BankRedirect(build_bank_redirect_instrument(bank_data)?)
            }
            _ => {
                return Err(error_stack::report!(
                    errors::ConnectorError::NotImplemented(
                        "Payment method not supported".to_string()
                    )
                ))
            }
        };

        Ok(Self {
            transaction_reference: payment_id,
            merchant: WorldpayMerchant {
                entity: merchant_entity,
            },
            instruction: WorldpayInstruction {
                method: "authorize".to_string(),
                payment_instrument,
                narrative: WorldpayNarrative {
                    line1: "Payment".to_string(),
                },
                value: WorldpayValue {
                    amount: item.request.minor_amount.get_amount_as_i64(),
                    currency
                },
                settlement_currency: Some(item.request.currency.to_string()),
            },
        })
    }
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for WorldpayCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Per WorldPay OpenAPI spec, capture (settlement) request has no body
        Ok(Self {})
    }
}

impl TryFrom<&RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for WorldpayPartialCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let reference = match &item.request.multiple_capture_data {
            Some(multiple_capture_data) => multiple_capture_data.capture_reference.clone(),
            None => item.resource_common_data.connector_request_reference_id.clone(),
        };

        Ok(Self {
            reference,
            value: WorldpayValue {
                amount: item.request.minor_amount_to_capture.get_amount_as_i64(),
                currency: item.request.currency.to_string(),
            },
        })
    }
}

impl TryFrom<&RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for WorldpaySyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Per WorldPay OpenAPI spec, sync (query) request has no body
        Ok(Self {})
    }
}

impl TryFrom<&RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>
    for WorldpayVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Per WorldPay OpenAPI spec, void (cancel) request has no body
        Ok(Self {})
    }
}

impl TryFrom<&RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for WorldpayRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Per WorldPay OpenAPI spec, refund request has no body
        Ok(Self {})
    }
}

impl TryFrom<&RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for WorldpayRSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: &RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Per WorldPay OpenAPI spec, refund sync (query) request has no body
        Ok(Self {})
    }
}

fn build_card_instrument<T: PaymentMethodDataTypes>(card_data: &Card<T>) -> Result<WorldpayCardInstrument<T>, error_stack::Report<errors::ConnectorError>> {
    let exp_month = card_data.card_exp_month.peek().parse::<u8>()
        .map_err(|_| error_stack::report!(errors::ConnectorError::MissingRequiredField { field_name: "card_exp_month" }))?;
    let exp_year = card_data.card_exp_year.peek().parse::<u16>()
        .map_err(|_| error_stack::report!(errors::ConnectorError::MissingRequiredField { field_name: "card_exp_year" }))?;

    Ok(WorldpayCardInstrument {
        instrument_type: "card/plain".to_string(),
        card_number: card_data.card_number.clone(),
        card_holder_name: card_data.card_holder_name.clone(),
        expiry_date: WorldpayExpiryDate {
            month: exp_month,
            year: exp_year,
        },
        cvc: Some(card_data.card_cvc.clone()),
    })
}

fn build_wallet_instrument<T: PaymentMethodDataTypes>(
    wallet_data: &WalletData,
    _item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
) -> Result<WorldpayWalletInstrument, error_stack::Report<errors::ConnectorError>> {
    match wallet_data {
        WalletData::ApplePay(_) => Ok(WorldpayWalletInstrument {
            instrument_type: "wallet/applepay".to_string(),
            wallet_token: None,
            return_url: None,
        }),
        WalletData::GooglePay(_) => Ok(WorldpayWalletInstrument {
            instrument_type: "wallet/googlepay".to_string(),
            wallet_token: None,
            return_url: None,
        }),
        WalletData::PaypalRedirect(_) => Ok(WorldpayWalletInstrument {
            instrument_type: "wallet/paypal".to_string(),
            wallet_token: None,
            return_url: None,
        }),
        _ => Err(error_stack::report!(
            errors::ConnectorError::NotImplemented(
                "Wallet type not supported".to_string()
            )
        )),
    }
}

fn build_bank_redirect_instrument(
    bank_data: &BankRedirectData,
) -> Result<WorldpayBankRedirectInstrument, error_stack::Report<errors::ConnectorError>> {
    match bank_data {
        BankRedirectData::Eps { .. } => Ok(WorldpayBankRedirectInstrument {
            instrument_type: "bank/eps".to_string(),
            bank_code: None,
            country_code: Some("AT".to_string()),
        }),
        BankRedirectData::Giropay { .. } => Ok(WorldpayBankRedirectInstrument {
            instrument_type: "bank/giropay".to_string(),
            bank_code: None,
            country_code: Some("DE".to_string()),
        }),
        BankRedirectData::Ideal { .. } => Ok(WorldpayBankRedirectInstrument {
            instrument_type: "bank/ideal".to_string(),
            bank_code: None,
            country_code: Some("NL".to_string()),
        }),
        BankRedirectData::Sofort { .. } => Ok(WorldpayBankRedirectInstrument {
            instrument_type: "bank/sofort".to_string(),
            bank_code: None,
            country_code: Some("DE".to_string()),
        }),
        _ => Err(error_stack::report!(
            errors::ConnectorError::NotImplemented(
                "Bank redirect method not supported".to_string()
            )
        )),
    }
}

impl<T: PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<WorldpayPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayPaymentsResponse, RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_payment_status(&item.response);
        let response_id = ResponseId::ConnectorTransactionId(
            item.response
                .links
                .payments_settle
                .as_ref()
                .or(item.response.links.payments_cancel.as_ref())
                .map(|link| extract_transaction_id_from_url(&link.href))
                .unwrap_or_else(|| "unknown".to_string()),
        );

        let connector_response_reference_id = item
            .response
            .outcome
            .network_transaction_reference
            .clone();

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: response_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: connector_response_reference_id,
                connector_response_reference_id: item
                    .response
                    .issuer
                    .as_ref()
                    .and_then(|issuer| issuer.authorization_code.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<WorldpayCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_capture_status(&item.response);
        let response_id = ResponseId::ConnectorTransactionId(
            item.response
                .links
                .as_ref()
                .and_then(|links| links.self_link.as_ref())
                .map(|link| extract_transaction_id_from_url(&link.href))
                .unwrap_or_else(|| "unknown".to_string()),
        );

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: response_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<WorldpayPartialCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayPartialCaptureResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_partial_capture_status(&item.response);
        let response_id = ResponseId::ConnectorTransactionId(
            item.response
                .links
                .as_ref()
                .and_then(|links| links.self_link.as_ref())
                .map(|link| extract_transaction_id_from_url(&link.href))
                .unwrap_or_else(|| "unknown".to_string()),
        );

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: response_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<WorldpaySyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpaySyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_sync_status(&item.response);
        let response_id = match &item.router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => ResponseId::ConnectorTransactionId(id.clone()),
            _ => ResponseId::NoResponseId,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: response_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<WorldpayVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayVoidResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_void_status(&item.response);
        let response_id = ResponseId::ConnectorTransactionId(
            item.router_data.request.connector_transaction_id.clone(),
        );

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: response_id,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<WorldpayRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayRefundResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_refund_status(&item.response);
        let response_id = item.response
            .links
            .as_ref()
            .and_then(|links| links.self_link.as_ref())
            .map(|link| extract_transaction_id_from_url(&link.href))
            .unwrap_or_else(|| "unknown".to_string());

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                connector_refund_id: response_id,
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<WorldpayRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<WorldpayRSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = get_refund_sync_status(&item.response);
        let response_id = item.router_data.request.connector_refund_id.clone();

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(RefundsResponseData {
                connector_refund_id: response_id,
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

fn get_void_status(response: &WorldpayVoidResponse) -> AttemptStatus {
    match response.outcome.as_str() {
        "sentForCancellation" => AttemptStatus::Voided,
        "refused" => AttemptStatus::VoidFailed,
        _ => AttemptStatus::Pending,
    }
}

fn get_sync_status(response: &WorldpaySyncResponse) -> AttemptStatus {
    match response.last_event.as_str() {
        "Authorized" => AttemptStatus::Authorized,
        "sentForSettlement" => AttemptStatus::Charged,
        "sentForCancellation" => AttemptStatus::Voided,
        "refused" => AttemptStatus::Failure,
        "sentForRefund" => AttemptStatus::Charged, // Original payment was charged, refund is separate
        "sentForPartialRefund" => AttemptStatus::Charged,
        _ => AttemptStatus::Pending,
    }
}

fn get_capture_status(response: &WorldpayCaptureResponse) -> AttemptStatus {
    match response.outcome.as_str() {
        "sentForSettlement" => AttemptStatus::Charged,
        "sentForCancellation" => AttemptStatus::Failure,
        "refused" => AttemptStatus::Failure,
        _ => AttemptStatus::Pending,
    }
}

fn get_partial_capture_status(response: &WorldpayPartialCaptureResponse) -> AttemptStatus {
    match response.outcome.as_str() {
        "sentForSettlement" => AttemptStatus::Charged,
        "sentForCancellation" => AttemptStatus::Failure,
        "refused" => AttemptStatus::Failure,
        _ => AttemptStatus::Pending,
    }
}

fn get_payment_status(response: &WorldpayPaymentsResponse) -> AttemptStatus {
    // Determine status based on available links and outcome
    if response.links.payments_settle.is_some() {
        AttemptStatus::Authorized
    } else if response.links.payments_cancel.is_some() {
        AttemptStatus::Authorized
    } else {
        // Check for any error indicators
        if let Some(reason) = &response.outcome.reason {
            if reason.contains("declined") || reason.contains("failed") {
                AttemptStatus::Failure
            } else {
                AttemptStatus::AuthenticationPending
            }
        } else {
            AttemptStatus::AuthenticationPending
        }
    }
}

fn get_refund_status(response: &WorldpayRefundResponse) -> common_enums::RefundStatus {
    match response.outcome.as_str() {
        "sentForRefund" => common_enums::RefundStatus::Success,
        "refused" => common_enums::RefundStatus::Failure,
        _ => common_enums::RefundStatus::Pending,
    }
}

fn get_refund_sync_status(response: &WorldpayRSyncResponse) -> common_enums::RefundStatus {
    match response.last_event.as_str() {
        "sentForRefund" => common_enums::RefundStatus::Success,
        "refundCompleted" => common_enums::RefundStatus::Success,
        "refundFailed" => common_enums::RefundStatus::Failure,
        "refused" => common_enums::RefundStatus::Failure,
        _ => common_enums::RefundStatus::Pending,
    }
}

fn extract_transaction_id_from_url(url: &str) -> String {
    // Extract transaction ID from Worldpay URL
    url.split('/')
        .last()
        .unwrap_or("unknown")
        .to_string()
}

