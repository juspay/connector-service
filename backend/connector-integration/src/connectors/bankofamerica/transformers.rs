use base64::Engine;
use jsonwebtoken as jwt;
use serde_json::Value;

use common_utils::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    ext_traits::OptionExt,
    pii,
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub const FLUID_DATA_DESCRIPTOR_FOR_SAMSUNG_PAY: &str = "FID=COMMON.SAMSUNG.INAPP.PAYMENT";

use crate::{
    connectors::bankofamerica::BankofamericaRouterData, types::ResponseRouterData,
    unimplemented_payment_method, utils,
};
use cards;
use common_enums;
use domain_types::{
    connector_flow::{Authorize, Capture, Refund, SetupMandate, Void},
    connector_types::{
        MandateReference, PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData,
        PaymentsCaptureData, PaymentsResponseData, PaymentsSyncData, RefundFlowData,
        RefundSyncData, RefundsData, RefundsResponseData, ResponseId, SetupMandateRequestData,
    },
    errors::{self, ConnectorError},
    payment_address::Address,
    payment_method_data::{
        self, ApplePayWalletData, GooglePayWalletData, PaymentMethodData, PaymentMethodDataTypes,
        RawCardNumber, SamsungPayWalletData, WalletData,
    },
    router_data::{ApplePayPredecryptData, ConnectorAuthType, ErrorResponse, PaymentMethodToken},
    router_data_v2::RouterDataV2,
    utils::{is_payment_failure, CardIssuer},
};
use error_stack::{report, ResultExt};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankofamericaPaymentsRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    processing_information: ProcessingInformation,
    payment_information: PaymentInformation<T>,
    order_information: OrderInformationWithBill,
    client_reference_information: ClientReferenceInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_authentication_information: Option<BankOfAmericaConsumerAuthInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingInformation {
    action_list: Option<Vec<BankOfAmericaActionsList>>,
    action_token_types: Option<Vec<BankOfAmericaActionsTokenType>>,
    authorization_options: Option<BankOfAmericaAuthorizationOptions>,
    commerce_indicator: String,
    capture: Option<bool>,
    capture_options: Option<CaptureOptions>,
    payment_solution: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BankOfAmericaActionsList {
    TokenCreate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BankOfAmericaActionsTokenType {
    PaymentInstrument,
    Customer,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaAuthorizationOptions {
    initiator: Option<BankOfAmericaPaymentInitiator>,
    merchant_initiated_transaction: Option<MerchantInitiatedTransaction>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureOptions {
    capture_sequence_number: u32,
    total_capture_count: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaPaymentInitiator {
    #[serde(rename = "type")]
    initiator_type: Option<BankOfAmericaPaymentInitiatorTypes>,
    credential_stored_on_file: Option<bool>,
    stored_credential_used: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BankOfAmericaPaymentInitiatorTypes {
    Customer,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantInitiatedTransaction {
    reason: Option<String>,
    original_authorized_amount: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaymentInformation<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    Cards(Box<CardPaymentInformation<T>>),
    GooglePay(Box<GooglePayPaymentInformation>),
    ApplePay(Box<ApplePayPaymentInformation>),
    ApplePayToken(Box<ApplePayTokenPaymentInformation>),
    MandatePayment(Box<MandatePaymentInformation>),
    SamsungPay(Box<SamsungPayPaymentInformation>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardPaymentInformation<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    card: Card<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    number: RawCardNumber<T>,
    expiration_month: Secret<String>,
    expiration_year: Secret<String>,
    security_code: Option<Secret<String>>,
    #[serde(rename = "type")]
    card_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayPaymentInformation {
    fluid_data: FluidData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FluidData {
    value: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayPaymentInformation {
    tokenized_card: TokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenizedCard {
    number: cards::CardNumber,
    expiration_month: Secret<String>,
    expiration_year: Secret<String>,
    cryptogram: Secret<String>,
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
pub enum TransactionType {
    #[serde(rename = "1")]
    ApplePay,
    #[serde(rename = "1")]
    SamsungPay,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayTokenPaymentInformation {
    fluid_data: FluidData,
    tokenized_card: ApplePayTokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayTokenizedCard {
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MandatePaymentInformation {
    payment_instrument: BankOfAmericaPaymentInstrument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankOfAmericaPaymentInstrument {
    id: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamsungPayPaymentInformation {
    fluid_data: FluidData,
    tokenized_card: SamsungPayTokenizedCard,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamsungPayTokenizedCard {
    transaction_type: TransactionType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformationWithBill {
    amount_details: Amount,
    bill_to: Option<BillTo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Amount {
    total_amount: StringMajorUnit,
    currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillTo {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    address1: Option<Secret<String>>,
    locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    administrative_area: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<Secret<String>>,
    country: Option<common_enums::CountryAlpha2>,
    email: pii::Email,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientReferenceInformation {
    code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaConsumerAuthInformation {
    ucaf_collection_indicator: Option<String>,
    cavv: Option<String>,
    ucaf_authentication_data: Option<Secret<String>>,
    xid: Option<String>,
    directory_server_transaction_id: Option<Secret<String>>,
    specification_version: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantDefinedInformation {
    key: u8,
    value: String,
}

#[derive(Debug, Serialize)]
pub enum PaymentSolution {
    ApplePay,
    GooglePay,
    SamsungPay,
}

pub trait RemoveNewLine {
    fn remove_new_line(&self) -> Self;
}

impl RemoveNewLine for Option<Secret<String>> {
    fn remove_new_line(&self) -> Self {
        self.clone().map(|masked_value| {
            let new_string = masked_value.expose().replace("\n", " ");
            Secret::new(new_string)
        })
    }
}

impl RemoveNewLine for Option<String> {
    fn remove_new_line(&self) -> Self {
        self.clone().map(|value| value.replace("\n", " "))
    }
}

fn build_bill_to(
    address_details: Option<&Address>,
    email: pii::Email,
) -> Result<BillTo, error_stack::Report<errors::ConnectorError>> {
    let default_address = BillTo {
        first_name: None,
        last_name: None,
        address1: None,
        locality: None,
        administrative_area: None,
        postal_code: None,
        country: None,
        email: email.clone(),
    };
    Ok(address_details
        .and_then(|addr| {
            addr.address.as_ref().map(|addr| BillTo {
                first_name: addr.first_name.remove_new_line(),
                last_name: addr.last_name.remove_new_line(),
                address1: addr.line1.remove_new_line(),
                locality: addr.city.clone().map(|c| c.expose()),
                administrative_area: addr.to_state_code_as_optional().ok().flatten().or_else(
                    || {
                        addr.state
                            .remove_new_line()
                            .as_ref()
                            .map(|state| truncate_string(state, 20))
                    },
                ),
                postal_code: addr.zip.remove_new_line(),
                country: addr.country,
                email,
            })
        })
        .unwrap_or(default_address))
}

fn convert_metadata_to_merchant_defined_info(metadata: Value) -> Vec<MerchantDefinedInformation> {
    let hashmap: std::collections::BTreeMap<String, Value> =
        serde_json::from_str(&metadata.to_string()).unwrap_or(std::collections::BTreeMap::new());
    let mut vector = Vec::new();
    let mut iter = 1;
    for (key, value) in hashmap {
        vector.push(MerchantDefinedInformation {
            key: iter,
            value: format!("{key}={value}"),
        });
        iter += 1;
    }
    vector
}

fn truncate_string(state: &Secret<String>, max_len: usize) -> Secret<String> {
    let exposed = state.clone().expose();
    let truncated = exposed.get(..max_len).unwrap_or(&exposed);
    Secret::new(truncated.to_string())
}

pub fn get_error_reason(
    error_info: Option<String>,
    detailed_error_info: Option<String>,
    avs_error_info: Option<String>,
) -> Option<String> {
    match (error_info, detailed_error_info, avs_error_info) {
        (Some(message), Some(details), Some(avs_message)) => Some(format!(
            "{message}, detailed_error_information: {details}, avs_message: {avs_message}",
        )),
        (Some(message), Some(details), None) => {
            Some(format!("{message}, detailed_error_information: {details}"))
        }
        (Some(message), None, Some(avs_message)) => {
            Some(format!("{message}, avs_message: {avs_message}"))
        }
        (None, Some(details), Some(avs_message)) => {
            Some(format!("{details}, avs_message: {avs_message}"))
        }
        (Some(message), None, None) => Some(message),
        (None, Some(details), None) => Some(details),
        (None, None, Some(avs_message)) => Some(avs_message),
        (None, None, None) => None,
    }
}

fn convert_to_error_response_from_error_info(
    error_response: &BankOfAmericaErrorInformationResponse,
    status_code: u16,
) -> ErrorResponse {
    let detailed_error_info =
        error_response
            .error_information
            .to_owned()
            .details
            .map(|error_details| {
                error_details
                    .iter()
                    .map(|details| format!("{} : {}", details.field, details.reason))
                    .collect::<Vec<_>>()
                    .join(", ")
            });

    let reason = get_error_reason(
        error_response.error_information.message.to_owned(),
        detailed_error_info,
        None,
    );
    ErrorResponse {
        code: error_response
            .error_information
            .reason
            .clone()
            .unwrap_or(NO_ERROR_CODE.to_string()),
        message: error_response
            .error_information
            .reason
            .clone()
            .unwrap_or(NO_ERROR_MESSAGE.to_string()),
        reason,
        status_code,
        attempt_status: None,
        connector_transaction_id: Some(error_response.id.clone()),
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
    }
}

fn get_boa_mandate_action_details() -> (
    Option<Vec<BankOfAmericaActionsList>>,
    Option<Vec<BankOfAmericaActionsTokenType>>,
    Option<BankOfAmericaAuthorizationOptions>,
) {
    (
        Some(vec![BankOfAmericaActionsList::TokenCreate]),
        Some(vec![
            BankOfAmericaActionsTokenType::PaymentInstrument,
            BankOfAmericaActionsTokenType::Customer,
        ]),
        Some(BankOfAmericaAuthorizationOptions {
            initiator: Some(BankOfAmericaPaymentInitiator {
                initiator_type: Some(BankOfAmericaPaymentInitiatorTypes::Customer),
                credential_stored_on_file: Some(true),
                stored_credential_used: None,
            }),
            merchant_initiated_transaction: None,
        }),
    )
}

fn get_commerce_indicator(network: Option<String>) -> String {
    match network {
        Some(card_network) => match card_network.to_lowercase().as_str() {
            "amex" => "aesk",
            "discover" => "dipb",
            "mastercard" => "spa",
            "visa" => "internet",
            _ => "internet",
        },
        None => "internet",
    }
    .to_string()
}

fn get_error_response(
    error_data: &Option<BankOfAmericaErrorInformation>,
    processor_information: &Option<ClientProcessorInformation>,
    risk_information: &Option<ClientRiskInformation>,
    attempt_status: Option<common_enums::AttemptStatus>,
    status_code: u16,
    transaction_id: String,
) -> ErrorResponse {
    let avs_message = risk_information
        .clone()
        .map(|client_risk_information| {
            client_risk_information.rules.map(|rules| {
                rules
                    .iter()
                    .map(|risk_info| {
                        risk_info.name.clone().map_or("".to_string(), |name| {
                            format!(" , {}", name.clone().expose())
                        })
                    })
                    .collect::<Vec<String>>()
                    .join("")
            })
        })
        .unwrap_or(Some("".to_string()));

    let detailed_error_info = error_data.to_owned().and_then(|error_info| {
        error_info.details.map(|error_details| {
            error_details
                .iter()
                .map(|details| format!("{} : {}", details.field, details.reason))
                .collect::<Vec<_>>()
                .join(", ")
        })
    });
    let network_decline_code = processor_information
        .as_ref()
        .and_then(|info| info.response_code.clone());
    let network_advice_code = processor_information.as_ref().and_then(|info| {
        info.merchant_advice
            .as_ref()
            .and_then(|merchant_advice| merchant_advice.code_raw.clone())
    });

    let reason = get_error_reason(
        error_data
            .clone()
            .and_then(|error_details| error_details.message),
        detailed_error_info,
        avs_message,
    );
    let error_message = error_data
        .clone()
        .and_then(|error_details| error_details.reason);

    ErrorResponse {
        code: error_message.clone().unwrap_or(NO_ERROR_CODE.to_string()),
        message: error_message
            .clone()
            .unwrap_or(NO_ERROR_MESSAGE.to_string()),
        reason,
        status_code,
        attempt_status,
        connector_transaction_id: Some(transaction_id.clone()),
        network_advice_code,
        network_decline_code,
        network_error_message: None,
    }
}

fn get_error_response_if_failure(
    (info_response, status, http_code): (
        &BankOfAmericaClientReferenceResponse,
        common_enums::AttemptStatus,
        u16,
    ),
) -> Option<ErrorResponse> {
    if domain_types::utils::is_payment_failure(status) {
        Some(get_error_response(
            &info_response.error_information,
            &info_response.processor_information,
            &info_response.risk_information,
            Some(status),
            http_code,
            info_response.id.clone(),
        ))
    } else {
        None
    }
}

fn get_payment_response(
    (info_response, status, http_code): (
        &BankOfAmericaClientReferenceResponse,
        common_enums::AttemptStatus,
        u16,
    ),
) -> Result<PaymentsResponseData, Box<ErrorResponse>> {
    let error_response = get_error_response_if_failure((info_response, status, http_code));
    match error_response {
        Some(error) => Err(Box::new(error)),
        None => {
            let mandate_reference =
                info_response
                    .token_information
                    .clone()
                    .map(|token_info| MandateReference {
                        connector_mandate_id: token_info
                            .payment_instrument
                            .map(|payment_instrument| payment_instrument.id.expose()),
                        payment_method_id: None,
                    });

            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(info_response.id.clone()),
                redirection_data: None,
                mandate_reference: mandate_reference.map(Box::new),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(
                    info_response
                        .client_reference_information
                        .code
                        .clone()
                        .unwrap_or(info_response.id.clone()),
                ),
                incremental_authorization_allowed: None,
                status_code: http_code,
            })
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
        BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(ccard) => Self::try_from((item, ccard)),
            PaymentMethodData::Wallet(wallet_data) => match wallet_data {
                WalletData::ApplePay(apple_pay_data) => Self::try_from((&item, apple_pay_data)),
                WalletData::GooglePay(google_pay_data) => Self::try_from((&item, google_pay_data)),
                WalletData::AliPayQr(_)
                | WalletData::AliPayRedirect(_)
                | WalletData::AliPayHkRedirect(_)
                | WalletData::AmazonPayRedirect(_)
                | WalletData::BluecodeRedirect {}
                | WalletData::MomoRedirect(_)
                | WalletData::KakaoPayRedirect(_)
                | WalletData::GoPayRedirect(_)
                | WalletData::GcashRedirect(_)
                | WalletData::ApplePayRedirect(_)
                | WalletData::ApplePayThirdPartySdk(_)
                | WalletData::DanaRedirect {}
                | WalletData::GooglePayRedirect(_)
                | WalletData::GooglePayThirdPartySdk(_)
                | WalletData::MbWayRedirect(_)
                | WalletData::MobilePayRedirect(_)
                | WalletData::PaypalRedirect(_)
                | WalletData::PaypalSdk(_)
                | WalletData::SamsungPay(_)
                | WalletData::TwintRedirect {}
                | WalletData::VippsRedirect {}
                | WalletData::TouchNGoRedirect(_)
                | WalletData::WeChatPayRedirect(_)
                | WalletData::WeChatPayQr(_)
                | WalletData::CashappQr(_)
                | WalletData::SwishQr(_)
                | WalletData::Paze(_)
                | WalletData::Mifinity(_)
                | WalletData::RevolutPay(_) => Err(errors::ConnectorError::NotImplemented(
                    domain_types::utils::get_unimplemented_payment_method_error_message(
                        "Bank of America",
                    ),
                )
                .into()),
            },
            PaymentMethodData::MandatePayment
            | PaymentMethodData::CardRedirect(_)
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
                    domain_types::utils::get_unimplemented_payment_method_error_message(
                        "Bank of America",
                    ),
                )
                .into())
            }
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
    TryFrom<(
        BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        payment_method_data::Card<T>,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        (item, ccard): (
            BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            payment_method_data::Card<T>,
        ),
    ) -> Result<Self, Self::Error> {
        let email = item
            .router_data
            .request
            .get_email()
            .or(item.router_data.resource_common_data.get_billing_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::try_from((&item, Some(bill_to)))?;
        let processing_information = ProcessingInformation::try_from((&item, None, None))?;
        let client_reference_information = ClientReferenceInformation::from(&item);
        let payment_information = PaymentInformation::try_from((&item, ccard))?;
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information: None,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BankofamericaPaymentsResponse {
    ClientReferenceInformation(Box<BankOfAmericaClientReferenceResponse>),
    ErrorInformation(Box<BankOfAmericaErrorInformationResponse>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaRefundRequest {
    order_information: OrderInformation,
    client_reference_information: ClientReferenceInformation,
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
        BankofamericaRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for BankOfAmericaRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BankofamericaRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            order_information: OrderInformation {
                amount_details: Amount {
                    total_amount: item
                        .connector
                        .amount_converter
                        .convert(
                            item.router_data.request.minor_refund_amount,
                            item.router_data.request.currency,
                        )
                        .change_context(ConnectorError::RequestEncodingFailed)?,
                    currency: item.router_data.request.currency,
                },
            },
            client_reference_information: ClientReferenceInformation {
                code: Some(item.router_data.request.refund_id.clone()),
            },
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaRefundResponse {
    id: String,
    status: BankofamericaRefundStatus,
    error_information: Option<BankOfAmericaErrorInformation>,
}

impl From<BankOfAmericaRefundResponse> for common_enums::RefundStatus {
    fn from(item: BankOfAmericaRefundResponse) -> Self {
        let error_reason = item
            .error_information
            .and_then(|error_info| error_info.reason);
        match item.status {
            BankofamericaRefundStatus::Succeeded | BankofamericaRefundStatus::Transmitted => {
                Self::Success
            }
            BankofamericaRefundStatus::Cancelled
            | BankofamericaRefundStatus::Failed
            | BankofamericaRefundStatus::Voided => Self::Failure,
            BankofamericaRefundStatus::Pending => Self::Pending,
            BankofamericaRefundStatus::TwoZeroOne => {
                if error_reason == Some("PROCESSOR_DECLINED".to_string()) {
                    Self::Failure
                } else {
                    Self::Pending
                }
            }
        }
    }
}

impl<F> TryFrom<ResponseRouterData<BankOfAmericaRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BankOfAmericaRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = common_enums::RefundStatus::from(item.response.clone());
        let response = if utils::is_refund_failure(refund_status) {
            Err(get_error_response(
                &item.response.error_information,
                &None,
                &None,
                None,
                item.http_code,
                item.response.id.clone(),
            ))
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status,
                status_code: item.http_code,
            })
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BankofamericaRefundStatus {
    Succeeded,
    Transmitted,
    Failed,
    Pending,
    Voided,
    Cancelled,
    #[serde(rename = "201")]
    TwoZeroOne,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RsyncApplicationInformation {
    status: Option<BankofamericaRefundStatus>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaRsyncResponse {
    id: String,
    application_information: Option<RsyncApplicationInformation>,
    error_information: Option<BankOfAmericaErrorInformation>,
}

impl<F> TryFrom<ResponseRouterData<BankOfAmericaRsyncResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<BankOfAmericaRsyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = match item
            .response
            .application_information
            .and_then(|application_information| application_information.status)
        {
            Some(status) => {
                let error_reason = item
                    .response
                    .error_information
                    .clone()
                    .and_then(|error_info| error_info.reason);
                let refund_status = match status {
                    BankofamericaRefundStatus::Succeeded
                    | BankofamericaRefundStatus::Transmitted => common_enums::RefundStatus::Success,
                    BankofamericaRefundStatus::Cancelled
                    | BankofamericaRefundStatus::Failed
                    | BankofamericaRefundStatus::Voided => common_enums::RefundStatus::Failure,
                    BankofamericaRefundStatus::Pending => common_enums::RefundStatus::Pending,
                    BankofamericaRefundStatus::TwoZeroOne => {
                        if error_reason == Some("PROCESSOR_DECLINED".to_string()) {
                            common_enums::RefundStatus::Failure
                        } else {
                            common_enums::RefundStatus::Pending
                        }
                    }
                };
                if utils::is_refund_failure(refund_status) {
                    Err(get_error_response(
                        &item.response.error_information,
                        &None,
                        &None,
                        None,
                        item.http_code,
                        item.response.id.clone(),
                    ))
                } else {
                    Ok(RefundsResponseData {
                        connector_refund_id: item.response.id.clone(),
                        refund_status,
                        status_code: item.http_code,
                    })
                }
            }
            None => Err(get_error_response(
                &item.response.error_information,
                &None,
                &None,
                None,
                item.http_code,
                item.response.id.clone(),
            )),
        };

        Ok(Self {
            response,
            ..item.router_data
        })
    }
}

pub type BankofamericaPaymentsResponseForCapture = BankofamericaPaymentsResponse;

pub type BankofamericaPaymentsRequestForSetupMandate<T> = BankofamericaPaymentsRequest<T>;
pub type BankOfAmericaPaymentsResponseForSetupMandate = BankofamericaPaymentsResponse;

pub type BankofamericaVoidRequestForVoid = BankofamericaVoidRequest;
pub type BankOfAmericaPaymentsResponseForVoid = BankofamericaPaymentsResponse;

pub type BankOfAmericaRefundRequestForRefund = BankOfAmericaRefundRequest;
pub type BankOfAmericaRefundResponseForRefund = BankOfAmericaRefundResponse;

pub type BankOfAmericaRsyncResponseForRSync = BankOfAmericaRsyncResponse;

impl<F> TryFrom<ResponseRouterData<BankofamericaPaymentsResponseForCapture, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BankofamericaPaymentsResponseForCapture, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BankofamericaPaymentsResponseForCapture::ClientReferenceInformation(info_response) => {
                let status = map_boa_attempt_status((info_response.status.clone(), true));
                let response = get_payment_response((&info_response, status, item.http_code))
                    .map_err(|err| *err);
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
            BankofamericaPaymentsResponseForCapture::ErrorInformation(ref error_response) => {
                Ok(map_error_response(&error_response.clone(), item, None))
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaClientReferenceResponse {
    id: String,
    status: BankofamericaPaymentStatus,
    client_reference_information: ClientReferenceInformation,
    processor_information: Option<ClientProcessorInformation>,
    processing_information: Option<ProcessingInformationResponse>,
    payment_information: Option<PaymentInformationResponse>,
    payment_insights_information: Option<PaymentInsightsInformation>,
    risk_information: Option<ClientRiskInformation>,
    token_information: Option<BankOfAmericaTokenInformation>,
    error_information: Option<BankOfAmericaErrorInformation>,
    issuer_information: Option<IssuerInformation>,
    sender_information: Option<SenderInformation>,
    payment_account_information: Option<PaymentAccountInformation>,
    reconciliation_id: Option<String>,
    consumer_authentication_information: Option<ConsumerAuthenticationInformation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BankofamericaPaymentStatus {
    Authorized,
    Succeeded,
    Failed,
    Voided,
    Reversed,
    Pending,
    Declined,
    Rejected,
    Challenge,
    AuthorizedPendingReview,
    AuthorizedRiskDeclined,
    Transmitted,
    InvalidRequest,
    ServerError,
    PendingAuthentication,
    PendingReview,
    Accepted,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientProcessorInformation {
    avs: Option<Avs>,
    card_verification: Option<CardVerification>,
    processor: Option<ProcessorResponse>,
    network_transaction_id: Option<Secret<String>>,
    approval_code: Option<String>,
    merchant_advice: Option<MerchantAdvice>,
    response_code: Option<String>,
    ach_verification: Option<AchVerification>,
    system_trace_audit_number: Option<String>,
    event_status: Option<String>,
    retrieval_reference_number: Option<String>,
    consumer_authentication_response: Option<ConsumerAuthenticationResponse>,
    response_details: Option<String>,
    transaction_id: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Avs {
    code: Option<String>,
    code_raw: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardVerification {
    result_code: Option<String>,
    result_code_raw: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessorResponse {
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantAdvice {
    code: Option<String>,
    code_raw: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AchVerification {
    result_code_raw: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerAuthenticationResponse {
    code: Option<String>,
    code_raw: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingInformationResponse {
    payment_solution: Option<String>,
    commerce_indicator: Option<String>,
    commerce_indicator_label: Option<String>,
    authorization_options: Option<AuthorizationOptions>,
    ecommerce_indicator: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationOptions {
    auth_type: Option<String>,
    initiator: Option<Initiator>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Initiator {
    merchant_initiated_transaction: Option<MerchantInitiatedTransactionResponse>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerchantInitiatedTransactionResponse {
    agreement_id: Option<String>,
    previous_transaction_id: Option<String>,
    original_authorized_amount: Option<StringMajorUnit>,
    reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInformationResponse {
    tokenized_card: Option<CardResponseObject>,
    customer: Option<CustomerResponseObject>,
    card: Option<CardResponseObject>,
    scheme: Option<String>,
    bin: Option<String>,
    account_type: Option<String>,
    issuer: Option<String>,
    bin_country: Option<common_enums::CountryAlpha2>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardResponseObject {
    suffix: Option<String>,
    prefix: Option<String>,
    expiration_month: Option<Secret<String>>,
    expiration_year: Option<Secret<String>>,
    #[serde(rename = "type")]
    card_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerResponseObject {
    customer_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInsightsInformation {
    response_insights: Option<ResponseInsights>,
    rule_results: Option<RuleResults>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseInsights {
    category_code: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleResults {
    id: Option<String>,
    decision: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRiskInformation {
    rules: Option<Vec<ClientRiskInformationRules>>,
    profile: Option<Profile>,
    score: Option<Score>,
    info_codes: Option<InfoCodes>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientRiskInformationRules {
    name: Option<Secret<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    early_decision: Option<String>,
    name: Option<String>,
    decision: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Score {
    factor_codes: Option<Vec<String>>,
    result: Option<RiskResult>,
    model_used: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RiskResult {
    StringVariant(String),
    IntVariant(u64),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoCodes {
    address: Option<Vec<String>>,
    identity_change: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaTokenInformation {
    payment_instrument: Option<BankOfAmericaPaymentInstrument>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BankOfAmericaErrorInformation {
    reason: Option<String>,
    message: Option<String>,
    details: Option<Vec<Details>>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Details {
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerInformation {
    country: Option<common_enums::CountryAlpha2>,
    discretionary_data: Option<String>,
    country_specific_discretionary_data: Option<String>,
    response_code: Option<String>,
    pin_request_indicator: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderInformation {
    payment_information: Option<PaymentInformationResponse>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentAccountInformation {
    card: Option<PaymentAccountCardInformation>,
    features: Option<PaymentAccountFeatureInformation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentAccountCardInformation {
    #[serde(rename = "type")]
    card_type: Option<String>,
    hashed_number: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentAccountFeatureInformation {
    health_card: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerAuthenticationInformation {
    eci_raw: Option<String>,
    eci: Option<String>,
    acs_transaction_id: Option<String>,
    cavv: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaErrorInformationResponse {
    id: String,
    error_information: BankOfAmericaErrorInformation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaStandardErrorResponse {
    pub error_information: Option<ErrorInformation>,
    pub status: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
    pub details: Option<Vec<Details>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaServerErrorResponse {
    pub status: Option<String>,
    pub message: Option<String>,
    pub reason: Option<Reason>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reason {
    SystemError,
    ServerTimeout,
    ServiceTimeout,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BankOfAmericaAuthenticationErrorResponse {
    pub response: AuthenticationErrorInformation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BankofamericaErrorResponse {
    AuthenticationError(BankOfAmericaAuthenticationErrorResponse),
    StandardError(BankOfAmericaStandardErrorResponse),
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ErrorInformation {
    pub message: String,
    pub reason: String,
    pub details: Option<Vec<Details>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct AuthenticationErrorInformation {
    pub rmsg: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankofamericaVoidRequest {
    client_reference_information: ClientReferenceInformation,
    reversal_information: ReversalInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversalInformation {
    amount_details: Amount,
    reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformation {
    amount_details: Amount,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankofamericaCaptureRequest {
    order_information: OrderInformation,
    client_reference_information: ClientReferenceInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankOfAmericaTransactionResponse {
    id: String,
    application_information: ApplicationInformation,
    client_reference_information: Option<ClientReferenceInformation>,
    processor_information: Option<ClientProcessorInformation>,
    processing_information: Option<ProcessingInformationResponse>,
    payment_information: Option<PaymentInformationResponse>,
    payment_insights_information: Option<PaymentInsightsInformation>,
    error_information: Option<BankOfAmericaErrorInformation>,
    fraud_marking_information: Option<FraudMarkingInformation>,
    risk_information: Option<ClientRiskInformation>,
    token_information: Option<BankOfAmericaTokenInformation>,
    reconciliation_id: Option<String>,
    consumer_authentication_information: Option<ConsumerAuthenticationInformation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FraudMarkingInformation {
    reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationInformation {
    status: Option<BankofamericaPaymentStatus>,
}

pub struct BankOfAmericaAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) merchant_account: Secret<String>,
    pub(super) api_secret: Secret<String>,
}

pub struct BankOfAmericaRouterData<T> {
    pub amount: StringMajorUnit,
    pub router_data: T,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BankOfAmericaSetupMandatesResponse {
    ClientReferenceInformation(Box<BankOfAmericaClientReferenceResponse>),
    ErrorInformation(Box<BankOfAmericaErrorInformationResponse>),
}

fn card_issuer_to_string(card_issuer: CardIssuer) -> String {
    let card_type = match card_issuer {
        CardIssuer::AmericanExpress => "003",
        CardIssuer::Master => "002",
        CardIssuer::Maestro => "042",
        CardIssuer::Visa => "001",
        CardIssuer::Discover => "004",
        CardIssuer::DinersClub => "005",
        CardIssuer::CarteBlanche => "006",
        CardIssuer::JCB => "007",
        CardIssuer::CartesBancaires => "036",
    };
    card_type.to_string()
}

fn get_boa_card_type(card_network: common_enums::CardNetwork) -> Option<&'static str> {
    match card_network {
        common_enums::CardNetwork::Visa => Some("001"),
        common_enums::CardNetwork::Mastercard => Some("002"),
        common_enums::CardNetwork::AmericanExpress => Some("003"),
        common_enums::CardNetwork::JCB => Some("007"),
        common_enums::CardNetwork::DinersClub => Some("005"),
        common_enums::CardNetwork::Discover => Some("004"),
        common_enums::CardNetwork::CartesBancaires => Some("006"),
        common_enums::CardNetwork::UnionPay => Some("062"),
        common_enums::CardNetwork::Maestro => Some("042"),
        common_enums::CardNetwork::Interac
        | common_enums::CardNetwork::RuPay
        | common_enums::CardNetwork::Star
        | common_enums::CardNetwork::Accel
        | common_enums::CardNetwork::Pulse
        | common_enums::CardNetwork::Nyce => None,
    }
}

impl<T> TryFrom<(StringMajorUnit, T)> for BankOfAmericaRouterData<T> {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from((amount, item): (StringMajorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

impl From<PaymentSolution> for String {
    fn from(solution: PaymentSolution) -> Self {
        let payment_solution = match solution {
            PaymentSolution::ApplePay => "001",
            PaymentSolution::GooglePay => "012",
            PaymentSolution::SamsungPay => "008",
        };
        payment_solution.to_string()
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
    From<
        &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ClientReferenceInformation
{
    fn from(
        item: &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Self {
        Self {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
        }
    }
}

impl TryFrom<&ConnectorAuthType> for BankOfAmericaAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::SignatureKey {
            api_key,
            key1,
            api_secret,
        } = auth_type
        {
            Ok(Self {
                api_key: api_key.to_owned(),
                merchant_account: key1.to_owned(),
                api_secret: api_secret.to_owned(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType)?
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Option<PaymentSolution>,
        Option<String>,
    )> for ProcessingInformation
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (item, solution, network): (
            &BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Option<PaymentSolution>,
            Option<String>,
        ),
    ) -> Result<Self, Self::Error> {
        let (action_list, action_token_types, authorization_options) = if item
            .router_data
            .request
            .setup_future_usage
            == Some(common_enums::FutureUsage::OffSession)
            && (item.router_data.request.customer_acceptance.is_some()
                || item
                    .router_data
                    .request
                    .setup_mandate_details
                    .clone()
                    .is_some_and(|mandate_details| mandate_details.customer_acceptance.is_some()))
        {
            get_boa_mandate_action_details()
        } else {
            (None, None, None)
        };

        let commerce_indicator = get_commerce_indicator(network);

        Ok(Self {
            capture: Some(matches!(
                item.router_data.request.capture_method,
                Some(common_enums::CaptureMethod::Automatic) | None
            )),
            payment_solution: solution.map(String::from),
            action_list,
            action_token_types,
            authorization_options,
            capture_options: None,
            commerce_indicator,
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        payment_method_data::Card<T>,
    )> for PaymentInformation<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (_item, ccard): (
            &BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            payment_method_data::Card<T>,
        ),
    ) -> Result<Self, Self::Error> {
        let card_type = match ccard.card_network.clone().and_then(get_boa_card_type) {
            Some(card_network) => Some(card_network.to_string()),
            None => domain_types::utils::get_card_issuer(ccard.card_number.peek())
                .ok()
                .map(card_issuer_to_string),
        };
        Ok(Self::Cards(Box::new(CardPaymentInformation {
            card: Card {
                number: ccard.card_number.clone(),
                expiration_month: ccard.card_exp_month.clone(),
                expiration_year: ccard.card_exp_year.clone(),
                security_code: Some(ccard.card_cvc),
                card_type,
            },
        })))
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Box<ApplePayPredecryptData>,
        ApplePayWalletData,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: (
            &BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Box<ApplePayPredecryptData>,
            ApplePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let (item, apple_pay_data, apple_pay_wallet_data) = item;
        let email = item
            .router_data
            .request
            .get_email()
            .or(item.router_data.resource_common_data.get_billing_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::try_from((item, Some(bill_to)))?;
        let processing_information = ProcessingInformation::try_from((
            item,
            Some(PaymentSolution::ApplePay),
            Some(apple_pay_wallet_data.payment_method.network.clone()),
        ))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let payment_information = PaymentInformation::try_from(&apple_pay_data)?;
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);
        let ucaf_collection_indicator = match apple_pay_wallet_data
            .payment_method
            .network
            .to_lowercase()
            .as_str()
        {
            "mastercard" => Some("2".to_string()),
            _ => None,
        };
        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information: Some(BankOfAmericaConsumerAuthInformation {
                ucaf_collection_indicator,
                cavv: None,
                ucaf_authentication_data: None,
                xid: None,
                directory_server_transaction_id: None,
                specification_version: None,
            }),
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                domain_types::connector_flow::Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        ApplePayWalletData,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (item, apple_pay_wallet_data): (
            &BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            ApplePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let email = item
            .router_data
            .request
            .get_email()
            .or(item.router_data.resource_common_data.get_billing_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::try_from((item, Some(bill_to)))?;
        let processing_information = ProcessingInformation::try_from((
            item,
            Some(PaymentSolution::ApplePay),
            Some(apple_pay_wallet_data.payment_method.network.clone()),
        ))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let payment_information = PaymentInformation::try_from(&apple_pay_wallet_data)?;
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);
        let ucaf_collection_indicator = match apple_pay_wallet_data
            .payment_method
            .network
            .to_lowercase()
            .as_str()
        {
            "mastercard" => Some("2".to_string()),
            _ => None,
        };
        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information: Some(BankOfAmericaConsumerAuthInformation {
                ucaf_collection_indicator,
                cavv: None,
                ucaf_authentication_data: None,
                xid: None,
                directory_server_transaction_id: None,
                specification_version: None,
            }),
        })
    }
}

fn map_boa_attempt_status(
    (status, auto_capture): (BankofamericaPaymentStatus, bool),
) -> common_enums::AttemptStatus {
    match status {
        BankofamericaPaymentStatus::Authorized
        | BankofamericaPaymentStatus::AuthorizedPendingReview => {
            if auto_capture {
                common_enums::AttemptStatus::Charged
            } else {
                common_enums::AttemptStatus::Authorized
            }
        }
        BankofamericaPaymentStatus::Pending => {
            if auto_capture {
                common_enums::AttemptStatus::Charged
            } else {
                common_enums::AttemptStatus::Pending
            }
        }
        BankofamericaPaymentStatus::Succeeded | BankofamericaPaymentStatus::Transmitted => {
            common_enums::AttemptStatus::Charged
        }
        BankofamericaPaymentStatus::Voided
        | BankofamericaPaymentStatus::Reversed
        | BankofamericaPaymentStatus::Cancelled => common_enums::AttemptStatus::Voided,
        BankofamericaPaymentStatus::Failed
        | BankofamericaPaymentStatus::Declined
        | BankofamericaPaymentStatus::AuthorizedRiskDeclined
        | BankofamericaPaymentStatus::InvalidRequest
        | BankofamericaPaymentStatus::Rejected
        | BankofamericaPaymentStatus::ServerError => common_enums::AttemptStatus::Failure,
        BankofamericaPaymentStatus::PendingAuthentication => {
            common_enums::AttemptStatus::AuthenticationPending
        }
        BankofamericaPaymentStatus::PendingReview
        | BankofamericaPaymentStatus::Challenge
        | BankofamericaPaymentStatus::Accepted => common_enums::AttemptStatus::Pending,
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
        ResponseRouterData<
            BankofamericaPaymentsResponse,
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BankofamericaPaymentsResponse,
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BankofamericaPaymentsResponse::ClientReferenceInformation(info_response) => {
                let is_auto_capture = matches!(
                    item.router_data.request.capture_method,
                    Some(common_enums::CaptureMethod::Automatic)
                        | Some(common_enums::CaptureMethod::SequentialAutomatic)
                        | None
                );
                let status =
                    map_boa_attempt_status((info_response.status.clone(), is_auto_capture));
                let response = get_payment_response((&info_response, status, item.http_code))
                    .map_err(|err| *err);
                Ok(RouterDataV2 {
                    response,
                    ..item.router_data
                })
            }
            BankofamericaPaymentsResponse::ErrorInformation(ref error_response) => {
                Ok(map_error_response(
                    &error_response.clone(),
                    item,
                    Some(common_enums::AttemptStatus::Failure),
                ))
            }
        }
    }
}

fn map_error_response<F, T>(
    error_response: &BankOfAmericaErrorInformationResponse,
    item: ResponseRouterData<
        BankofamericaPaymentsResponse,
        RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>,
    >,
    _transaction_status: Option<common_enums::AttemptStatus>,
) -> RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
where
    T: Clone,
{
    let detailed_error_info = error_response
        .error_information
        .details
        .as_ref()
        .map(|details| {
            details
                .iter()
                .map(|details| format!("{} : {}", details.field, details.reason))
                .collect::<Vec<_>>()
                .join(", ")
        });

    let reason = get_error_reason(
        error_response.error_information.message.clone(),
        detailed_error_info,
        None,
    );
    let response = Err(ErrorResponse {
        code: error_response
            .error_information
            .reason
            .clone()
            .unwrap_or(NO_ERROR_CODE.to_string()),
        message: error_response
            .error_information
            .reason
            .clone()
            .unwrap_or(NO_ERROR_MESSAGE.to_string()),
        reason,
        status_code: item.http_code,
        attempt_status: None,
        connector_transaction_id: Some(error_response.id.clone()),
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
    });

    RouterDataV2 {
        response,
        ..item.router_data
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
        BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(card_data) => Self::try_from((&item, card_data)),
            PaymentMethodData::Wallet(wallet_data) => match wallet_data {
                WalletData::ApplePay(apple_pay_data) => Self::try_from((&item, apple_pay_data)),
                WalletData::GooglePay(google_pay_data) => Self::try_from((&item, google_pay_data)),
                WalletData::AliPayQr(_)
                | WalletData::AliPayRedirect(_)
                | WalletData::AliPayHkRedirect(_)
                | WalletData::AmazonPayRedirect(_)
                | WalletData::BluecodeRedirect {}
                | WalletData::MomoRedirect(_)
                | WalletData::KakaoPayRedirect(_)
                | WalletData::GoPayRedirect(_)
                | WalletData::GcashRedirect(_)
                | WalletData::ApplePayRedirect(_)
                | WalletData::ApplePayThirdPartySdk(_)
                | WalletData::DanaRedirect {}
                | WalletData::GooglePayRedirect(_)
                | WalletData::GooglePayThirdPartySdk(_)
                | WalletData::MbWayRedirect(_)
                | WalletData::MobilePayRedirect(_)
                | WalletData::PaypalRedirect(_)
                | WalletData::PaypalSdk(_)
                | WalletData::Paze(_)
                | WalletData::SamsungPay(_)
                | WalletData::TwintRedirect {}
                | WalletData::VippsRedirect {}
                | WalletData::TouchNGoRedirect(_)
                | WalletData::WeChatPayRedirect(_)
                | WalletData::WeChatPayQr(_)
                | WalletData::CashappQr(_)
                | WalletData::SwishQr(_)
                | WalletData::Mifinity(_)
                | WalletData::RevolutPay(_) => Err(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("BankOfAmerica"),
                ))?,
            },
            PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::MandatePayment
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
                    utils::get_unimplemented_payment_method_error_message("BankOfAmerica"),
                ))?
            }
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        payment_method_data::Card<T>,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (item, ccard): (
            &BankofamericaRouterData<
                RouterDataV2<
                    SetupMandate,
                    PaymentFlowData,
                    SetupMandateRequestData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            payment_method_data::Card<T>,
        ),
    ) -> Result<Self, Self::Error> {
        if item.router_data.resource_common_data.is_three_ds() {
            Err(errors::ConnectorError::NotSupported {
                message: "Card 3DS".to_string(),
                connector: "BankOfAmerica",
            })?
        };

        let order_information = OrderInformationWithBill::try_from(item)?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);
        let payment_information = PaymentInformation::try_from(&ccard)?;
        let processing_information = ProcessingInformation::try_from((item, None, None))?;
        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: None,
            merchant_defined_information,
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
    From<(
        BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Option<BillTo>,
    )> for OrderInformationWithBill
{
    fn from(
        (item, bill_to): (
            BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Option<BillTo>,
        ),
    ) -> Self {
        Self {
            amount_details: Amount {
                total_amount: StringMajorUnit::zero(),
                currency: item.router_data.request.currency,
            },
            bill_to,
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Option<BillTo>,
    )> for OrderInformationWithBill
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        (item, bill_to): (
            &BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Option<BillTo>,
        ),
    ) -> Result<Self, Self::Error> {
        let converter = StringMajorUnitForConnector;
        let amount = converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        Ok(Self {
            amount_details: Amount {
                total_amount: amount,
                currency: item.router_data.request.currency,
            },
            bill_to,
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
    From<
        &BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for ClientReferenceInformation
{
    fn from(
        item: &BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Self {
        Self {
            code: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
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
        &BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for OrderInformationWithBill
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: &BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            amount_details: Amount {
                total_amount: StringMajorUnit::zero(),
                currency: item.router_data.request.currency,
            },
            bill_to: None,
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
    > TryFrom<&payment_method_data::Card<T>> for PaymentInformation<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(ccard: &payment_method_data::Card<T>) -> Result<Self, Self::Error> {
        let card_type = match ccard.card_network.clone().and_then(get_boa_card_type) {
            Some(card_network) => Some(card_network.to_string()),
            None => domain_types::utils::get_card_issuer(ccard.card_number.peek())
                .ok()
                .map(card_issuer_to_string),
        };
        Ok(Self::Cards(Box::new(CardPaymentInformation {
            card: Card {
                number: ccard.card_number.clone(),
                expiration_month: ccard.card_exp_month.clone(),
                expiration_year: ccard.card_exp_year.clone(),
                security_code: Some(ccard.card_cvc.clone()),
                card_type,
            },
        })))
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        ApplePayWalletData,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (item, apple_pay_data): (
            &BankofamericaRouterData<
                RouterDataV2<
                    SetupMandate,
                    PaymentFlowData,
                    SetupMandateRequestData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            ApplePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let order_information = OrderInformationWithBill::try_from(item)?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);
        let payment_information = match item
            .router_data
            .resource_common_data
            .payment_method_token
            .clone()
        {
            Some(payment_method_token) => match payment_method_token {
                PaymentMethodToken::ApplePayDecrypt(decrypt_data) => {
                    PaymentInformation::try_from(&decrypt_data)?
                }
                PaymentMethodToken::Token(_) => Err(unimplemented_payment_method!(
                    "Apple Pay",
                    "Manual",
                    "Bank Of America"
                ))?,
                PaymentMethodToken::PazeDecrypt(_) => {
                    Err(unimplemented_payment_method!("Paze", "Bank Of America"))?
                }
                PaymentMethodToken::GooglePayDecrypt(_) => Err(unimplemented_payment_method!(
                    "Google Pay",
                    "Bank Of America"
                ))?,
            },
            None => PaymentInformation::try_from(&apple_pay_data)?,
        };
        let processing_information: ProcessingInformation = ProcessingInformation::try_from((
            item,
            Some(PaymentSolution::ApplePay),
            Some(apple_pay_data.payment_method.network.clone()),
        ))?;
        let ucaf_collection_indicator = match apple_pay_data
            .payment_method
            .network
            .to_lowercase()
            .as_str()
        {
            "mastercard" => Some("2".to_string()),
            _ => None,
        };
        let consumer_authentication_information = Some(BankOfAmericaConsumerAuthInformation {
            ucaf_collection_indicator,
            cavv: None,
            ucaf_authentication_data: None,
            xid: None,
            directory_server_transaction_id: None,
            specification_version: None,
        });

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information,
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
    > TryFrom<&ApplePayWalletData> for PaymentInformation<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(apple_pay_data: &ApplePayWalletData) -> Result<Self, Self::Error> {
        let apple_pay_encrypted_data = apple_pay_data
            .payment_data
            .get_encrypted_apple_pay_payment_data_mandatory()
            .change_context(errors::ConnectorError::MissingRequiredField {
                field_name: "Apple pay encrypted data",
            })?;

        Ok(Self::ApplePayToken(Box::new(
            ApplePayTokenPaymentInformation {
                fluid_data: FluidData {
                    value: Secret::from(apple_pay_encrypted_data.clone()),
                    descriptor: None,
                },
                tokenized_card: ApplePayTokenizedCard {
                    transaction_type: TransactionType::ApplePay,
                },
            },
        )))
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<&Box<ApplePayPredecryptData>> for PaymentInformation<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(apple_pay_data: &Box<ApplePayPredecryptData>) -> Result<Self, Self::Error> {
        let expiration_month = apple_pay_data.get_expiry_month().change_context(
            errors::ConnectorError::InvalidDataFormat {
                field_name: "expiration_month",
            },
        )?;

        let expiration_year = apple_pay_data.get_four_digit_expiry_year();

        Ok(Self::ApplePay(Box::new(ApplePayPaymentInformation {
            tokenized_card: TokenizedCard {
                number: apple_pay_data
                    .application_primary_account_number
                    .clone()
                    .peek()
                    .parse::<cards::CardNumber>()
                    .map_err(|err| {
                        tracing::error!(
                            "Failed to parse Apple Pay account number as CardNumber: {:?}",
                            err
                        );
                        report!(ConnectorError::RequestEncodingFailed)
                    })?,
                cryptogram: apple_pay_data
                    .payment_data
                    .online_payment_cryptogram
                    .clone(),
                transaction_type: TransactionType::ApplePay,
                expiration_year,
                expiration_month,
            },
        })))
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        GooglePayWalletData,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (item, google_pay_data): (
            &BankofamericaRouterData<
                RouterDataV2<
                    SetupMandate,
                    PaymentFlowData,
                    SetupMandateRequestData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            GooglePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let order_information = OrderInformationWithBill::try_from(item)?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);
        let payment_information = PaymentInformation::try_from(&google_pay_data)?;
        let processing_information =
            ProcessingInformation::try_from((item, Some(PaymentSolution::GooglePay), None))?;

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information: None,
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
    > TryFrom<&GooglePayWalletData> for PaymentInformation<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(google_pay_data: &GooglePayWalletData) -> Result<Self, Self::Error> {
        Ok(Self::GooglePay(Box::new(GooglePayPaymentInformation {
            fluid_data: FluidData {
                value: Secret::from(
                    BASE64_ENGINE.encode(
                        google_pay_data
                            .tokenization_data
                            .get_encrypted_google_pay_token()
                            .change_context(errors::ConnectorError::MissingRequiredField {
                                field_name: "gpay wallet_token",
                            })?
                            .clone(),
                    ),
                ),
                descriptor: None,
            },
        })))
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
        BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for OrderInformationWithBill
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let email = item
            .router_data
            .request
            .get_email()
            .or(item.router_data.resource_common_data.get_billing_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        Ok(Self {
            amount_details: Amount {
                total_amount: StringMajorUnit::zero(),
                currency: item.router_data.request.currency,
            },
            bill_to: Some(bill_to),
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        String,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (item, connector_mandate_id): (
            &BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            String,
        ),
    ) -> Result<Self, Self::Error> {
        let processing_information = ProcessingInformation::try_from((item, None, None))?;
        let payment_instrument = BankOfAmericaPaymentInstrument {
            id: connector_mandate_id.into(),
        };
        let bill_to = item.router_data.request.get_email().ok().and_then(|email| {
            build_bill_to(
                item.router_data.resource_common_data.get_optional_billing(),
                email,
            )
            .ok()
        });
        let order_information = OrderInformationWithBill::try_from((item, bill_to))?;
        let payment_information =
            PaymentInformation::MandatePayment(Box::new(MandatePaymentInformation {
                payment_instrument,
            }));
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);
        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information: None,
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        GooglePayWalletData,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (item, google_pay_data): (
            &BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            GooglePayWalletData,
        ),
    ) -> Result<Self, Self::Error> {
        let email = item.router_data.request.get_email()?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::try_from((item, Some(bill_to)))?;
        let payment_information = PaymentInformation::try_from(&google_pay_data)?;
        let processing_information =
            ProcessingInformation::try_from((item, Some(PaymentSolution::GooglePay), None))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            merchant_defined_information,
            consumer_authentication_information: None,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamsungPayFluidDataValue {
    public_key_hash: Secret<String>,
    version: String,
    data: Secret<String>,
}

fn get_samsung_pay_fluid_data_value(
    samsung_pay_token_data: &payment_method_data::SamsungPayTokenData,
) -> Result<SamsungPayFluidDataValue, error_stack::Report<errors::ConnectorError>> {
    let samsung_pay_header = jwt::decode_header(samsung_pay_token_data.data.clone().peek())
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Failed to decode samsung pay header")?;

    let samsung_pay_kid_optional = samsung_pay_header.kid;

    let samsung_pay_fluid_data_value = SamsungPayFluidDataValue {
        public_key_hash: Secret::new(
            samsung_pay_kid_optional
                .get_required_value("samsung pay public_key_hash")
                .change_context(errors::ConnectorError::RequestEncodingFailed)?
                .to_string(),
        ),
        version: samsung_pay_token_data.version.clone(),
        data: Secret::new(BASE64_ENGINE.encode(samsung_pay_token_data.data.peek())),
    };
    Ok(samsung_pay_fluid_data_value)
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Box<SamsungPayWalletData>,
    )> for BankofamericaPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (item, samsung_pay_data): (
            &BankofamericaRouterData<
                RouterDataV2<
                    Authorize,
                    PaymentFlowData,
                    PaymentsAuthorizeData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Box<SamsungPayWalletData>,
        ),
    ) -> Result<Self, Self::Error> {
        let email = item
            .router_data
            .request
            .get_email()
            .or(item.router_data.resource_common_data.get_billing_email())?;
        let bill_to = build_bill_to(
            item.router_data.resource_common_data.get_optional_billing(),
            email,
        )?;
        let order_information = OrderInformationWithBill::try_from((item, Some(bill_to)))?;

        let samsung_pay_fluid_data_value =
            get_samsung_pay_fluid_data_value(&samsung_pay_data.payment_credential.token_data)?;

        let samsung_pay_fluid_data_str = serde_json::to_string(&samsung_pay_fluid_data_value)
            .change_context(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("Failed to serialize samsung pay fluid data")?;

        let payment_information =
            PaymentInformation::SamsungPay(Box::new(SamsungPayPaymentInformation {
                fluid_data: FluidData {
                    value: Secret::new(BASE64_ENGINE.encode(samsung_pay_fluid_data_str)),
                    descriptor: Some(BASE64_ENGINE.encode(FLUID_DATA_DESCRIPTOR_FOR_SAMSUNG_PAY)),
                },
                tokenized_card: SamsungPayTokenizedCard {
                    transaction_type: TransactionType::SamsungPay,
                },
            }));

        let processing_information = ProcessingInformation::try_from((
            item,
            Some(PaymentSolution::SamsungPay),
            Some(samsung_pay_data.payment_credential.card_brand.to_string()),
        ))?;
        let client_reference_information = ClientReferenceInformation::from(item);
        let merchant_defined_information = item
            .router_data
            .request
            .metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);

        Ok(Self {
            processing_information,
            payment_information,
            order_information,
            client_reference_information,
            consumer_authentication_information: None,
            merchant_defined_information,
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
    TryFrom<(
        &BankofamericaRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
        Option<PaymentSolution>,
        Option<String>,
    )> for ProcessingInformation
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (_item, solution, network): (
            &BankofamericaRouterData<
                RouterDataV2<
                    SetupMandate,
                    PaymentFlowData,
                    SetupMandateRequestData<T>,
                    PaymentsResponseData,
                >,
                T,
            >,
            Option<PaymentSolution>,
            Option<String>,
        ),
    ) -> Result<Self, Self::Error> {
        let (action_list, action_token_types, authorization_options) =
            get_boa_mandate_action_details();
        let commerce_indicator = get_commerce_indicator(network);

        Ok(Self {
            capture: Some(false),
            capture_options: None,
            action_list,
            action_token_types,
            authorization_options,
            commerce_indicator,
            payment_solution: solution.map(String::from),
        })
    }
}

impl<F> TryFrom<ResponseRouterData<BankOfAmericaSetupMandatesResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BankOfAmericaSetupMandatesResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BankOfAmericaSetupMandatesResponse::ClientReferenceInformation(info_response) => {
                let mandate_reference =
                    info_response
                        .token_information
                        .clone()
                        .map(|token_info| MandateReference {
                            connector_mandate_id: token_info
                                .payment_instrument
                                .map(|payment_instrument| payment_instrument.id.expose()),
                            payment_method_id: None,
                        });
                let mut mandate_status =
                    map_boa_attempt_status((info_response.status.clone(), false));
                if matches!(mandate_status, common_enums::AttemptStatus::Authorized) {
                    mandate_status = common_enums::AttemptStatus::Charged
                }
                let error_response =
                    get_error_response_if_failure((&info_response, mandate_status, item.http_code));

                Ok(Self {
                    response: match error_response {
                        Some(error) => Err(error),
                        None => Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                info_response.id.clone(),
                            ),
                            redirection_data: None,
                            mandate_reference: mandate_reference.map(Box::new),
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: Some(
                                info_response
                                    .client_reference_information
                                    .code
                                    .clone()
                                    .unwrap_or(info_response.id),
                            ),
                            incremental_authorization_allowed: None,
                            status_code: item.http_code,
                        }),
                    },
                    ..item.router_data
                })
            }
            BankOfAmericaSetupMandatesResponse::ErrorInformation(error_response) => {
                let response = Err(convert_to_error_response_from_error_info(
                    &error_response,
                    item.http_code,
                ));
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
        }
    }
}

fn convert_to_additional_payment_method_connector_response(
    processor_information: &ClientProcessorInformation,
    consumer_authentication_information: &ConsumerAuthenticationInformation,
) -> domain_types::router_data::AdditionalPaymentMethodConnectorResponse {
    let payment_checks = Some(serde_json::json!({
        "avs_response": processor_information.avs,
        "card_verification": processor_information.card_verification,
        "approval_code": processor_information.approval_code,
        "consumer_authentication_response": processor_information.consumer_authentication_response,
        "cavv": consumer_authentication_information.cavv,
        "eci": consumer_authentication_information.eci,
        "eci_raw": consumer_authentication_information.eci_raw,
    }));

    let authentication_data = Some(serde_json::json!({
        "retrieval_reference_number": processor_information.retrieval_reference_number,
        "acs_transaction_id": consumer_authentication_information.acs_transaction_id,
        "system_trace_audit_number": processor_information.system_trace_audit_number,
    }));

    domain_types::router_data::AdditionalPaymentMethodConnectorResponse::Card {
        authentication_data,
        payment_checks,
        card_network: None,
        domestic_network: None,
    }
}

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<BankofamericaPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BankofamericaPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = item;
        match response {
            BankofamericaPaymentsResponse::ClientReferenceInformation(info_response) => {
                let status = map_boa_attempt_status((
                    info_response.status.clone(),
                    router_data.request.is_auto_capture()?,
                ));
                let response =
                    get_payment_response((&info_response, status, http_code)).map_err(|err| *err);
                let connector_response = match router_data.resource_common_data.payment_method {
                    common_enums::PaymentMethod::Card => info_response
                        .processor_information
                        .as_ref()
                        .and_then(|processor_information| {
                            info_response
                                .consumer_authentication_information
                                .as_ref()
                                .map(|consumer_auth_information| {
                                    convert_to_additional_payment_method_connector_response(
                                        processor_information,
                                        consumer_auth_information,
                                    )
                                })
                        })
                        .map(domain_types::router_data::ConnectorResponseData::with_additional_payment_method_data),
                    common_enums::PaymentMethod::CardRedirect
                    | common_enums::PaymentMethod::PayLater
                    | common_enums::PaymentMethod::Wallet
                    | common_enums::PaymentMethod::BankRedirect
                    | common_enums::PaymentMethod::BankTransfer
                    | common_enums::PaymentMethod::Crypto
                    | common_enums::PaymentMethod::BankDebit
                    | common_enums::PaymentMethod::Reward
                    | common_enums::PaymentMethod::RealTimePayment
                    | common_enums::PaymentMethod::MobilePayment
                    | common_enums::PaymentMethod::Upi
                    | common_enums::PaymentMethod::Voucher
                    | common_enums::PaymentMethod::OpenBanking
                    | common_enums::PaymentMethod::GiftCard => None,
                };

                Ok(Self {
                    response,
                    resource_common_data: PaymentFlowData {
                        status,
                        connector_response,
                        ..router_data.resource_common_data
                    },
                    ..router_data
                })
            }
            BankofamericaPaymentsResponse::ErrorInformation(ref error_response) => {
                Ok(map_error_response(
                    &error_response.clone(),
                    ResponseRouterData {
                        response: BankofamericaPaymentsResponse::ErrorInformation(
                            error_response.clone(),
                        ),
                        router_data,
                        http_code,
                    },
                    Some(common_enums::AttemptStatus::Failure),
                ))
            }
        }
    }
}

impl<F> TryFrom<ResponseRouterData<BankofamericaPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BankofamericaPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            BankofamericaPaymentsResponse::ClientReferenceInformation(info_response) => {
                let status = map_boa_attempt_status((info_response.status.clone(), false));
                let response = get_payment_response((&info_response, status, item.http_code))
                    .map_err(|err| *err);
                Ok(Self {
                    response,
                    ..item.router_data
                })
            }
            BankofamericaPaymentsResponse::ErrorInformation(ref error_response) => {
                Ok(map_error_response(&error_response.clone(), item, None))
            }
        }
    }
}

impl<F> TryFrom<ResponseRouterData<BankOfAmericaTransactionResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<BankOfAmericaTransactionResponse, Self>,
    ) -> Result<Self, Self::Error> {
        match item.response.application_information.status {
            Some(app_status) => {
                let status = map_boa_attempt_status((
                    app_status,
                    item.router_data.request.is_auto_capture()?,
                ));

                let risk_info: Option<ClientRiskInformation> = None;
                if is_payment_failure(status) {
                    Ok(Self {
                        response: Err(get_error_response(
                            &item.response.error_information,
                            &item.response.processor_information,
                            &risk_info,
                            Some(status),
                            item.http_code,
                            item.response.id.clone(),
                        )),
                        ..item.router_data
                    })
                } else {
                    Ok(Self {
                        response: Ok(PaymentsResponseData::TransactionResponse {
                            resource_id: ResponseId::ConnectorTransactionId(
                                item.response.id.clone(),
                            ),
                            redirection_data: None,
                            mandate_reference: None,
                            connector_metadata: None,
                            network_txn_id: None,
                            connector_response_reference_id: item
                                .response
                                .client_reference_information
                                .map(|cref| cref.code)
                                .unwrap_or(Some(item.response.id)),
                            incremental_authorization_allowed: None,
                            status_code: item.http_code,
                        }),
                        ..item.router_data
                    })
                }
            }
            None => Ok(Self {
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(item.response.id),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                }),
                ..item.router_data
            }),
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
        BankofamericaRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for BankofamericaCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: BankofamericaRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_defined_information = item
            .router_data
            .request
            .connector_metadata
            .clone()
            .map(convert_metadata_to_merchant_defined_info);
        Ok(Self {
            order_information: OrderInformation {
                amount_details: Amount {
                    total_amount: item
                        .connector
                        .amount_converter
                        .convert(
                            item.router_data.request.minor_amount_to_capture,
                            item.router_data.request.currency,
                        )
                        .change_context(errors::ConnectorError::AmountConversionFailed)?,
                    currency: item.router_data.request.currency,
                },
            },
            client_reference_information: ClientReferenceInformation {
                code: Some(
                    item.router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
            },
            merchant_defined_information,
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
        BankofamericaRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for BankofamericaVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: BankofamericaRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_defined_information = item
            .router_data
            .request
            .connector_metadata
            .clone()
            .map(|metadata| convert_metadata_to_merchant_defined_info(metadata.expose()));

        let amount = item.router_data.request.amount.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "Amount",
            },
        )?;

        let currency = item.router_data.request.currency.ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "Currency",
            },
        )?;

        Ok(Self {
            client_reference_information: ClientReferenceInformation {
                code: Some(
                    item.router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
            },

            reversal_information: ReversalInformation {
                amount_details: Amount {
                    total_amount: item
                        .connector
                        .amount_converter
                        .convert(amount, currency)
                        .change_context(errors::ConnectorError::AmountConversionFailed)?,
                    currency,
                },
                reason: item.router_data.request.cancellation_reason.clone().ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "Cancellation Reason",
                    },
                )?,
            },
            merchant_defined_information,
        })
    }
}
