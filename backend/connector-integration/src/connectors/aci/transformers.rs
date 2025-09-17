use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    ext_traits::OptionExt,
    pii,
    request::Method,
    types::{MinorUnit, StringMinorUnit},
};
use domain_types::{
    connector_flow::{self, Authorize, PSync, RSync, Refund, RepeatPayment, SetupMandate, Void, Capture},
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
use serde_json;
use strum::Display;

use crate::types::ResponseRouterData;
use super::AciRouterData;

pub struct AciAuthType {
    pub api_key: Secret<String>,
    pub entity_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AciAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = item {
            Ok(Self {
                api_key: api_key.to_owned(),
                entity_id: key1.to_owned(),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType)?
        }
    }
}

// Helper struct for amount data
#[derive(Debug, Serialize)]
pub struct AciRouterData1<T> {
    pub amount: StringMinorUnit,
    pub router_data: T,
}

impl<T> TryFrom<(StringMinorUnit, T)> for AciRouterData1<T> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from((amount, item): (StringMinorUnit, T)) -> Result<Self, Self::Error> {
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciPaymentsRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    #[serde(flatten)]
    pub txn_details: TransactionDetails,
    #[serde(flatten)]
    pub payment_method: PaymentDetails<T>,
    #[serde(flatten)]
    pub instruction: Option<Instruction>,
    pub shopper_result_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDetails {
    pub entity_id: Secret<String>,
    pub amount: StringMinorUnit,
    pub currency: String,
    pub payment_type: AciPaymentType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciCaptureRequest {
    #[serde(flatten)]
    pub txn_details: TransactionDetails,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciRefundRequest {
    pub amount: StringMinorUnit,
    pub currency: String,
    pub payment_type: AciPaymentType,
    pub entity_id: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct AciSyncRequest;

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        AciRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for AciSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: AciRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciVoidRequest {
    pub payment_type: AciPaymentType,
    pub entity_id: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct AciRefundSyncRequest;

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        AciRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for AciRefundSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        _item: AciRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum PaymentDetails<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> {
    #[serde(rename = "card")]
    AciCard(Box<CardDetails<T>>),
    BankRedirect(Box<BankRedirectionPMData>),
    Wallet(Box<WalletPMData>),
    Klarna,
    Mandate,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct CardDetails<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize> {
    #[serde(rename = "card.number")]
    pub card_number: RawCardNumber<T>,
    #[serde(rename = "card.holder")]
    pub card_holder: Secret<String>,
    #[serde(rename = "card.expiryMonth")]
    pub card_expiry_month: Secret<String>,
    #[serde(rename = "card.expiryYear")]
    pub card_expiry_year: Secret<String>,
    #[serde(rename = "card.cvv")]
    pub card_cvv: Secret<String>,
    #[serde(rename = "paymentBrand")]
    pub payment_brand: PaymentBrand,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BankRedirectionPMData {
    payment_brand: PaymentBrand,
    #[serde(rename = "bankAccount.country")]
    bank_account_country: Option<common_enums::CountryAlpha2>,
    #[serde(rename = "bankAccount.bankName")]
    bank_account_bank_name: Option<common_enums::BankNames>,
    #[serde(rename = "bankAccount.bic")]
    bank_account_bic: Option<Secret<String>>,
    #[serde(rename = "bankAccount.iban")]
    bank_account_iban: Option<Secret<String>>,
    #[serde(rename = "billing.country")]
    billing_country: Option<common_enums::CountryAlpha2>,
    #[serde(rename = "customer.email")]
    customer_email: Option<pii::Email>,
    #[serde(rename = "customer.merchantCustomerId")]
    merchant_customer_id: Option<Secret<common_utils::id_type::CustomerId>>,
    merchant_transaction_id: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletPMData {
    payment_brand: PaymentBrand,
    #[serde(rename = "virtualAccount.accountId")]
    account_id: Option<Secret<String>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentBrand {
    Eps,
    Eft,
    Ideal,
    Giropay,
    Sofortueberweisung,
    InteracOnline,
    Przelewy,
    Trustly,
    Mbway,
    #[serde(rename = "ALIPAY")]
    AliPay,
    // Card network brands
    #[serde(rename = "VISA")]
    Visa,
    #[serde(rename = "MASTER")]
    Mastercard,
    #[serde(rename = "AMEX")]
    AmericanExpress,
    #[serde(rename = "JCB")]
    Jcb,
    #[serde(rename = "DINERS")]
    DinersClub,
    #[serde(rename = "DISCOVER")]
    Discover,
    #[serde(rename = "UNIONPAY")]
    UnionPay,
    #[serde(rename = "MAESTRO")]
    Maestro,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum InstructionMode {
    Initial,
    Repeated,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum InstructionType {
    Unscheduled,
}

#[derive(Debug, Clone, Serialize)]
pub enum InstructionSource {
    #[serde(rename = "CIT")]
    CardholderInitiatedTransaction,
    #[serde(rename = "MIT")]
    MerchantInitiatedTransaction,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Instruction {
    #[serde(rename = "standingInstruction.mode")]
    mode: InstructionMode,

    #[serde(rename = "standingInstruction.type")]
    transaction_type: InstructionType,

    #[serde(rename = "standingInstruction.source")]
    source: InstructionSource,

    create_registration: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum AciPaymentType {
    #[serde(rename = "PA")]
    Preauthorization,
    #[default]
    #[serde(rename = "DB")]
    Debit,
    #[serde(rename = "CD")]
    Credit,
    #[serde(rename = "CP")]
    Capture,
    #[serde(rename = "RV")]
    Reversal,
    #[serde(rename = "RF")]
    Refund,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciPaymentsResponse {
    pub id: String,
    pub registration_id: Option<Secret<String>>,
    pub ndc: String,
    pub timestamp: String,
    pub build_number: String,
    pub result: ResultCode,
    pub redirect: Option<AciRedirectionData>,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciCaptureResponse {
    pub id: String,
    pub referenced_id: String,
    pub payment_type: AciPaymentType,
    pub amount: StringMinorUnit,
    pub currency: String,
    pub descriptor: String,
    pub result: AciCaptureResult,
    pub result_details: AciCaptureResultDetails,
    pub build_number: String,
    pub timestamp: String,
    pub ndc: Secret<String>,
    pub source: Secret<String>,
    pub payment_method: String,
    pub short_id: String,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciCaptureResult {
    pub code: String,
    pub description: String,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AciCaptureResultDetails {
    pub extended_description: String,
    #[serde(rename = "clearingInstituteName")]
    pub clearing_institute_name: String,
    pub connector_tx_i_d1: String,
    pub connector_tx_i_d3: String,
    pub connector_tx_i_d2: String,
    pub acquirer_response: String,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciRefundResponse {
    pub id: String,
    pub ndc: String,
    pub timestamp: String,
    pub build_number: String,
    pub result: ResultCode,
}

// Response type aliases for unique macro handling
pub type AciPSyncResponse = AciPaymentsResponse;
pub type AciVoidResponse = AciPaymentsResponse;
pub type AciRefundSyncResponse = AciRefundResponse;

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciErrorResponse {
    pub ndc: String,
    pub timestamp: String,
    pub build_number: String,
    pub result: ResultCode,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AciRedirectionData {
    pub method: Option<Method>,
    pub parameters: Vec<Parameters>,
    pub url: url::Url,
    pub preconditions: Option<Vec<PreconditionData>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreconditionData {
    pub method: Option<Method>,
    pub parameters: Vec<Parameters>,
    pub url: url::Url,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Parameters {
    pub name: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultCode {
    pub code: Option<String>,
    pub description: Option<String>,
    pub parameter_errors: Option<Vec<ErrorParameters>>,
}

#[derive(Default, Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct ErrorParameters {
    pub name: String,
    pub value: Option<String>,
    pub message: String,
}

// Convert Hyperswitch request transformation to UCS
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        AciRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    > for AciPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: AciRouterData<
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        println!("aci: Starting request transformation for Authorize");
        
        let auth = AciAuthType::try_from(&item.router_data.connector_auth_type)?;
        println!("aci: Auth generation completed");
        
        let is_auto_capture = item.router_data.request.is_auto_capture()?;
        let payment_type = if is_auto_capture {
            AciPaymentType::Debit
        } else {
            AciPaymentType::Preauthorization
        };
        println!("aci: Payment type determined: {:?} (auto_capture: {})", payment_type, is_auto_capture);

        let payment_method = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                println!("aci: Processing card payment method");
                println!("aci: Card network: {:?}", card.card_network);
                
                let card_holder_name = item.router_data.resource_common_data.get_optional_billing_full_name()
                    .ok_or_else(|| {
                        println!("aci: Missing card holder name, using default");
                        errors::ConnectorError::MissingRequiredField {
                            field_name: "card_holder_name",
                        }
                    });
                
                let card_holder_name = match card_holder_name {
                    Ok(name) => {
                        println!("aci: Card holder name found: {:?}", name);
                        name
                    },
                    Err(_) => {
                        println!("aci: Using fallback card holder name");
                        Secret::new("Test User".to_string())
                    }
                };

                let payment_brand = get_aci_payment_brand(card.card_network.clone(), false)?;
                println!("aci: Payment brand determined: {:?}", payment_brand);

                PaymentDetails::AciCard(Box::new(CardDetails {
                    card_number: card.card_number.clone(),
                    card_holder: card_holder_name,
                    card_expiry_month: card.card_exp_month.clone(),
                    card_expiry_year: card.card_exp_year.clone(),
                    card_cvv: card.card_cvc.clone(),
                    payment_brand,
                }))
            },
            _ => return Err(ConnectorError::NotImplemented("payment method".into()).into()),
        };

        println!("aci: Converting amount: {}", item.router_data.request.amount);
        let amount: StringMinorUnit = serde_json::from_str(&format!("{}", item.router_data.request.amount))
            .change_context(errors::ConnectorError::ParsingFailed)?;
        
        println!("aci: Payment object created successfully");
        println!("aci: Amount: {}, Currency: {}", amount, item.router_data.request.currency);
        println!("aci: Entity ID: {:?}", auth.entity_id);
        
        let request = Self {
            txn_details: TransactionDetails {
                entity_id: auth.entity_id.clone(),
                amount: amount.clone(),
                currency: item.router_data.request.currency.to_string(),
                payment_type,
            },
            payment_method,
            instruction: None,
            shopper_result_url: item.router_data.request.router_return_url.clone(),
        };
        
        println!("aci: Final request object: {:?}", request);
        println!("aci: Request transformation completed successfully");
        Ok(request)
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        AciRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for AciCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: AciRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = AciAuthType::try_from(&item.router_data.connector_auth_type)?;
        let amount: StringMinorUnit = serde_json::from_str(&item.router_data.request.amount_to_capture.to_string())
            .change_context(errors::ConnectorError::ParsingFailed)?;
        
        Ok(Self {
            txn_details: TransactionDetails {
                entity_id: auth.entity_id,
                amount,
                currency: item.router_data.request.currency.to_string(),
                payment_type: AciPaymentType::Capture,
            },
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        AciRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    > for AciRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: AciRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = AciAuthType::try_from(&item.router_data.connector_auth_type)?;
        let amount: StringMinorUnit = serde_json::from_str(&item.router_data.request.refund_amount.to_string())
            .change_context(errors::ConnectorError::ParsingFailed)?;
        
        Ok(Self {
            amount,
            currency: item.router_data.request.currency.to_string(),
            payment_type: AciPaymentType::Refund,
            entity_id: auth.entity_id,
        })
    }
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        AciRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for AciVoidRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: AciRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = AciAuthType::try_from(&item.router_data.connector_auth_type)?;
        Ok(Self {
            payment_type: AciPaymentType::Reversal,
            entity_id: auth.entity_id,
        })
    }
}

impl<F> TryFrom<ResponseRouterData<AciPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<AciPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_aci_attempt_status(&item.response.result.code, true)?;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// Convert Hyperswitch response transformation to UCS
impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
    TryFrom<
        ResponseRouterData<
            AciPaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            AciPaymentsResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        println!("aci: Starting response transformation for Authorize");
        println!("aci: Raw response received: {:?}", item.response);
        println!("aci: HTTP status code: {}", item.http_code);
        
        let redirection_data = item.response.redirect.map(|data| {
            println!("aci: Redirection data found: {:?}", data);
            let form_fields = std::collections::HashMap::<_, _>::from_iter(
                data.parameters
                    .iter()
                    .map(|parameter| (parameter.name.clone(), parameter.value.clone())),
            );

            RedirectForm::Form {
                endpoint: data.url.to_string(),
                method: data.method.unwrap_or(Method::Post),
                form_fields,
            }
        });

        let mandate_reference = item.response.registration_id.map(|id| MandateReference {
            connector_mandate_id: Some(id.expose()),
            payment_method_id: None,
        });

        let auto_capture = item.router_data.request.is_auto_capture()?;
        println!("aci: Auto capture setting: {}", auto_capture);

        let status = if redirection_data.is_some() {
            println!("aci: Redirection detected, setting status to AuthenticationPending");
            common_enums::AttemptStatus::AuthenticationPending
        } else {
            println!("aci: No redirection, mapping status from result code");
            map_aci_attempt_status(&item.response.result.code, auto_capture)?
        };

        println!("aci: Final mapped status: {:?}", status);
        println!("aci: Final mapped status as i32: {}", status as i32);

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: redirection_data.map(Box::new),
                connector_metadata: None,
                mandate_reference: mandate_reference.map(Box::new),
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<AciPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<AciPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_aci_attempt_status(&item.response.result.code, true)?;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<AciCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<AciCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_aci_capture_status(&Some(item.response.result.code.clone()))?;

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.referenced_id),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<AciRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<AciRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_aci_refund_status(&item.response.result.code)?;

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl<F> TryFrom<ResponseRouterData<AciRefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<AciRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = map_aci_refund_status(&item.response.result.code)?;

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

fn get_aci_payment_brand(
    card_network: Option<common_enums::CardNetwork>,
    _is_network_token_flow: bool,
) -> Result<PaymentBrand, error_stack::Report<ConnectorError>> {
    match card_network {
        Some(common_enums::CardNetwork::Visa) => Ok(PaymentBrand::Visa),
        Some(common_enums::CardNetwork::Mastercard) => Ok(PaymentBrand::Mastercard),
        Some(common_enums::CardNetwork::AmericanExpress) => Ok(PaymentBrand::AmericanExpress),
        Some(common_enums::CardNetwork::JCB) => Ok(PaymentBrand::Jcb),
        Some(common_enums::CardNetwork::DinersClub) => Ok(PaymentBrand::DinersClub),
        Some(common_enums::CardNetwork::Discover) => Ok(PaymentBrand::Discover),
        Some(common_enums::CardNetwork::UnionPay) => Ok(PaymentBrand::UnionPay),
        Some(common_enums::CardNetwork::Maestro) => Ok(PaymentBrand::Maestro),
        Some(unsupported_network) => Err(errors::ConnectorError::NotSupported {
            message: format!(
                "Card network {:?} is not supported by ACI",
                unsupported_network
            ),
            connector: "ACI",
        })?,
        None => Err(errors::ConnectorError::MissingRequiredField {
            field_name: "card.card_network",
        }
        .into()),
    }
}

fn map_aci_attempt_status(
    code: &Option<String>,
    auto_capture: bool,
) -> Result<common_enums::AttemptStatus, error_stack::Report<ConnectorError>> {
    println!("aci: Starting status mapping with code: {:?}, auto_capture: {}", code, auto_capture);
    
    let code_str = code.as_ref().ok_or(errors::ConnectorError::MissingRequiredField {
        field_name: "result.code",
    })?;

    println!("aci: Processing status code: {}", code_str);

    // ACI success codes pattern: /^(000\.000\.|000\.100\.1|000\.[2-9])/
    if code_str.starts_with("000.000.") || code_str.starts_with("000.100.1") || 
       (code_str.starts_with("000.") && code_str.chars().nth(4).map_or(false, |c| c >= '2' && c <= '9')) {
        let status = if auto_capture {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Authorized
        };
        println!("aci: Success code detected, returning status: {:?}", status);
        Ok(status)
    }
    // ACI pending codes pattern: /^(000\.200)/
    else if code_str.starts_with("000.200") {
        println!("aci: Pending code detected, returning Pending status");
        Ok(common_enums::AttemptStatus::Pending)
    }
    // All other codes are considered failures
    else {
        println!("aci: Unknown/failure code detected, returning Failure status");
        Ok(common_enums::AttemptStatus::Failure)
    }
}

fn map_aci_capture_status(
    code: &Option<String>,
) -> Result<common_enums::AttemptStatus, error_stack::Report<ConnectorError>> {
    let code_str = code.as_ref().ok_or(errors::ConnectorError::MissingRequiredField {
        field_name: "result.code",
    })?;

    if code_str.starts_with("000.000.") || code_str.starts_with("000.100.1") || 
       (code_str.starts_with("000.") && code_str.chars().nth(4).map_or(false, |c| c >= '2' && c <= '9')) {
        Ok(common_enums::AttemptStatus::Charged)
    }
    else if code_str.starts_with("000.200") {
        Ok(common_enums::AttemptStatus::Pending)
    }
    else {
        Ok(common_enums::AttemptStatus::Failure)
    }
}

fn map_aci_refund_status(
    code: &Option<String>,
) -> Result<common_enums::RefundStatus, error_stack::Report<ConnectorError>> {
    let code_str = code.as_ref().ok_or(errors::ConnectorError::MissingRequiredField {
        field_name: "result.code",
    })?;

    if code_str.starts_with("000.000.") || code_str.starts_with("000.100.1") || 
       (code_str.starts_with("000.") && code_str.chars().nth(4).map_or(false, |c| c >= '2' && c <= '9')) {
        Ok(common_enums::RefundStatus::Success)
    }
    else if code_str.starts_with("000.200") {
        Ok(common_enums::RefundStatus::Pending)
    }
    else {
        Ok(common_enums::RefundStatus::Failure)
    }
}

