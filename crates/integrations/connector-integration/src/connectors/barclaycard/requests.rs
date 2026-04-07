use common_enums::CountryAlpha2;
use common_utils::{pii, types::StringMajorUnit};
use domain_types::payment_method_data::{PaymentMethodDataTypes, RawCardNumber};
use hyperswitch_masking::Secret;
use serde::Serialize;

use crate::utils::MerchantDefinedInformation;

/// Fluid data descriptor for Apple Pay in-app payments
/// This is the base64 encoding of "FID=COMMON.APPLE.INAPP.PAYMENT"
pub const FLUID_DATA_DESCRIPTOR: &str = "RklEPUNPTU1PTi5BUFBMRS5JTkFQUC5QQVlNRU5U";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BarclaycardPaymentsRequest<T: PaymentMethodDataTypes + Sync + Send + 'static + Serialize>
{
    pub processing_information: ProcessingInformation,
    pub payment_information: PaymentInformation<T>,
    pub order_information: OrderInformationWithBill,
    pub client_reference_information: ClientReferenceInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingInformation {
    pub commerce_indicator: String,
    pub capture: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_solution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cavv_algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardPaymentInformation<T: PaymentMethodDataTypes + Sync + Send + 'static + Serialize> {
    pub card: Card<T>,
}

/// Fluid data container for tokenized wallet payment data (Apple Pay, Google Pay)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FluidData {
    pub value: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<String>,
}

/// Transaction type for tokenized wallet payments
#[derive(Debug, Serialize)]
pub enum TransactionType {
    #[serde(rename = "1")]
    InApp,
}

/// Apple Pay tokenized card metadata
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayTokenizedCard {
    pub transaction_type: TransactionType,
}

/// Apple Pay token payment information (encrypted blob path)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplePayTokenPaymentInformation {
    pub fluid_data: FluidData,
    pub tokenized_card: ApplePayTokenizedCard,
}

/// Google Pay tokenized card metadata
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayTokenizedCard {
    pub transaction_type: TransactionType,
}

/// Google Pay token payment information (encrypted blob path)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayTokenPaymentInformation {
    pub fluid_data: FluidData,
    pub tokenized_card: GooglePayTokenizedCard,
}

/// Payment solution codes used in ProcessingInformation
pub enum PaymentSolution {
    ApplePay,
    GooglePay,
}

impl From<PaymentSolution> for String {
    fn from(solution: PaymentSolution) -> Self {
        match solution {
            PaymentSolution::ApplePay => "001".to_string(),
            PaymentSolution::GooglePay => "012".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaymentInformation<T: PaymentMethodDataTypes + Sync + Send + 'static + Serialize> {
    Cards(Box<CardPaymentInformation<T>>),
    ApplePayToken(Box<ApplePayTokenPaymentInformation>),
    GooglePayToken(Box<GooglePayTokenPaymentInformation>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card<T: PaymentMethodDataTypes + Sync + Send + 'static + Serialize> {
    pub number: RawCardNumber<T>,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
    pub security_code: Secret<String>,
    #[serde(rename = "type")]
    pub card_type: Option<String>,
    pub type_selection_indicator: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformationWithBill {
    pub amount_details: Amount,
    pub bill_to: Option<BillTo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Amount {
    pub total_amount: StringMajorUnit,
    pub currency: common_enums::Currency,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillTo {
    pub first_name: Secret<String>,
    pub last_name: Secret<String>,
    pub address1: Secret<String>,
    pub locality: String,
    pub administrative_area: Secret<String>,
    pub postal_code: Secret<String>,
    pub country: CountryAlpha2,
    pub email: pii::Email,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientReferenceInformation {
    pub code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformation {
    pub amount_details: Amount,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BarclaycardCaptureRequest {
    pub order_information: OrderInformation,
    pub client_reference_information: ClientReferenceInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BarclaycardVoidRequest {
    pub client_reference_information: ClientReferenceInformation,
    pub reversal_information: ReversalInformation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_defined_information: Option<Vec<MerchantDefinedInformation>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversalInformation {
    pub amount_details: Amount,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BarclaycardRefundRequest {
    pub order_information: OrderInformation,
    pub client_reference_information: ClientReferenceInformation,
}
