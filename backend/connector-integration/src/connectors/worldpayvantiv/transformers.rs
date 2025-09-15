use common_enums::{self, CountryAlpha2, Currency};
use common_utils::{
    types::MinorUnit,
};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, SetupMandate, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsCaptureData, PaymentsAuthorizeData, 
        PaymentsSyncData, RefundFlowData, RefundsData, RefundsResponseData, 
        SetupMandateRequestData, RefundSyncData, ResponseId, PaymentsResponseData, 
        MandateReference,
    },
    errors::ConnectorError,
    payment_method_data::{
        PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        WalletData,
    },
    router_data::{ConnectorAuthType, ErrorResponse, PaymentMethodToken},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    connectors::worldpayvantiv::WorldpayvantivRouterData,
    types::ResponseRouterData,
};

// Helper function to extract report group from connector metadata
fn extract_report_group(connector_meta_data: &Option<hyperswitch_masking::Secret<serde_json::Value>>) -> Option<String> {
    connector_meta_data
        .as_ref()
        .and_then(|metadata| {
            let metadata_value = metadata.peek();
            if let serde_json::Value::String(metadata_str) = metadata_value {
                // Try to parse the metadata string as JSON
                serde_json::from_str::<WorldpayvantivMetadataObject>(metadata_str)
                    .ok()
                    .map(|obj| obj.report_group)
            } else {
                // Try to parse metadata directly as object
                serde_json::from_value::<WorldpayvantivMetadataObject>(metadata_value.clone())
                    .ok()
                    .map(|obj| obj.report_group)
            }
        })
}

// Metadata structures for WorldpayVantiv
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WorldpayvantivMetadataObject {
    pub report_group: String,
    pub merchant_config_currency: common_enums::Currency,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WorldpayvantivPaymentMetadata {
    pub report_group: Option<String>,
}

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// WorldpayVantiv Payments Request - wrapper for all payment flows
#[derive(Debug, Serialize)]
pub struct WorldpayvantivPaymentsRequest<T: PaymentMethodDataTypes> {
    #[serde(flatten)]
    pub cnp_request: CnpOnlineRequest<T>,
}

// TryFrom implementations for macro integration
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<WorldpayvantivRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>>
    for WorldpayvantivPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: WorldpayvantivRouterData<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = WorldpayvantivAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let authentication = Authentication {
            user: auth.user,
            password: auth.password,
        };

        let payment_method_data = &item.router_data.request.payment_method_data;
        let order_source = OrderSource::from(payment_method_data.clone());
        
        // Handle payment info directly without generic constraints
        let payment_info = match payment_method_data {
            PaymentMethodData::Card(card_data) => {
                let card_type = match card_data.card_network.clone() {
                    Some(network) => WorldpayvativCardType::try_from(network)?,
                    None => {
                        return Err(ConnectorError::MissingRequiredField {
                            field_name: "card_network",
                        }.into());
                    }
                };

                let exp_date = format!("{}{}", 
                    card_data.card_exp_month.peek(),
                    card_data.card_exp_year.peek()
                );

                let worldpay_card = WorldpayvantivCardData {
                    card_type,
                    number: card_data.card_number.clone(),
                    exp_date: exp_date.into(),
                    card_validation_num: Some(card_data.card_cvc.clone()),
                };

                PaymentInfo::Card(CardData {
                    card: worldpay_card,
                    processing_type: None,
                    network_transaction_id: None,
                })
            }
            _ => {
                return Err(ConnectorError::NotSupported {
                    message: "Payment method".to_string(),
                    connector: "worldpayvantiv",
                }.into());
            }
        };
        
        let merchant_txn_id = get_valid_transaction_id(
            item.router_data.resource_common_data.connector_request_reference_id.clone(),
            "transaction_id",
        )?;
        let amount = MinorUnit::from(item.router_data.request.minor_amount);
        
        // Extract report group from metadata or use default
        let report_group = extract_report_group(&item.router_data.resource_common_data.connector_meta_data)
            .unwrap_or_else(|| "rtpGrp".to_string());
        
        let bill_to_address = get_billing_address(&item.router_data.resource_common_data.address.get_payment_method_billing().cloned());
        let ship_to_address = get_shipping_address(&item.router_data.resource_common_data.address.get_shipping().cloned());
        
        let (authorization, sale) = if item.router_data.request.is_auto_capture()? && amount != MinorUnit::zero() {
            let sale = Sale {
                id: format!("sale_{}", merchant_txn_id),
                report_group: report_group.clone(),
                customer_id: Some("12345".to_string()),
                order_id: merchant_txn_id.clone(),
                amount,
                order_source,
                bill_to_address,
                ship_to_address,
                payment_info,
                enhanced_data: None,
                processing_instructions: None,
                cardholder_authentication: None,
            };
            (None, Some(sale))
        } else {
            let authorization = Authorization {
                id: format!("auth_{}", merchant_txn_id),
                report_group: report_group.clone(),
                customer_id: Some("12345".to_string()),
                order_id: merchant_txn_id.clone(),
                amount,
                order_source,
                bill_to_address,
                ship_to_address,
                payment_info,
                enhanced_data: None,
                processing_instructions: None,
                cardholder_authentication: None,
            };
            (Some(authorization), None)
        };

        let cnp_request = CnpOnlineRequest {
            version: worldpayvantiv_constants::WORLDPAYVANTIV_VERSION.to_string(),
            xmlns: worldpayvantiv_constants::XMLNS.to_string(),
            merchant_id: auth.merchant_id,
            authentication,
            authorization,
            sale,
            capture: None,
            auth_reversal: None,
            void: None,
            credit: None,
        };

        Ok(WorldpayvantivPaymentsRequest { cnp_request })
    }
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<WorldpayvantivRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>>
    for VantivSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        _item: WorldpayvantivRouterData<RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        // Empty sync request for WorldpayVantiv
        Ok(Self {})
    }
}

pub(super) mod worldpayvantiv_constants {
    pub const WORLDPAYVANTIV_VERSION: &str = "12.23";
    #[allow(dead_code)]
    pub const XML_VERSION: &str = "1.0";
    #[allow(dead_code)]
    pub const XML_ENCODING: &str = "UTF-8";
    #[allow(dead_code)]
    pub const XML_STANDALONE: &str = "yes";
    pub const XMLNS: &str = "http://www.vantivcnp.com/schema";
    pub const MAX_PAYMENT_REFERENCE_ID_LENGTH: usize = 28;
    #[allow(dead_code)]
    pub const XML_CHARGEBACK: &str = "http://www.vantivcnp.com/chargebacks";
    #[allow(dead_code)]
    pub const MAC_FIELD_NUMBER: &str = "39";
    #[allow(dead_code)]
    pub const CUSTOMER_ID_MAX_LENGTH: usize = 50;
    #[allow(dead_code)]
    pub const CUSTOMER_REFERENCE_MAX_LENGTH: usize = 17;
}

#[derive(Debug, Clone)]
pub struct WorldpayvantivAuthType {
    pub user: Secret<String>,
    pub password: Secret<String>,
    pub merchant_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WorldpayvantivAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                key1,
            } => Ok(Self {
                user: api_key.to_owned(),
                password: api_secret.to_owned(),
                merchant_id: key1.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename = "cnpOnlineRequest", rename_all = "camelCase")]
pub struct CnpOnlineRequest<T: PaymentMethodDataTypes> {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "@merchantId")]
    pub merchant_id: Secret<String>,
    pub authentication: Authentication,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sale: Option<Sale<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_reversal: Option<AuthReversal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub void: Option<VoidRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit: Option<RefundRequest>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authentication {
    pub user: Secret<String>,
    pub password: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization<T: PaymentMethodDataTypes> {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    #[serde(rename = "@customerId", skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    pub order_id: String,
    pub amount: MinorUnit,
    pub order_source: OrderSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bill_to_address: Option<BillToAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ship_to_address: Option<ShipToAddress>,
    #[serde(flatten)]
    pub payment_info: PaymentInfo<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced_data: Option<EnhancedData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_instructions: Option<ProcessingInstructions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardholder_authentication: Option<CardholderAuthentication>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sale<T: PaymentMethodDataTypes> {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    #[serde(rename = "@customerId", skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    pub order_id: String,
    pub amount: MinorUnit,
    pub order_source: OrderSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bill_to_address: Option<BillToAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ship_to_address: Option<ShipToAddress>,
    #[serde(flatten)]
    pub payment_info: PaymentInfo<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced_data: Option<EnhancedData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_instructions: Option<ProcessingInstructions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardholder_authentication: Option<CardholderAuthentication>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRequest {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    pub cnp_txn_id: String,
    pub amount: MinorUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced_data: Option<EnhancedData>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthReversal {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    pub cnp_txn_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<MinorUnit>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoidRequest {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    pub cnp_txn_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundRequest {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    pub cnp_txn_id: String,
    pub amount: MinorUnit,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PaymentInfo<T: PaymentMethodDataTypes> {
    Card(CardData<T>),
    Token(TokenData),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardData<T: PaymentMethodDataTypes> {
    pub card: WorldpayvantivCardData<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_type: Option<VantivProcessingType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_transaction_id: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenData {
    pub token: TokenizationData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayvantivCardData<T: PaymentMethodDataTypes> {
    #[serde(rename = "type")]
    pub card_type: WorldpayvativCardType,
    pub number: RawCardNumber<T>,
    pub exp_date: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_validation_num: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenizationData {
    pub cnp_token: Secret<String>,
    pub exp_date: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum VantivProcessingType {
    InitialCOF,
    MerchantInitiatedCOF,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum WorldpayvativCardType {
    Visa,
    #[serde(rename = "MC")]
    MasterCard,
    #[serde(rename = "AX")]
    AmericanExpress,
    #[serde(rename = "DI")]
    Discover,
    #[serde(rename = "DC")]
    DinersClub,
    #[serde(rename = "JC")]
    JCB,
    #[serde(rename = "UP")]
    UnionPay,
}

impl TryFrom<common_enums::CardNetwork> for WorldpayvativCardType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(card_network: common_enums::CardNetwork) -> Result<Self, Self::Error> {
        match card_network {
            common_enums::CardNetwork::Visa => Ok(Self::Visa),
            common_enums::CardNetwork::Mastercard => Ok(Self::MasterCard),
            common_enums::CardNetwork::AmericanExpress => Ok(Self::AmericanExpress),
            common_enums::CardNetwork::Discover => Ok(Self::Discover),
            common_enums::CardNetwork::DinersClub => Ok(Self::DinersClub),
            common_enums::CardNetwork::JCB => Ok(Self::JCB),
            common_enums::CardNetwork::UnionPay => Ok(Self::UnionPay),
            _ => Err(ConnectorError::NotSupported {
                message: "Card network".to_string(),
                connector: "worldpayvantiv",
            }
            .into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderSource {
    #[serde(rename = "ecommerce")]
    Ecommerce,
    #[serde(rename = "installment")]
    Installment,
    #[serde(rename = "mailorder")]
    MailOrder,
    #[serde(rename = "recurring")]
    Recurring,
    #[serde(rename = "telephone")]
    Telephone,
    #[serde(rename = "applepay")]
    ApplePay,
    #[serde(rename = "androidpay")]
    AndroidPay,
}

impl<T: PaymentMethodDataTypes> From<PaymentMethodData<T>> for OrderSource {
    fn from(payment_method_data: PaymentMethodData<T>) -> Self {
        match payment_method_data {
            PaymentMethodData::Wallet(WalletData::ApplePay(_)) => Self::ApplePay,
            PaymentMethodData::Wallet(WalletData::GooglePay(_)) => Self::AndroidPay,
            _ => Self::Ecommerce,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillToAddress {
    pub name: Option<Secret<String>>,
    pub company: Option<String>,
    pub address_line1: Option<Secret<String>>,
    pub address_line2: Option<Secret<String>>,
    pub city: Option<String>,
    pub state: Option<Secret<String>>,
    pub zip: Option<Secret<String>>,
    pub country: Option<CountryAlpha2>,
    pub email: Option<common_utils::pii::Email>,
    pub phone: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShipToAddress {
    pub name: Option<Secret<String>>,
    pub company: Option<String>,
    pub address_line1: Option<Secret<String>>,
    pub address_line2: Option<Secret<String>>,
    pub city: Option<String>,
    pub state: Option<Secret<String>>,
    pub zip: Option<Secret<String>>,
    pub country: Option<CountryAlpha2>,
    pub email: Option<common_utils::pii::Email>,
    pub phone: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnhancedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sales_tax: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tax_exempt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discount_amount: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shipping_amount: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duty_amount: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_item_data: Option<Vec<LineItemData>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LineItemData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_sequence_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_of_measure: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_cost: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_total: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_discount_amount: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commodity_code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingInstructions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypass_velocity_check: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardholderAuthentication {
    pub authentication_value: Secret<String>,
}

// Response structures
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "cnpOnlineResponse", rename_all = "camelCase")]
pub struct CnpOnlineResponse {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@response")]
    pub response_code: String,
    #[serde(rename = "@message")]
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_response: Option<PaymentResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sale_response: Option<PaymentResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_response: Option<CaptureResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_reversal_response: Option<AuthReversalResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub void_response: Option<VoidResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit_response: Option<CreditResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentResponse {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    #[serde(rename = "@customerId", skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    pub cnp_txn_id: String,
    pub order_id: String,
    pub response: WorldpayvantivResponseCode,
    pub message: String,
    pub response_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fraud_result: Option<FraudResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_response: Option<TokenResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_transaction_id: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced_auth_response: Option<EnhancedAuthResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResponse {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    pub cnp_txn_id: String,
    pub response: WorldpayvantivResponseCode,
    pub message: String,
    pub response_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthReversalResponse {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    pub cnp_txn_id: String,
    pub response: WorldpayvantivResponseCode,
    pub message: String,
    pub response_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VoidResponse {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    pub cnp_txn_id: String,
    pub response: WorldpayvantivResponseCode,
    pub message: String,
    pub response_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditResponse {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@reportGroup")]
    pub report_group: String,
    pub cnp_txn_id: String,
    pub response: WorldpayvantivResponseCode,
    pub message: String,
    pub response_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FraudResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avs_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_validation_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advanced_a_v_s_result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    pub cnp_token: Secret<String>,
    pub token_response_code: String,
    pub token_message: String,
    #[serde(rename = "type")]
    pub token_type: String,
    pub bin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnhancedAuthResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_response: Option<NetworkResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResponse {
    pub network_fields: Vec<NetworkField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkField {
    pub field_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_value: Option<String>,
}

// Response codes (comprehensive list)
#[derive(Debug, strum::Display, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum WorldpayvantivResponseCode {
    #[serde(rename = "000")]
    Approved,
    #[serde(rename = "001")]
    TransactionReceived,
    #[serde(rename = "010")]
    PartiallyApproved,
    #[serde(rename = "110")]
    InsufficientFunds,
    #[serde(rename = "120")]
    CallIssuer,
    #[serde(rename = "121")]
    ExceedsApprovalAmountLimit,
    #[serde(rename = "123")]
    ExceedsActivityAmountLimit,
    #[serde(rename = "125")]
    InvalidEffectiveDate,
    #[serde(rename = "301")]
    InvalidAccountNumber,
    #[serde(rename = "302")]
    AccountNumberDoesNotMatchPaymentType,
    #[serde(rename = "303")]
    InvalidExpirationDate,
    #[serde(rename = "304")]
    InvalidCVV,
    #[serde(rename = "305")]
    InvalidCardValidationNum,
    #[serde(rename = "306")]
    ExpiredCard,
    #[serde(rename = "307")]
    InvalidPin,
    #[serde(rename = "308")]
    InvalidTransactionType,
    #[serde(rename = "310")]
    AccountNumberNotOnFile,
    #[serde(rename = "311")]
    AccountNumberLocked,
    #[serde(rename = "320")]
    InvalidLocation,
    #[serde(rename = "321")]
    InvalidMerchantId,
    #[serde(rename = "322")]
    InvalidLocation2,
    #[serde(rename = "323")]
    InvalidMerchantClassCode,
    #[serde(rename = "324")]
    InvalidExpirationDate2,
    #[serde(rename = "325")]
    InvalidData,
    #[serde(rename = "326")]
    InvalidPin2,
    #[serde(rename = "327")]
    ExceedsNumberofPINEntryTries,
    #[serde(rename = "328")]
    InvalidCryptoBox,
    #[serde(rename = "329")]
    InvalidRequestFormat,
    #[serde(rename = "330")]
    InvalidApplicationData,
    #[serde(rename = "340")]
    InvalidMerchantCategoryCode,
    #[serde(rename = "346")]
    TransactionCannotBeCompleted,
    #[serde(rename = "347")]
    TransactionTypeNotSupportedForCard,
    #[serde(rename = "349")]
    TransactionTypeNotAllowedAtTerminal,
    #[serde(rename = "350")]
    GenericDecline,
    #[serde(rename = "351")]
    DeclineByCard,
    #[serde(rename = "352")]
    DoNotHonor,
    #[serde(rename = "353")]
    InvalidMerchant,
    #[serde(rename = "354")]
    PickUpCard,
    #[serde(rename = "355")]
    CardOk,
    #[serde(rename = "356")]
    CallVoiceOperator,
    #[serde(rename = "357")]
    StopRecurring,
    #[serde(rename = "358")]
    NoChecking,
    #[serde(rename = "359")]
    NoCreditAccount,
    #[serde(rename = "360")]
    NoCreditAccountType,
    #[serde(rename = "361")]
    InvalidCreditPlan,
    #[serde(rename = "362")]
    InvalidTransactionCode,
    #[serde(rename = "363")]
    TransactionNotPermittedToCardholderAccount,
    #[serde(rename = "364")]
    TransactionNotPermittedToMerchant,
    #[serde(rename = "365")]
    PINTryExceeded,
    #[serde(rename = "366")]
    SecurityViolation,
    #[serde(rename = "367")]
    HardCapturePickUpCard,
    #[serde(rename = "368")]
    ResponseReceivedTooLate,
    #[serde(rename = "370")]
    SoftDecline,
    #[serde(rename = "400")]
    ContactCardIssuer,
    #[serde(rename = "401")]
    CallVoiceCenter,
    #[serde(rename = "402")]
    InvalidMerchantTerminal,
    #[serde(rename = "410")]
    InvalidAmount,
    #[serde(rename = "411")]
    ResubmitTransaction,
    #[serde(rename = "412")]
    InvalidTransaction,
    #[serde(rename = "413")]
    MerchantNotFound,
    #[serde(rename = "501")]
    PickUpCard2,
    #[serde(rename = "502")]
    ExpiredCard2,
    #[serde(rename = "503")]
    SuspectedFraud,
    #[serde(rename = "504")]
    ContactCardIssuer2,
    #[serde(rename = "505")]
    DoNotHonor2,
    #[serde(rename = "506")]
    InvalidMerchant2,
    #[serde(rename = "507")]
    InsufficientFunds2,
    #[serde(rename = "508")]
    AccountNumberNotOnFile2,
    #[serde(rename = "509")]
    InvalidAmount2,
    #[serde(rename = "510")]
    InvalidCardNumber,
    #[serde(rename = "511")]
    InvalidExpirationDate3,
    #[serde(rename = "512")]
    InvalidCVV2,
    #[serde(rename = "513")]
    InvalidCardValidationNum2,
    #[serde(rename = "514")]
    InvalidPin3,
    #[serde(rename = "515")]
    CardRestricted,
    #[serde(rename = "516")]
    OverCreditLimit,
    #[serde(rename = "517")]
    AccountClosed,
    #[serde(rename = "518")]
    AccountFrozen,
    #[serde(rename = "519")]
    InvalidTransactionType2,
    #[serde(rename = "520")]
    InvalidMerchantId2,
    #[serde(rename = "521")]
    ProcessorNotAvailable,
    #[serde(rename = "522")]
    NetworkTimeOut,
    #[serde(rename = "523")]
    SystemError,
    #[serde(rename = "524")]
    DuplicateTransaction,
    #[serde(rename = "601")]
    OfflineApproval,
    #[serde(rename = "602")]
    VoiceAuthRequired,
    #[serde(rename = "603")]
    AuthenticationRequired,
    #[serde(rename = "604")]
    SecurityCodeRequired,
    #[serde(rename = "605")]
    SecurityCodeNotMatch,
    #[serde(rename = "606")]
    ZipCodeNotMatch,
    #[serde(rename = "607")]
    AddressNotMatch,
    #[serde(rename = "608")]
    AVSFailure,
    #[serde(rename = "609")]
    CVVFailure,
    #[serde(rename = "610")]
    ServiceNotAllowed,
    #[serde(rename = "820")]
    CreditNotSupported,
    #[serde(rename = "821")]
    InvalidCreditAmount,
    #[serde(rename = "822")]
    CreditAmountExceedsDebitAmount,
    #[serde(rename = "823")]
    RefundNotSupported,
    #[serde(rename = "824")]
    InvalidRefundAmount,
    #[serde(rename = "825")]
    RefundAmountExceedsOriginalAmount,
    #[serde(rename = "826")]
    VoidNotSupported,
    #[serde(rename = "827")]
    VoidNotAllowed,
    #[serde(rename = "828")]
    CaptureNotSupported,
    #[serde(rename = "829")]
    CaptureNotAllowed,
    #[serde(rename = "830")]
    InvalidCaptureAmount,
    #[serde(rename = "831")]
    CaptureAmountExceedsAuthAmount,
    #[serde(rename = "832")]
    TransactionAlreadySettled,
    #[serde(rename = "833")]
    TransactionAlreadyVoided,
    #[serde(rename = "834")]
    TransactionAlreadyCaptured,
    #[serde(rename = "835")]
    TransactionNotFound,
}

// Sync structures
#[derive(Debug, Serialize, Deserialize)]
pub struct VantivSyncRequest {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VantivSyncResponse {
    pub transaction_id: String,
    pub merchant_txn_id: Option<String>,
    pub payment_status: PaymentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_detail: Option<PaymentDetail>,
}

#[derive(Debug, strum::Display, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatus {
    NotYetProcessed,
    ProcessedSuccessfully,
    TransactionDeclined,
    StatusUnavailable,
    PaymentStatusNotFound,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentDetail {
    pub merchant_txn_id: Option<String>,
    pub payment_amount: Option<MinorUnit>,
    pub payment_currency: Option<Currency>,
    pub processing_date: Option<String>,
    pub settlement_date: Option<String>,
}

// Sync error response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VantivSyncErrorResponse {
    pub error_messages: Vec<String>,
}

// Dispute structures
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "chargebackRetrievalResponse", rename_all = "camelCase")]
pub struct ChargebackRetrievalResponse {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    pub transaction_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chargeback_case: Option<Vec<ChargebackCase>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChargebackCase {
    pub case_id: String,
    pub merchant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_issued_by_bank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_received_by_vantiv_cnp: Option<String>,
    pub vantiv_cnp_txn_id: String,
    pub cycle: String,
    pub order_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_number_last4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_type: Option<String>,
    pub chargeback_amount: MinorUnit,
    pub chargeback_currency_type: Currency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_txn_day: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chargeback_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_queue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquirer_reference_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chargeback_reference_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_amount: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_by_day: Option<String>,
    pub activity: Vec<Activity>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub activity_date: String,
    pub activity_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_queue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_queue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_amount: Option<MinorUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "chargebackUpdateRequest", rename_all = "camelCase")]
pub struct ChargebackUpdateRequest {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    pub activity_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargebackDocumentUploadResponse {
    pub response_message: String,
    pub response_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VantivDisputeErrorResponse {
    pub errors: Vec<ErrorInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorInfo {
    pub error: String,
}


// Payment flow types
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum WorldpayvantivPaymentFlow {
    Sale,
    Auth,
    Capture,
    Void,
    VoidPC, // VoidPostCapture
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum OperationId {
    Sale,
    Auth,
    Capture,
    Void,
    VoidPC,
    Refund,
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sale => write!(f, "sale"),
            Self::Auth => write!(f, "auth"),
            Self::Capture => write!(f, "capture"),
            Self::Void => write!(f, "void"),
            Self::VoidPC => write!(f, "voidPC"),
            Self::Refund => write!(f, "refund"),
        }
    }
}



// Step 90-93: TryFrom for Authorize response
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
            CnpOnlineResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            CnpOnlineResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        match (item.response.sale_response.as_ref(), item.response.authorization_response.as_ref()) {
            (Some(sale_response), None) => {
                let status = get_attempt_status(WorldpayvantivPaymentFlow::Sale, sale_response.response)?;
                
                if is_payment_failure(status) {
                    let error_response = ErrorResponse {
                        code: sale_response.response.to_string(),
                        message: sale_response.message.clone(),
                        reason: Some(sale_response.message.clone()),
                        status_code: item.http_code,
                        attempt_status: Some(status),
                        connector_transaction_id: Some(sale_response.cnp_txn_id.clone()),
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    };
                    
                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response: Err(error_response),
                        ..item.router_data
                    })
                } else {
                    let payments_response = PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(sale_response.cnp_txn_id.clone()),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: sale_response.network_transaction_id.clone().map(|id| id.expose()),
                        connector_response_reference_id: Some(sale_response.order_id.clone()),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    };
                    
                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response: Ok(payments_response),
                        ..item.router_data
                    })
                }
            }
            (None, Some(auth_response)) => {
                let status = get_attempt_status(WorldpayvantivPaymentFlow::Auth, auth_response.response)?;
                
                if is_payment_failure(status) {
                    let error_response = ErrorResponse {
                        code: auth_response.response.to_string(),
                        message: auth_response.message.clone(),
                        connector_transaction_id: Some(auth_response.cnp_txn_id.clone()),
                        ..Default::default()
                    };
                    
                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response: Err(error_response),
                        ..item.router_data
                    })
                } else {
                    let payments_response = PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(auth_response.cnp_txn_id.clone()),
                        redirection_data: None,
                        mandate_reference: None,
                        connector_metadata: None,
                        network_txn_id: auth_response.network_transaction_id.clone().map(|id| id.expose()),
                        connector_response_reference_id: Some(auth_response.order_id.clone()),
                        incremental_authorization_allowed: None,
                        status_code: item.http_code,
                    };
                    
                    Ok(Self {
                        resource_common_data: PaymentFlowData {
                            status,
                            ..item.router_data.resource_common_data
                        },
                        response: Ok(payments_response),
                        ..item.router_data
                    })
                }
            }
            (None, None) => {
                let error_response = ErrorResponse {
                    code: item.response.response_code,
                    message: item.response.message.clone(),
                    connector_transaction_id: None,
                    ..Default::default()
                };
                
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::Failure,
                        ..item.router_data.resource_common_data
                    },
                    response: Err(error_response),
                    ..item.router_data
                })
            }
            (_, _) => {
                Err(ConnectorError::UnexpectedResponseError(
                    "Only one of 'sale_response' or 'authorization_response' is expected".to_string().into()
                ).into())
            }
        }
    }
}

// Helper functions for creating RawCardNumber from different sources  
fn create_raw_card_number_from_string<T: PaymentMethodDataTypes>(
    card_string: String,
) -> Result<RawCardNumber<T>, error_stack::Report<ConnectorError>>
where
    T::Inner: From<String>,
{
    Ok(RawCardNumber(T::Inner::from(card_string)))
}

fn get_payment_info<T: PaymentMethodDataTypes>(
    payment_method_data: &PaymentMethodData<T>,
    payment_method_token: Option<PaymentMethodToken>,
) -> Result<PaymentInfo<T>, error_stack::Report<ConnectorError>>
where
    T::Inner: From<String> + Clone,
{
    match payment_method_data {
        PaymentMethodData::Card(card_data) => {
            let card_type = match card_data.card_network.clone() {
                Some(network) => WorldpayvativCardType::try_from(network)?,
                None => {
                    // Determine from card number if network not provided
                    return Err(ConnectorError::MissingRequiredField {
                        field_name: "card_network",
                    }.into());
                }
            };

            let exp_date = format!("{}{}", 
                card_data.card_exp_month.peek(),
                card_data.card_exp_year.peek()
            );

            let worldpay_card = WorldpayvantivCardData {
                card_type,
                number: card_data.card_number.clone(),
                exp_date: exp_date.into(),
                card_validation_num: Some(card_data.card_cvc.clone()),
            };

            Ok(PaymentInfo::Card(CardData {
                card: worldpay_card,
                processing_type: None,
                network_transaction_id: None,
            }))
        }
        PaymentMethodData::Wallet(wallet_data) => {
            match wallet_data {
                WalletData::ApplePay(apple_pay_data) => {
                    match payment_method_token {
                        Some(PaymentMethodToken::ApplePayDecrypt(apple_pay_decrypted_data)) => {
                            let card_type = determine_apple_pay_card_type(&apple_pay_data.payment_method.network)?;
                            // Apple Pay doesn't provide separate expiry fields, use placeholder
                            let exp_date = "1299".to_string(); // December 2099 as placeholder
                            
                            let card_number_string = apple_pay_decrypted_data.application_primary_account_number.expose();
                            let raw_card_number = create_raw_card_number_from_string::<T>(card_number_string)?;
                            
                            let worldpay_card = WorldpayvantivCardData {
                                card_type,
                                number: raw_card_number,
                                exp_date: exp_date.into(),
                                card_validation_num: None, // Apple Pay doesn't provide CVV
                            };

                            Ok(PaymentInfo::Card(CardData {
                                card: worldpay_card,
                                processing_type: None,
                                network_transaction_id: None,
                            }))
                        }
                        _ => Err(ConnectorError::MissingRequiredField {
                            field_name: "apple_pay_decrypted_data",
                        }.into())
                    }
                }
                WalletData::GooglePay(google_pay_data) => {
                    match payment_method_token {
                        Some(PaymentMethodToken::GooglePayDecrypt(google_pay_decrypted_data)) => {
                            let card_type = determine_google_pay_card_type(&google_pay_data.info.card_network)?;
                            // Google Pay doesn't provide separate expiry fields, use placeholder
                            let exp_date = "1299".to_string(); // December 2099 as placeholder

                            let card_number_string = google_pay_decrypted_data.payment_method_details.pan.peek().to_string();
                            let raw_card_number = create_raw_card_number_from_string::<T>(card_number_string)?;

                            let worldpay_card = WorldpayvantivCardData {
                                card_type,
                                number: raw_card_number,
                                exp_date: exp_date.into(),
                                card_validation_num: None, // Google Pay doesn't provide CVV
                            };

                            Ok(PaymentInfo::Card(CardData {
                                card: worldpay_card,
                                processing_type: None,
                                network_transaction_id: None,
                            }))
                        }
                        _ => Err(ConnectorError::MissingRequiredField {
                            field_name: "google_pay_decrypted_data",
                        }.into())
                    }
                }
                _ => Err(ConnectorError::NotSupported {
                    message: "Wallet type".to_string(),
                    connector: "worldpayvantiv",
                }.into())
            }
        }
        _ => Err(ConnectorError::NotSupported {
            message: "Payment method".to_string(),
            connector: "worldpayvantiv",
        }.into())
    }
}

fn determine_apple_pay_card_type(network: &str) -> Result<WorldpayvativCardType, error_stack::Report<ConnectorError>> {
    match network.to_lowercase().as_str() {
        "visa" => Ok(WorldpayvativCardType::Visa),
        "mastercard" => Ok(WorldpayvativCardType::MasterCard),
        "amex" => Ok(WorldpayvativCardType::AmericanExpress),
        "discover" => Ok(WorldpayvativCardType::Discover),
        _ => Err(ConnectorError::NotSupported {
            message: format!("Apple Pay network: {}", network),
            connector: "worldpayvantiv",
        }.into())
    }
}

fn determine_google_pay_card_type(network: &str) -> Result<WorldpayvativCardType, error_stack::Report<ConnectorError>> {
    match network.to_lowercase().as_str() {
        "visa" => Ok(WorldpayvativCardType::Visa),
        "mastercard" => Ok(WorldpayvativCardType::MasterCard),
        "amex" => Ok(WorldpayvativCardType::AmericanExpress),
        "discover" => Ok(WorldpayvativCardType::Discover),
        _ => Err(ConnectorError::NotSupported {
            message: format!("Google Pay network: {}", network),
            connector: "worldpayvantiv",
        }.into())
    }
}

fn get_billing_address(billing_address: &Option<domain_types::payment_address::Address>) -> Option<BillToAddress> {
    billing_address.as_ref().map(|addr| BillToAddress {
        name: addr.get_optional_full_name(),
        company: addr.address.as_ref().and_then(|a| a.first_name.as_ref().map(|f| f.peek().to_string())),
        address_line1: addr.address.as_ref().and_then(|a| a.line1.as_ref().map(|l| Secret::new(l.peek().to_string()))),
        address_line2: addr.address.as_ref().and_then(|a| a.line2.as_ref().map(|l| Secret::new(l.peek().to_string()))),
        city: addr.address.as_ref().and_then(|a| a.city.clone()),
        state: addr.address.as_ref().and_then(|a| a.state.as_ref().map(|s| Secret::new(s.peek().to_string()))),
        zip: addr.address.as_ref().and_then(|a| a.zip.as_ref().map(|z| Secret::new(z.peek().to_string()))),
        country: addr.address.as_ref().and_then(|a| a.country),
        email: addr.email.clone(),
        phone: addr.phone.as_ref().and_then(|p| p.number.as_ref().map(|n| Secret::new(n.peek().to_string()))),
    })
}

fn get_shipping_address(shipping_address: &Option<domain_types::payment_address::Address>) -> Option<ShipToAddress> {
    shipping_address.as_ref().map(|addr| ShipToAddress {
        name: addr.get_optional_full_name(),
        company: addr.address.as_ref().and_then(|a| a.first_name.as_ref().map(|f| f.peek().to_string())),
        address_line1: addr.address.as_ref().and_then(|a| a.line1.as_ref().map(|l| Secret::new(l.peek().to_string()))),
        address_line2: addr.address.as_ref().and_then(|a| a.line2.as_ref().map(|l| Secret::new(l.peek().to_string()))),
        city: addr.address.as_ref().and_then(|a| a.city.clone()),
        state: addr.address.as_ref().and_then(|a| a.state.as_ref().map(|s| Secret::new(s.peek().to_string()))),
        zip: addr.address.as_ref().and_then(|a| a.zip.as_ref().map(|z| Secret::new(z.peek().to_string()))),
        country: addr.address.as_ref().and_then(|a| a.country),
        email: addr.email.clone(),
        phone: addr.phone.as_ref().and_then(|p| p.number.as_ref().map(|n| Secret::new(n.peek().to_string()))),
    })
}

fn get_valid_transaction_id(
    id: String,
    _error_field_name: &str,
) -> Result<String, error_stack::Report<ConnectorError>> {
    if id.len() <= worldpayvantiv_constants::MAX_PAYMENT_REFERENCE_ID_LENGTH {
        Ok(id)
    } else {
        Err(ConnectorError::InvalidConnectorConfig {
            config: "Transaction ID length exceeds maximum limit",
        }.into())
    }
}

// Step 94-98: TryFrom for PSync response
impl TryFrom<ResponseRouterData<VantivSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<VantivSyncResponse, RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.payment_status {
            PaymentStatus::ProcessedSuccessfully => common_enums::AttemptStatus::Charged,
            PaymentStatus::TransactionDeclined => common_enums::AttemptStatus::Failure,
            _ => item.router_data.resource_common_data.status,
        };

        let payments_response = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(item.response.transaction_id.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: item.response.merchant_txn_id.clone(),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(payments_response),
            ..item.router_data
        })
    }
}

// TryFrom for Capture request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<WorldpayvantivRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>>
    for WorldpayvantivPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: WorldpayvantivRouterData<RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = WorldpayvantivAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let authentication = Authentication {
            user: auth.user,
            password: auth.password,
        };

        let cnp_txn_id = item.router_data.request.get_connector_transaction_id()
            .change_context(ConnectorError::MissingConnectorTransactionID)?;
        let merchant_txn_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        let capture = CaptureRequest {
            id: format!("capture_{}", merchant_txn_id),
            report_group: "Default".to_string(),
            cnp_txn_id,
            amount: MinorUnit::from(item.router_data.request.minor_amount_to_capture),
            enhanced_data: None,
        };

        let cnp_request = CnpOnlineRequest {
            version: worldpayvantiv_constants::WORLDPAYVANTIV_VERSION.to_string(),
            xmlns: worldpayvantiv_constants::XMLNS.to_string(),
            merchant_id: auth.merchant_id,
            authentication,
            authorization: None,
            sale: None,
            capture: Some(capture),
            auth_reversal: None,
            void: None,
            credit: None,
        };

        Ok(WorldpayvantivPaymentsRequest { cnp_request })
    }
}

// TryFrom for Void request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<WorldpayvantivRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>>
    for WorldpayvantivPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: WorldpayvantivRouterData<RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = WorldpayvantivAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let authentication = Authentication {
            user: auth.user,
            password: auth.password,
        };

        let cnp_txn_id = item.router_data.request.connector_transaction_id.clone();
        let merchant_txn_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        let void = VoidRequest {
            id: format!("void_{}", merchant_txn_id),
            report_group: "Default".to_string(),
            cnp_txn_id,
        };

        let cnp_request = CnpOnlineRequest {
            version: worldpayvantiv_constants::WORLDPAYVANTIV_VERSION.to_string(),
            xmlns: worldpayvantiv_constants::XMLNS.to_string(),
            merchant_id: auth.merchant_id,
            authentication,
            authorization: None,
            sale: None,
            capture: None,
            auth_reversal: None,
            void: Some(void),
            credit: None,
        };

        Ok(WorldpayvantivPaymentsRequest { cnp_request })
    }
}

// TryFrom for Refund request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<WorldpayvantivRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for WorldpayvantivPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: WorldpayvantivRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = WorldpayvantivAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let authentication = Authentication {
            user: auth.user,
            password: auth.password,
        };

        let cnp_txn_id = item.router_data.request.connector_transaction_id.clone();
        let merchant_txn_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        let credit = RefundRequest {
            id: format!("refund_{}", merchant_txn_id),
            report_group: "Default".to_string(),
            cnp_txn_id,
            amount: MinorUnit::from(item.router_data.request.minor_refund_amount),
        };

        let cnp_request = CnpOnlineRequest {
            version: worldpayvantiv_constants::WORLDPAYVANTIV_VERSION.to_string(),
            xmlns: worldpayvantiv_constants::XMLNS.to_string(),
            merchant_id: auth.merchant_id,
            authentication,
            authorization: None,
            sale: None,
            capture: None,
            auth_reversal: None,
            void: None,
            credit: Some(credit),
        };

        Ok(WorldpayvantivPaymentsRequest { cnp_request })
    }
}

// TryFrom for RSync request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<WorldpayvantivRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>>
    for VantivSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        _item: WorldpayvantivRouterData<RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        // Empty sync request for WorldpayVantiv refund sync
        Ok(Self {})
    }
}

// TryFrom for SetupMandate request
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<WorldpayvantivRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>, T>>
    for WorldpayvantivPaymentsRequest<T>
where
    T::Inner: From<String> + Clone,
{
    type Error = error_stack::Report<ConnectorError>;
    
    fn try_from(
        item: WorldpayvantivRouterData<RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let auth = WorldpayvantivAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let authentication = Authentication {
            user: auth.user,
            password: auth.password,
        };

        let payment_method_data = &item.router_data.request.payment_method_data;
        let order_source = OrderSource::from(payment_method_data.clone());
        let payment_info = get_payment_info::<T>(payment_method_data, None)?;
        
        let merchant_txn_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        let bill_to_address = get_billing_address(&item.router_data.resource_common_data.address.get_payment_method_billing().cloned());
        let ship_to_address = get_shipping_address(&item.router_data.resource_common_data.address.get_shipping().cloned());
        
        let authorization = Authorization {
            id: format!("setupmandate_{}", merchant_txn_id),
            report_group: "Default".to_string(),
            customer_id: None,
            order_id: merchant_txn_id.clone(),
            amount: item.router_data.request.minor_amount.unwrap_or(MinorUnit::zero()),
            order_source,
            bill_to_address,
            ship_to_address,
            payment_info,
            enhanced_data: None,
            processing_instructions: None,
            cardholder_authentication: None,
        };

        let cnp_request = CnpOnlineRequest {
            version: worldpayvantiv_constants::WORLDPAYVANTIV_VERSION.to_string(),
            xmlns: worldpayvantiv_constants::XMLNS.to_string(),
            merchant_id: auth.merchant_id,
            authentication,
            authorization: Some(authorization),
            sale: None,
            capture: None,
            auth_reversal: None,
            void: None,
            credit: None,
        };

        Ok(WorldpayvantivPaymentsRequest { cnp_request })
    }
}

impl TryFrom<ResponseRouterData<CnpOnlineResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CnpOnlineResponse, RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        if let Some(credit_response) = item.response.credit_response {
            let status = match credit_response.response {
                WorldpayvantivResponseCode::Approved 
                | WorldpayvantivResponseCode::TransactionReceived => common_enums::RefundStatus::Pending,
                _ => common_enums::RefundStatus::Failure,
            };

            let refunds_response = RefundsResponseData {
                connector_refund_id: credit_response.cnp_txn_id.clone(),
                refund_status: status,
                status_code: item.http_code,
            };

            Ok(Self {
                resource_common_data: RefundFlowData {
                    status,
                    ..item.router_data.resource_common_data
                },
                response: Ok(refunds_response),
                ..item.router_data
            })
        } else {
            let error_response = ErrorResponse {
                code: item.response.response_code,
                message: item.response.message.clone(),
                connector_transaction_id: None,
                ..Default::default()
            };
            
            Ok(Self {
                resource_common_data: RefundFlowData {
                    status: common_enums::RefundStatus::Failure,
                    ..item.router_data.resource_common_data
                },
                response: Err(error_response),
                ..item.router_data
            })
        }
    }
}

// Step 109-113: TryFrom for RSync response
impl TryFrom<ResponseRouterData<VantivSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<VantivSyncResponse, RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.payment_status {
            PaymentStatus::ProcessedSuccessfully => common_enums::RefundStatus::Success,
            PaymentStatus::TransactionDeclined => common_enums::RefundStatus::Failure,
            _ => item.router_data.resource_common_data.status,
        };

        let refunds_response = RefundsResponseData {
            connector_refund_id: item.response.transaction_id.clone(),
            refund_status: status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response: Ok(refunds_response),
            ..item.router_data
        })
    }
}

// Step 114-123: TryFrom for Capture request and response
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        WorldpayvantivRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for CnpOnlineRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: WorldpayvantivRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = WorldpayvantivAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let authentication = Authentication {
            user: auth.user,
            password: auth.password,
        };

        let cnp_txn_id = item.router_data.request.get_connector_transaction_id()
            .change_context(ConnectorError::MissingConnectorTransactionID)?;
        let merchant_txn_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        let capture = CaptureRequest {
            id: format!("capture_{}", merchant_txn_id),
            report_group: "Default".to_string(),
            cnp_txn_id,
            amount: MinorUnit::from(item.router_data.request.minor_amount_to_capture),
            enhanced_data: None,
        };

        Ok(Self {
            version: worldpayvantiv_constants::WORLDPAYVANTIV_VERSION.to_string(),
            xmlns: worldpayvantiv_constants::XMLNS.to_string(),
            merchant_id: auth.merchant_id,
            authentication,
            authorization: None,
            sale: None,
            capture: Some(capture),
            auth_reversal: None,
            void: None,
            credit: None,
        })
    }
}

impl TryFrom<ResponseRouterData<CnpOnlineResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<CnpOnlineResponse, RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>,
    ) -> Result<Self, Self::Error> {
        if let Some(capture_response) = item.response.capture_response {
            let status = get_attempt_status(WorldpayvantivPaymentFlow::Capture, capture_response.response)?;
            
            if is_payment_failure(status) {
                let error_response = ErrorResponse {
                    code: capture_response.response.to_string(),
                    message: capture_response.message.clone(),
                    connector_transaction_id: Some(capture_response.cnp_txn_id.clone()),
                    ..Default::default()
                };
                
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    response: Err(error_response),
                    ..item.router_data
                })
            } else {
                let payments_response = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(capture_response.cnp_txn_id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(capture_response.id.clone()),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                };
                
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(payments_response),
                    ..item.router_data
                })
            }
        } else {
            let error_response = ErrorResponse {
                code: item.response.response_code,
                message: item.response.message.clone(),
                connector_transaction_id: None,
                ..Default::default()
            };
            
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::CaptureFailed,
                    ..item.router_data.resource_common_data
                },
                response: Err(error_response),
                ..item.router_data
            })
        }
    }
}

// Step 124-133: TryFrom for Void request and response
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        WorldpayvantivRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for CnpOnlineRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: WorldpayvantivRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = WorldpayvantivAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let authentication = Authentication {
            user: auth.user,
            password: auth.password,
        };

        let cnp_txn_id = item.router_data.request.connector_transaction_id.clone();
        let merchant_txn_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        let void = VoidRequest {
            id: format!("void_{}", merchant_txn_id),
            report_group: "Default".to_string(),
            cnp_txn_id,
        };

        Ok(Self {
            version: worldpayvantiv_constants::WORLDPAYVANTIV_VERSION.to_string(),
            xmlns: worldpayvantiv_constants::XMLNS.to_string(),
            merchant_id: auth.merchant_id,
            authentication,
            authorization: None,
            sale: None,
            capture: None,
            auth_reversal: None,
            void: Some(void),
            credit: None,
        })
    }
}

impl TryFrom<ResponseRouterData<CnpOnlineResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<CnpOnlineResponse, RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        if let Some(void_response) = item.response.void_response {
            let status = get_attempt_status(WorldpayvantivPaymentFlow::Void, void_response.response)?;
            
            if is_payment_failure(status) {
                let error_response = ErrorResponse {
                    code: void_response.response.to_string(),
                    message: void_response.message.clone(),
                    connector_transaction_id: Some(void_response.cnp_txn_id.clone()),
                    ..Default::default()
                };
                
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    response: Err(error_response),
                    ..item.router_data
                })
            } else {
                let payments_response = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(void_response.cnp_txn_id.clone()),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(void_response.id.clone()),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                };
                
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(payments_response),
                    ..item.router_data
                })
            }
        } else {
            let error_response = ErrorResponse {
                code: item.response.response_code,
                message: item.response.message.clone(),
                connector_transaction_id: None,
                ..Default::default()
            };
            
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::VoidFailed,
                    ..item.router_data.resource_common_data
                },
                response: Err(error_response),
                ..item.router_data
            })
        }
    }
}

// Step 134-143: TryFrom for SetupMandate request and response
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        WorldpayvantivRouterData<
            RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
            T,
        >,
    > for CnpOnlineRequest<T>
where
    T::Inner: From<String> + Clone,
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: WorldpayvantivRouterData<
            RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = WorldpayvantivAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let authentication = Authentication {
            user: auth.user,
            password: auth.password,
        };

        let payment_method_data = &item.router_data.request.payment_method_data;
        let order_source = OrderSource::from(payment_method_data.clone());
        let payment_info = get_payment_info::<T>(payment_method_data, None)?;
        
        let merchant_txn_id = item.router_data.resource_common_data.connector_request_reference_id.clone();
        
        let bill_to_address = get_billing_address(&item.router_data.resource_common_data.address.get_payment_method_billing().cloned());
        let ship_to_address = get_shipping_address(&item.router_data.resource_common_data.address.get_shipping().cloned());
        
        let authorization = Authorization {
            id: format!("setupmandate_{}", merchant_txn_id),
            report_group: "Default".to_string(),
            customer_id: None,
            order_id: merchant_txn_id.clone(),
            amount: item.router_data.request.minor_amount.unwrap_or(MinorUnit::zero()),
            order_source,
            bill_to_address,
            ship_to_address,
            payment_info,
            enhanced_data: None,
            processing_instructions: None,
            cardholder_authentication: None,
        };

        Ok(Self {
            version: worldpayvantiv_constants::WORLDPAYVANTIV_VERSION.to_string(),
            xmlns: worldpayvantiv_constants::XMLNS.to_string(),
            merchant_id: auth.merchant_id,
            authentication,
            authorization: Some(authorization),
            sale: None,
            capture: None,
            auth_reversal: None,
            void: None,
            credit: None,
        })
    }
}

impl<T: PaymentMethodDataTypes> TryFrom<ResponseRouterData<CnpOnlineResponse, RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>>>
    for RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<CnpOnlineResponse, RouterDataV2<SetupMandate, PaymentFlowData, SetupMandateRequestData<T>, PaymentsResponseData>>) -> Result<Self, Self::Error> {
        if let Some(auth_response) = item.response.authorization_response {
            let status = get_attempt_status(WorldpayvantivPaymentFlow::Auth, auth_response.response)?;
            
            if is_payment_failure(status) {
                let error_response = ErrorResponse {
                    code: auth_response.response.to_string(),
                    message: auth_response.message.clone(),
                    connector_transaction_id: Some(auth_response.cnp_txn_id.clone()),
                    ..Default::default()
                };
                
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    response: Err(error_response),
                    ..item.router_data
                })
            } else {
                let mandate_reference = auth_response.token_response.as_ref().map(|token| {
                    Box::new(MandateReference {
                        connector_mandate_id: Some(token.cnp_token.clone().expose()),
                        payment_method_id: None,
                    })
                });

                let payments_response = PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(auth_response.cnp_txn_id.clone()),
                    redirection_data: None,
                    mandate_reference,
                    connector_metadata: None,
                    network_txn_id: auth_response.network_transaction_id.clone().map(|id| id.expose()),
                    connector_response_reference_id: Some(auth_response.order_id.clone()),
                    incremental_authorization_allowed: None,
                    status_code: item.http_code,
                };
                
                Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status,
                        ..item.router_data.resource_common_data
                    },
                    response: Ok(payments_response),
                    ..item.router_data
                })
            }
        } else {
            let error_response = ErrorResponse {
                code: item.response.response_code,
                message: item.response.message.clone(),
                connector_transaction_id: None,
                ..Default::default()
            };
            
            Ok(Self {
                resource_common_data: PaymentFlowData {
                    status: common_enums::AttemptStatus::AuthorizationFailed,
                    ..item.router_data.resource_common_data
                },
                response: Err(error_response),
                ..item.router_data
            })
        }
    }
}

// Status mapping functions
fn get_attempt_status(flow: WorldpayvantivPaymentFlow, response: WorldpayvantivResponseCode) -> Result<common_enums::AttemptStatus, ConnectorError> {
    match response {
        WorldpayvantivResponseCode::Approved
        | WorldpayvantivResponseCode::PartiallyApproved
        | WorldpayvantivResponseCode::OfflineApproval
        | WorldpayvantivResponseCode::TransactionReceived => match flow {
            WorldpayvantivPaymentFlow::Sale => Ok(common_enums::AttemptStatus::Pending),
            WorldpayvantivPaymentFlow::Auth => Ok(common_enums::AttemptStatus::Authorizing),
            WorldpayvantivPaymentFlow::Capture => Ok(common_enums::AttemptStatus::CaptureInitiated),
            WorldpayvantivPaymentFlow::Void => Ok(common_enums::AttemptStatus::VoidInitiated),
            WorldpayvantivPaymentFlow::VoidPC => Ok(common_enums::AttemptStatus::VoidInitiated),
        },
        // Decline codes
        _ => match flow {
            WorldpayvantivPaymentFlow::Sale => Ok(common_enums::AttemptStatus::Failure),
            WorldpayvantivPaymentFlow::Auth => Ok(common_enums::AttemptStatus::AuthorizationFailed),
            WorldpayvantivPaymentFlow::Capture => Ok(common_enums::AttemptStatus::CaptureFailed),
            WorldpayvantivPaymentFlow::Void | WorldpayvantivPaymentFlow::VoidPC => Ok(common_enums::AttemptStatus::VoidFailed),
        }
    }
}

fn is_payment_failure(status: common_enums::AttemptStatus) -> bool {
    matches!(
        status,
        common_enums::AttemptStatus::Failure
            | common_enums::AttemptStatus::AuthorizationFailed
            | common_enums::AttemptStatus::CaptureFailed
            | common_enums::AttemptStatus::VoidFailed
    )
}
