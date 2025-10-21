use common_enums::{self, enums, AttemptStatus, RefundStatus};
use common_utils::{consts, ext_traits::OptionExt, pii::Email, types::FloatMajorUnit};
use domain_types::{
    connector_flow::{
        Authorize, CreateConnectorCustomer, PSync, RSync, Refund, RepeatPayment, SetupMandate,
    },
    connector_types::{
        ConnectorCustomerData, ConnectorCustomerResponse, MandateReference, MandateReferenceId,
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, RepeatPaymentData, ResponseId, SetupMandateRequestData,
    },
    errors::ConnectorError,
    payment_method_data::{
        DefaultPCIHolder, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber,
        VaultTokenHolder,
    },
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};

use crate::types::ResponseRouterData;
// Alias to make the transition easier
type HsInterfacesConnectorError = ConnectorError;
use std::str::FromStr;

use error_stack::ResultExt;
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::AuthorizedotnetRouterData;

type Error = error_stack::Report<domain_types::errors::ConnectorError>;

// Constants
const MAX_ID_LENGTH: usize = 20;

// Helper functions for creating RawCardNumber from string
fn create_raw_card_number_for_default_pci(
    card_string: String,
) -> Result<RawCardNumber<DefaultPCIHolder>, Error> {
    let card_number = cards::CardNumber::from_str(&card_string)
        .change_context(ConnectorError::RequestEncodingFailed)?;
    Ok(RawCardNumber(card_number))
}

fn create_raw_card_number_for_vault_token(card_string: String) -> RawCardNumber<VaultTokenHolder> {
    RawCardNumber(card_string)
}

fn get_random_string() -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), MAX_ID_LENGTH)
}

// // Helper traits for working with generic types
// trait RawCardNumberExt<T: PaymentMethodDataTypes> {
//     fn peek(&self) -> &str;
// }

// trait CardExt<T: PaymentMethodDataTypes> {
//     fn get_expiry_date_as_yyyymm(&self, separator: &str) -> Secret<String>;
// }

// // Implementations for DefaultPCIHolder
// impl RawCardNumberExt<DefaultPCIHolder> for RawCardNumber<DefaultPCIHolder> {
//     fn peek(&self) -> &str {
//         self.0.peek()
//     }
// }

// impl CardExt<DefaultPCIHolder> for domain_types::payment_method_data::Card<DefaultPCIHolder> {
//     fn get_expiry_date_as_yyyymm(&self, separator: &str) -> Secret<String> {
//         Secret::new(format!("{}{}{}",
//             self.card_exp_year.peek(),
//             separator,
//             self.card_exp_month.peek()
//         ))
//     }
// }

// // Implementations for VaultTokenHolder
// impl RawCardNumberExt<VaultTokenHolder> for RawCardNumber<VaultTokenHolder> {
//     fn peek(&self) -> &str {
//         &self.0
//     }
// }

// impl CardExt<VaultTokenHolder> for domain_types::payment_method_data::Card<VaultTokenHolder> {
//     fn get_expiry_date_as_yyyymm(&self, separator: &str) -> Secret<String> {
//         Secret::new(format!("{}{}{}",
//             self.card_exp_year.peek(),
//             separator,
//             self.card_exp_month.peek()
//         ))
//     }
// }

// Wrapper for RawCardNumber to provide construction methods
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedotnetRawCardNumber<T: PaymentMethodDataTypes>(pub RawCardNumber<T>);

impl AuthorizedotnetRawCardNumber<DefaultPCIHolder> {
    pub fn from_card_number_string(card_number: String) -> Result<Self, Error> {
        let card_number = cards::CardNumber::from_str(&card_number)
            .change_context(ConnectorError::RequestEncodingFailed)?;
        Ok(AuthorizedotnetRawCardNumber(RawCardNumber(card_number)))
    }
}

impl AuthorizedotnetRawCardNumber<VaultTokenHolder> {
    pub fn from_token_string(token: String) -> Self {
        AuthorizedotnetRawCardNumber(RawCardNumber(token))
    }
}

// Implement From to convert back to RawCardNumber
impl<T: PaymentMethodDataTypes> From<AuthorizedotnetRawCardNumber<T>> for RawCardNumber<T> {
    fn from(wrapper: AuthorizedotnetRawCardNumber<T>) -> Self {
        wrapper.0
    }
}

// Re-export common enums for use in this file
pub mod api_enums {
    pub use common_enums::Currency;
}

pub trait ForeignTryFrom<F>: Sized {
    type Error;

    fn foreign_try_from(from: F) -> Result<Self, Self::Error>;
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MerchantAuthentication {
    name: Secret<String>,
    transaction_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for MerchantAuthentication {
    type Error = Error;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                name: api_key.clone(),
                transaction_key: key1.clone(),
            }),
            _ => Err(error_stack::report!(ConnectorError::FailedToObtainAuthType)),
        }
    }
}

impl ForeignTryFrom<serde_json::Value> for Vec<UserField> {
    type Error = Error;
    fn foreign_try_from(metadata: serde_json::Value) -> Result<Self, Self::Error> {
        let mut vector = Self::new();

        if let serde_json::Value::Object(obj) = metadata {
            for (key, value) in obj {
                vector.push(UserField {
                    name: key,
                    value: match value {
                        serde_json::Value::String(s) => s,
                        _ => value.to_string(),
                    },
                });
            }
        }

        Ok(vector)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationType {
    Final,
    Pre,
}

impl TryFrom<enums::CaptureMethod> for AuthorizationType {
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;

    fn try_from(capture_method: enums::CaptureMethod) -> Result<Self, Self::Error> {
        match capture_method {
            enums::CaptureMethod::Manual => Ok(Self::Pre),
            enums::CaptureMethod::SequentialAutomatic | enums::CaptureMethod::Automatic => {
                Ok(Self::Final)
            }
            enums::CaptureMethod::ManualMultiple | enums::CaptureMethod::Scheduled => {
                Err(error_stack::report!(ConnectorError::NotSupported {
                    message: "Capture method not supported".to_string(),
                    connector: "authorizedotnet",
                }))?
            }
        }
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardDetails<T: PaymentMethodDataTypes> {
    card_number: RawCardNumber<T>,
    expiration_date: Secret<String>, // YYYY-MM
    card_code: Option<Secret<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PaymentDetails<T: PaymentMethodDataTypes> {
    CreditCard(CreditCardDetails<T>),
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TransactionType {
    AuthOnlyTransaction,
    AuthCaptureTransaction,
    PriorAuthCaptureTransaction,
    VoidTransaction,
    RefundTransaction,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    invoice_number: String,
    description: String,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillTo {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    address: Option<Secret<String>>,
    city: Option<String>,
    state: Option<Secret<String>>,
    zip: Option<Secret<String>>,
    country: Option<enums::CountryAlpha2>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShipTo {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    company: Option<String>,
    address: Option<Secret<String>>,
    city: Option<String>,
    state: Option<String>,
    zip: Option<Secret<String>>,
    country: Option<enums::CountryAlpha2>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerDetails {
    id: String,
    email: Option<Email>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserField {
    name: String,
    value: String,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFields {
    user_field: Vec<UserField>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingOptions {
    is_subsequent_auth: bool,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubsequentAuthInformation {
    original_network_trans_id: Secret<String>,
    reason: Reason,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reason {
    Resubmission,
    #[serde(rename = "delayedCharge")]
    DelayedCharge,
    Reauthorization,
    #[serde(rename = "noShow")]
    NoShow,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationIndicator {
    authorization_indicator: AuthorizationType,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ProfileDetails {
    CreateProfileDetails(CreateProfileDetails),
    CustomerProfileDetails(CustomerProfileDetails),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProfileDetails {
    create_profile: bool,
    customer_profile_id: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerProfileDetails {
    customer_profile_id: Secret<String>,
    payment_profile: PaymentProfileDetails,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentProfileDetails {
    payment_profile_id: Secret<String>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetTransactionRequest<T: PaymentMethodDataTypes> {
    // General structure for transaction details in Authorize
    transaction_type: TransactionType,
    amount: Option<FloatMajorUnit>,
    currency_code: Option<api_enums::Currency>,
    payment: Option<PaymentDetails<T>>,
    profile: Option<ProfileDetails>,
    order: Option<Order>,
    customer: Option<CustomerDetails>,
    bill_to: Option<BillTo>,
    user_fields: Option<UserFields>,
    processing_options: Option<ProcessingOptions>,
    subsequent_auth_information: Option<SubsequentAuthInformation>,
    authorization_indicator_type: Option<AuthorizationIndicator>,
    ref_trans_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSettings {
    setting: Vec<TransactionSetting>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSetting {
    setting_name: String,
    setting_value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionRequest<T: PaymentMethodDataTypes> {
    // Used by Authorize Flow, wraps the general transaction request
    merchant_authentication: AuthorizedotnetAuthType,
    ref_id: Option<String>,
    transaction_request: AuthorizedotnetTransactionRequest<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetPaymentsRequest<T: PaymentMethodDataTypes> {
    // Top-level wrapper for Authorize Flow
    create_transaction_request: CreateTransactionRequest<T>,
}

// Implementation for owned RouterData that doesn't depend on reference version
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for AuthorizedotnetPaymentsRequest<T>
{
    type Error = Error;
    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let currency_str = item.router_data.request.currency.to_string();
        let currency = api_enums::Currency::from_str(&currency_str)
            .map_err(|_| error_stack::report!(ConnectorError::RequestEncodingFailed))?;

        // Always create regular transaction request (mandate logic moved to RepeatPayment flow)
        let transaction_request = create_regular_transaction_request(&item, currency)?;

        let ref_id = if item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .len()
            <= MAX_ID_LENGTH
        {
            Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            )
        } else {
            None
        };
        let create_transaction_request = CreateTransactionRequest {
            merchant_authentication,
            ref_id,
            transaction_request,
        };

        Ok(AuthorizedotnetPaymentsRequest {
            create_transaction_request,
        })
    }
}

// Helper function to create regular transaction request (non-mandate)
fn create_regular_transaction_request<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
>(
    item: &AuthorizedotnetRouterData<
        RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        T,
    >,
    currency: api_enums::Currency,
) -> Result<AuthorizedotnetTransactionRequest<T>, Error> {
    let card_data = match &item.router_data.request.payment_method_data {
        PaymentMethodData::Card(card) => Ok(card),
        _ => Err(ConnectorError::RequestEncodingFailed),
    }?;

    let expiry_month = card_data.card_exp_month.peek().clone();
    let year = card_data.card_exp_year.peek().clone();
    let expiry_year = if year.len() == 2 {
        format!("20{year}")
    } else {
        year
    };
    let expiration_date = format!("{expiry_year}-{expiry_month}");

    let credit_card_details = CreditCardDetails {
        card_number: card_data.card_number.clone(),
        expiration_date: Secret::new(expiration_date),
        card_code: Some(card_data.card_cvc.clone()),
    };

    let payment_details = PaymentDetails::CreditCard(credit_card_details);

    let transaction_type = match item.router_data.request.capture_method {
        Some(enums::CaptureMethod::Manual) => TransactionType::AuthOnlyTransaction,
        Some(enums::CaptureMethod::Automatic)
        | None
        | Some(enums::CaptureMethod::SequentialAutomatic) => {
            TransactionType::AuthCaptureTransaction
        }
        Some(_) => {
            return Err(error_stack::report!(ConnectorError::NotSupported {
                message: "Capture method not supported".to_string(),
                connector: "authorizedotnet",
            }))
        }
    };

    let order_description = item
        .router_data
        .resource_common_data
        .connector_request_reference_id
        .clone();

    // Truncate invoice number to 20 characters (Authorize.Net limit)
    let invoice_number = match item.router_data.request.merchant_order_reference_id.clone() {
        Some(invoice_num) => {
            if invoice_num.len() > MAX_ID_LENGTH {
                invoice_num[0..MAX_ID_LENGTH].to_string()
            } else {
                invoice_num
            }
        }
        None => get_random_string(),
    };

    let order = Order {
        invoice_number,
        description: order_description,
    };

    // Extract user fields from metadata
    let user_fields: Option<UserFields> = match item.router_data.request.metadata.clone() {
        Some(metadata) => Some(UserFields {
            user_field: Vec::<UserField>::foreign_try_from(metadata)?,
        }),
        None => None,
    };

    // Process billing address
    let billing_address = item
        .router_data
        .resource_common_data
        .address
        .get_payment_billing();
    let bill_to = billing_address.as_ref().map(|billing| {
        let first_name = billing.address.as_ref().and_then(|a| a.first_name.clone());
        let last_name = billing.address.as_ref().and_then(|a| a.last_name.clone());

        BillTo {
            first_name,
            last_name,
            address: billing.address.as_ref().and_then(|a| a.line1.clone()),
            city: billing.address.as_ref().and_then(|a| a.city.clone()),
            state: billing.address.as_ref().and_then(|a| a.state.clone()),
            zip: billing.address.as_ref().and_then(|a| a.zip.clone()),
            country: billing
                .address
                .as_ref()
                .and_then(|a| a.country)
                .and_then(|api_country| {
                    enums::CountryAlpha2::from_str(&api_country.to_string()).ok()
                }),
        }
    });

    let customer_details = if !item
        .router_data
        .request
        .is_customer_initiated_mandate_payment()
    {
        item.router_data
            .request
            .customer_id
            .as_ref()
            .and_then(|customer| {
                let customer_id = customer.get_string_repr();
                (customer_id.len() <= MAX_ID_LENGTH).then_some(CustomerDetails {
                    id: customer_id.to_string(),
                    email: item.router_data.request.get_optional_email(),
                })
            })
    } else {
        None
    };

    // Check if we should create a profile for future mandate usage
    let profile = if item
        .router_data
        .request
        .is_customer_initiated_mandate_payment()
    {
        Some(ProfileDetails::CreateProfileDetails(CreateProfileDetails {
            create_profile: true,
            customer_profile_id: item
                .router_data
                .resource_common_data
                .connector_customer
                .as_ref()
                .map(|cid| Secret::new(cid.to_string())),
        }))
    } else {
        None
    };

    Ok(AuthorizedotnetTransactionRequest {
        transaction_type,
        amount: Some(
            item.connector
                .amount_converter
                .convert(
                    item.router_data.request.minor_amount,
                    item.router_data.request.currency,
                )
                .change_context(ConnectorError::AmountConversionFailed)
                .attach_printable("Failed to convert payment amount for authorize transaction")?,
        ),
        currency_code: Some(currency),
        payment: Some(payment_details),
        profile,
        order: Some(order),
        customer: customer_details,
        bill_to,
        user_fields,
        processing_options: None,
        subsequent_auth_information: None,
        authorization_indicator_type: match item.router_data.request.capture_method {
            Some(capture_method) => Some(AuthorizationIndicator {
                authorization_indicator: capture_method.try_into()?,
            }),
            None => None,
        },
        ref_trans_id: None,
    })
}

// RepeatPayment request structures
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRepeatPaymentRequest {
    create_transaction_request: CreateRepeatPaymentRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRepeatPaymentRequest {
    merchant_authentication: AuthorizedotnetAuthType,
    ref_id: Option<String>,
    transaction_request: AuthorizedotnetRepeatPaymentTransactionRequest,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRepeatPaymentTransactionRequest {
    transaction_type: TransactionType,
    amount: FloatMajorUnit,
    currency_code: api_enums::Currency,
    profile: Option<ProfileDetails>,
    order: Option<Order>,
    customer: Option<CustomerDetails>,
    user_fields: Option<UserFields>,
    processing_options: Option<ProcessingOptions>,
    subsequent_auth_information: Option<SubsequentAuthInformation>,
    authorization_indicator_type: Option<AuthorizationIndicator>,
}

// Implementation for RepeatPayment request conversion
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
            T,
        >,
    > for AuthorizedotnetRepeatPaymentRequest
{
    type Error = Error;
    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let currency_str = item.router_data.request.currency.to_string();
        let currency = api_enums::Currency::from_str(&currency_str)
            .map_err(|_| error_stack::report!(ConnectorError::RequestEncodingFailed))?;

        // Handle different mandate reference types with appropriate MIT structures
        let (profile, processing_options, subsequent_auth_information) =
            match &item.router_data.request.mandate_reference {
                // Case 1: Mandate-based MIT (using stored customer profile)
                MandateReferenceId::ConnectorMandateId(connector_mandate_ref) => {
                    let mandate_id = connector_mandate_ref
                        .get_connector_mandate_id()
                        .ok_or_else(|| {
                            error_stack::report!(ConnectorError::MissingRequiredField {
                                field_name: "connector_mandate_id"
                            })
                        })?;

                    // Parse mandate_id to extract customer_profile_id and payment_profile_id
                    let profile = mandate_id
                        .split_once('-')
                        .map(|(customer_profile_id, payment_profile_id)| {
                            ProfileDetails::CustomerProfileDetails(CustomerProfileDetails {
                                customer_profile_id: Secret::from(customer_profile_id.to_string()),
                                payment_profile: PaymentProfileDetails {
                                    payment_profile_id: Secret::from(
                                        payment_profile_id.to_string(),
                                    ),
                                },
                            })
                        })
                        .ok_or_else(|| {
                            error_stack::report!(ConnectorError::MissingRequiredField {
                                field_name: "valid mandate_id format (should contain '-')"
                            })
                        })?;

                    (
                        Some(profile),
                        Some(ProcessingOptions {
                            is_subsequent_auth: true,
                        }),
                        None, // No network transaction ID for mandate-based flow
                    )
                }

                // Case 2: Network mandate ID flow (PG agnostic with network trans ID)
                MandateReferenceId::NetworkMandateId(network_trans_id) => (
                    None, // No customer profile for network transaction flow
                    Some(ProcessingOptions {
                        is_subsequent_auth: true,
                    }),
                    Some(SubsequentAuthInformation {
                        original_network_trans_id: Secret::new(network_trans_id.clone()),
                        reason: Reason::Resubmission,
                    }),
                ),

                // Case 3: Network token with NTI - NOT SUPPORTED (same as Hyperswitch)
                MandateReferenceId::NetworkTokenWithNTI(_) => {
                    return Err(error_stack::report!(ConnectorError::NotImplemented(
                        "Network token with NTI not supported for authorizedotnet".to_string(),
                    )))
                }
            };

        // Order description should be connector_request_reference_id (same as Hyperswitch)
        let order_description = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();

        // Invoice number should be merchant_order_reference_id or random string (same as Hyperswitch)
        let invoice_number = match item.router_data.request.merchant_order_reference_id.clone() {
            Some(merchant_order_ref) => {
                if merchant_order_ref.len() <= MAX_ID_LENGTH {
                    merchant_order_ref
                } else {
                    get_random_string()
                }
            }
            None => get_random_string(),
        };

        let order = Order {
            invoice_number,
            description: order_description,
        };

        // Extract user fields from metadata
        let user_fields: Option<UserFields> = match item.router_data.request.metadata.clone() {
            Some(metadata) => {
                let metadata_value = serde_json::to_value(metadata)
                    .change_context(ConnectorError::RequestEncodingFailed)?;
                Some(UserFields {
                    user_field: Vec::<UserField>::foreign_try_from(metadata_value)?,
                })
            }
            None => None,
        };

        // ref_id should be connector_request_reference_id with MAX_ID_LENGTH check (same as Authorize flow)
        let ref_id = if item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .len()
            <= MAX_ID_LENGTH
        {
            Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            )
        } else {
            None
        };

        let customer_id_string = item
            .router_data
            .resource_common_data
            .customer_id
            .as_ref()
            .and_then(|cid| {
                let id_str = cid.get_string_repr().to_owned();
                if id_str.len() > MAX_ID_LENGTH {
                    None
                } else {
                    Some(id_str)
                }
            });

        let customer_details = customer_id_string.map(|cid| CustomerDetails {
            id: cid,
            email: item.router_data.request.email.clone(),
        });

        let transaction_request = AuthorizedotnetRepeatPaymentTransactionRequest {
            transaction_type: TransactionType::AuthCaptureTransaction, // Repeat payments are typically captured immediately
            amount: item
                .connector
                .amount_converter
                .convert(
                    item.router_data.request.minor_amount,
                    item.router_data.request.currency,
                )
                .change_context(ConnectorError::AmountConversionFailed)
                .attach_printable(
                    "Failed to convert payment amount for repeat payment transaction",
                )?,
            currency_code: currency,
            profile,
            order: Some(order),
            customer: customer_details,
            user_fields,
            processing_options,
            subsequent_auth_information,
            authorization_indicator_type: match item.router_data.request.capture_method {
                Some(capture_method) => Some(AuthorizationIndicator {
                    authorization_indicator: capture_method.try_into()?,
                }),
                None => None,
            },
        };

        Ok(Self {
            create_transaction_request: CreateRepeatPaymentRequest {
                merchant_authentication,
                ref_id,
                transaction_request,
            },
        })
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCaptureTransactionInternal {
    // Specific transaction details for Capture
    transaction_type: TransactionType,
    amount: FloatMajorUnit,
    ref_trans_id: String,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCaptureTransactionRequest {
    // Used by Capture Flow, wraps specific capture transaction details
    merchant_authentication: AuthorizedotnetAuthType,
    transaction_request: AuthorizedotnetCaptureTransactionInternal,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCaptureRequest {
    // Top-level wrapper for Capture Flow
    create_transaction_request: CreateCaptureTransactionRequest,
}

// New direct implementation for capture without relying on the reference version
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<
                domain_types::connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for AuthorizedotnetCaptureRequest
{
    type Error = Error;
    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<
                domain_types::connector_flow::Capture,
                PaymentFlowData,
                PaymentsCaptureData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        let original_connector_txn_id = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => {
                return Err(error_stack::report!(
                    HsInterfacesConnectorError::MissingRequiredField {
                        field_name: "connector_transaction_id"
                    }
                ));
            }
        };

        let transaction_request_payload = AuthorizedotnetCaptureTransactionInternal {
            transaction_type: TransactionType::PriorAuthCaptureTransaction,
            amount: item
                .connector
                .amount_converter
                .convert(
                    item.router_data.request.minor_amount_to_capture,
                    item.router_data.request.currency,
                )
                .change_context(ConnectorError::AmountConversionFailed)
                .attach_printable("Failed to convert capture amount for capture transaction")?,
            ref_trans_id: original_connector_txn_id,
        };

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let create_transaction_request_payload = CreateCaptureTransactionRequest {
            merchant_authentication,
            transaction_request: transaction_request_payload,
        };

        Ok(Self {
            create_transaction_request: create_transaction_request_payload,
        })
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetTransactionVoidDetails {
    // Specific transaction details for Void
    transaction_type: TransactionType,
    ref_trans_id: String,
    amount: Option<f64>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionVoidRequest {
    // Used by Void Flow, wraps specific void transaction details
    merchant_authentication: AuthorizedotnetAuthType,
    ref_id: Option<String>,
    transaction_request: AuthorizedotnetTransactionVoidDetails,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetVoidRequest {
    // Top-level wrapper for Void Flow
    create_transaction_request: CreateTransactionVoidRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetAuthType {
    name: Secret<String>,
    transaction_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AuthorizedotnetAuthType {
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        if let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type {
            Ok(Self {
                name: api_key.to_owned(),
                transaction_key: key1.to_owned(),
            })
        } else {
            Err(ConnectorError::FailedToObtainAuthType)?
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
        AuthorizedotnetRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    > for AuthorizedotnetVoidRequest
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<
                domain_types::connector_flow::Void,
                PaymentFlowData,
                domain_types::connector_types::PaymentVoidData,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Extract transaction ID from the connector_transaction_id string
        // This transaction ID comes from the authorization response
        let transaction_id = match router_data.request.connector_transaction_id.as_str() {
            "" => {
                return Err(error_stack::report!(
                    HsInterfacesConnectorError::MissingRequiredField {
                        field_name: "connector_transaction_id"
                    }
                ));
            }
            id => id.to_string(),
        };

        let ref_id = Some(
            &item
                .router_data
                .resource_common_data
                .connector_request_reference_id,
        )
        .filter(|id| !id.is_empty())
        .cloned();

        let ref_id = get_the_truncate_id(ref_id, MAX_ID_LENGTH);

        let transaction_void_details = AuthorizedotnetTransactionVoidDetails {
            transaction_type: TransactionType::VoidTransaction,
            ref_trans_id: transaction_id,
            amount: None,
        };

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&router_data.connector_auth_type)?;

        let create_transaction_void_request = CreateTransactionVoidRequest {
            merchant_authentication,
            ref_id,
            transaction_request: transaction_void_details,
        };

        Ok(Self {
            create_transaction_request: create_transaction_void_request,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDetails {
    pub merchant_authentication: MerchantAuthentication,
    #[serde(rename = "transId")]
    pub transaction_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCreateSyncRequest {
    pub get_transaction_details_request: TransactionDetails,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRSyncRequest {
    pub get_transaction_details_request: TransactionDetails,
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
        AuthorizedotnetRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for AuthorizedotnetCreateSyncRequest
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract connector_transaction_id from the request
        let connector_transaction_id = match &item.router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => {
                return Err(error_stack::report!(
                    HsInterfacesConnectorError::MissingRequiredField {
                        field_name: "connector_transaction_id"
                    }
                ))
            }
        };

        let merchant_authentication =
            MerchantAuthentication::try_from(&item.router_data.connector_auth_type)?;

        let payload = Self {
            get_transaction_details_request: TransactionDetails {
                merchant_authentication,
                transaction_id: Some(connector_transaction_id),
            },
        };
        Ok(payload)
    }
}

// Implementation for the RSync flow to support refund synchronization
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for AuthorizedotnetRSyncRequest
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Extract connector_refund_id from the request
        let connector_refund_id = if !item.router_data.request.connector_refund_id.is_empty() {
            item.router_data.request.connector_refund_id.clone()
        } else {
            return Err(error_stack::report!(
                HsInterfacesConnectorError::MissingRequiredField {
                    field_name: "connector_refund_id"
                }
            ));
        };

        let merchant_authentication =
            MerchantAuthentication::try_from(&item.router_data.connector_auth_type)?;

        let payload = Self {
            get_transaction_details_request: TransactionDetails {
                merchant_authentication,
                transaction_id: Some(connector_refund_id),
            },
        };
        Ok(payload)
    }
}

// Refund-related structs and implementations
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRefundCardDetails {
    card_number: Secret<String>,
    expiration_date: Secret<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
enum AuthorizedotnetRefundPaymentDetails<T: PaymentMethodDataTypes> {
    CreditCard(CreditCardDetails<T>),
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRefundTransactionDetails<T: PaymentMethodDataTypes> {
    transaction_type: TransactionType,
    amount: FloatMajorUnit,
    payment: PaymentDetails<T>,
    ref_trans_id: String,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRefundRequest<T: PaymentMethodDataTypes> {
    create_transaction_request: CreateTransactionRefundRequest<T>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionRefundRequest<T: PaymentMethodDataTypes> {
    merchant_authentication: AuthorizedotnetAuthType,
    ref_id: Option<String>,
    transaction_request: AuthorizedotnetRefundTransactionDetails<T>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardPayment {
    credit_card: CreditCardInfo,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardInfo {
    card_number: String,
    expiration_date: String,
}

// Specific implementation for DefaultPCIHolder
impl
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            DefaultPCIHolder,
        >,
    > for AuthorizedotnetRefundRequest<DefaultPCIHolder>
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            DefaultPCIHolder,
        >,
    ) -> Result<Self, Self::Error> {
        // Get connector metadata which contains payment details
        let payment_details = item
            .router_data
            .request
            .refund_connector_metadata
            .as_ref()
            .get_required_value("refund_connector_metadata")
            .change_context(HsInterfacesConnectorError::MissingRequiredField {
                field_name: "refund_connector_metadata",
            })?
            .clone();

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        // Handle the payment details which might be a JSON string or a serde_json::Value
        let payment_details_inner = payment_details.peek();
        let payment_details_value = match payment_details_inner {
            serde_json::Value::String(s) => {
                serde_json::from_str::<serde_json::Value>(s.as_str())
                    .change_context(HsInterfacesConnectorError::RequestEncodingFailed)?
            }
            _ => payment_details_inner.clone(),
        };

        // For refunds, we need to reconstruct the payment details from the metadata
        let payment_details = match payment_details_value.get("payment") {
            Some(payment_obj) => {
                if let Some(credit_card) = payment_obj.get("creditCard") {
                    let card_number = credit_card
                        .get("cardNumber")
                        .and_then(|v| v.as_str())
                        .unwrap_or("****")
                        .to_string();
                    let expiration_date = credit_card
                        .get("expirationDate")
                        .and_then(|v| v.as_str())
                        .unwrap_or("YYYY-MM")
                        .to_string();

                    // For DefaultPCIHolder, create a proper CardNumber
                    let raw_card_number = create_raw_card_number_for_default_pci(card_number)?;

                    let credit_card_details = CreditCardDetails {
                        card_number: raw_card_number,
                        expiration_date: Secret::new(expiration_date),
                        card_code: None, // Not needed for refunds
                    };
                    PaymentDetails::CreditCard(credit_card_details)
                } else {
                    return Err(error_stack::report!(
                        HsInterfacesConnectorError::MissingRequiredField {
                            field_name: "credit_card_details",
                        }
                    ));
                }
            }
            None => {
                return Err(error_stack::report!(
                    HsInterfacesConnectorError::MissingRequiredField {
                        field_name: "payment_details",
                    }
                ));
            }
        };

        // Build the refund transaction request with parsed payment details
        let transaction_request = AuthorizedotnetRefundTransactionDetails {
            transaction_type: TransactionType::RefundTransaction,
            amount: item
                .connector
                .amount_converter
                .convert(
                    item.router_data.request.minor_refund_amount,
                    item.router_data.request.currency,
                )
                .change_context(ConnectorError::AmountConversionFailed)
                .attach_printable(
                    "Failed to convert refund amount for refund transaction (DefaultPCIHolder)",
                )?,
            payment: payment_details,
            ref_trans_id: item.router_data.request.connector_transaction_id.clone(),
        };

        Ok(Self {
            create_transaction_request: CreateTransactionRefundRequest {
                merchant_authentication,
                ref_id: Some(format!(
                    "refund_{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                )),
                transaction_request,
            },
        })
    }
}

// Specific implementation for VaultTokenHolder
impl
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            VaultTokenHolder,
        >,
    > for AuthorizedotnetRefundRequest<VaultTokenHolder>
{
    type Error = Error;

    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            VaultTokenHolder,
        >,
    ) -> Result<Self, Self::Error> {
        // Get connector metadata which contains payment details
        let payment_details = item
            .router_data
            .request
            .refund_connector_metadata
            .as_ref()
            .get_required_value("refund_connector_metadata")
            .change_context(HsInterfacesConnectorError::MissingRequiredField {
                field_name: "refund_connector_metadata",
            })?
            .clone();

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        // Handle the payment details which might be a JSON string or a serde_json::Value
        let payment_details_inner = payment_details.peek();
        let payment_details_value = match payment_details_inner {
            serde_json::Value::String(s) => {
                serde_json::from_str::<serde_json::Value>(s.as_str())
                    .change_context(HsInterfacesConnectorError::RequestEncodingFailed)?
            }
            _ => payment_details_inner.clone(),
        };

        // For refunds, we need to reconstruct the payment details from the metadata
        let payment_details = match payment_details_value.get("payment") {
            Some(payment_obj) => {
                if let Some(credit_card) = payment_obj.get("creditCard") {
                    let card_number = credit_card
                        .get("cardNumber")
                        .and_then(|v| v.as_str())
                        .unwrap_or("****")
                        .to_string();
                    let expiration_date = credit_card
                        .get("expirationDate")
                        .and_then(|v| v.as_str())
                        .unwrap_or("YYYY-MM")
                        .to_string();

                    // For VaultTokenHolder, use the string directly as a token
                    let raw_card_number = create_raw_card_number_for_vault_token(card_number);

                    let credit_card_details = CreditCardDetails {
                        card_number: raw_card_number,
                        expiration_date: Secret::new(expiration_date),
                        card_code: None, // Not needed for refunds
                    };
                    PaymentDetails::CreditCard(credit_card_details)
                } else {
                    return Err(error_stack::report!(
                        HsInterfacesConnectorError::MissingRequiredField {
                            field_name: "credit_card_details",
                        }
                    ));
                }
            }
            None => {
                return Err(error_stack::report!(
                    HsInterfacesConnectorError::MissingRequiredField {
                        field_name: "payment_details",
                    }
                ));
            }
        };

        // Build the refund transaction request with parsed payment details
        let transaction_request = AuthorizedotnetRefundTransactionDetails {
            transaction_type: TransactionType::RefundTransaction,
            amount: item
                .connector
                .amount_converter
                .convert(
                    item.router_data.request.minor_refund_amount,
                    item.router_data.request.currency,
                )
                .change_context(ConnectorError::AmountConversionFailed)
                .attach_printable(
                    "Failed to convert refund amount for refund transaction (VaultTokenHolder)",
                )?,
            payment: payment_details,
            ref_trans_id: item.router_data.request.connector_transaction_id.clone(),
        };

        let ref_id = Some(&item.router_data.request.refund_id)
            .filter(|id| !id.is_empty())
            .cloned();
        let ref_id = get_the_truncate_id(ref_id, MAX_ID_LENGTH);

        Ok(Self {
            create_transaction_request: CreateTransactionRefundRequest {
                merchant_authentication,
                ref_id,
                transaction_request,
            },
        })
    }
}

// Refund request struct is fully implemented above

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TransactionResponse {
    AuthorizedotnetTransactionResponse(Box<AuthorizedotnetTransactionResponse>),
    AuthorizedotnetTransactionResponseError(Box<AuthorizedotnetTransactionResponseError>),
}

// Base transaction response - used internally
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionProfileInfo {
    customer_profile_id: String,
    customer_payment_profile_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetTransactionResponse {
    response_code: AuthorizedotnetPaymentStatus,
    #[serde(rename = "transId")]
    transaction_id: String,
    #[serde(default)]
    transaction_status: Option<String>,
    #[serde(default)]
    network_trans_id: Option<Secret<String>>,
    #[serde(default)]
    pub(super) account_number: Option<Secret<String>>,
    #[serde(default)]
    pub(super) account_type: Option<Secret<String>>,
    #[serde(default)]
    pub(super) errors: Option<Vec<ErrorMessage>>,
    #[serde(default)]
    secure_acceptance: Option<SecureAcceptance>,
    #[serde(default)]
    profile: Option<TransactionProfileInfo>,
    #[serde(default, rename = "avsResultCode")]
    avs_result_code: Option<String>,
}

// Create flow-specific response types
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetAuthorizeResponse(pub AuthorizedotnetPaymentsResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetCaptureResponse(pub AuthorizedotnetPaymentsResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetVoidResponse(pub AuthorizedotnetPaymentsResponse);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetRepeatPaymentResponse(pub AuthorizedotnetPaymentsResponse);

// Helper function to get AVS response description based on the code
fn get_avs_response_description(code: &str) -> Option<&'static str> {
    match code {
        "A" => Some("The street address matched, but the postal code did not."),
        "B" => Some("No address information was provided."),
        "E" => Some("The AVS check returned an error."),
        "G" => Some("The card was issued by a bank outside the U.S. and does not support AVS."),
        "N" => Some("Neither the street address nor postal code matched."),
        "P" => Some("AVS is not applicable for this transaction."),
        "R" => Some("Retry — AVS was unavailable or timed out."),
        "S" => Some("AVS is not supported by card issuer."),
        "U" => Some("Address information is unavailable."),
        "W" => Some("The US ZIP+4 code matches, but the street address does not."),
        "X" => Some("Both the street address and the US ZIP+4 code matched."),
        "Y" => Some("The street address and postal code matched."),
        "Z" => Some("The postal code matched, but the street address did not."),
        _ => None,
    }
}

// Convert transaction response to additional payment method connector response
fn convert_to_additional_payment_method_connector_response(
    transaction_response: &AuthorizedotnetTransactionResponse,
) -> Option<domain_types::router_data::AdditionalPaymentMethodConnectorResponse> {
    match transaction_response.avs_result_code.as_deref() {
        Some("P") | None => None,
        Some(code) => {
            let description = get_avs_response_description(code);
            let payment_checks = serde_json::json!({
                "avs_result_code": code,
                "description": description
            });

            Some(
                domain_types::router_data::AdditionalPaymentMethodConnectorResponse::Card {
                    authentication_data: None,
                    payment_checks: Some(payment_checks),
                    card_network: None,
                    domestic_network: None,
                },
            )
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundResponse {
    response_code: AuthorizedotnetRefundStatus,
    #[serde(rename = "transId")]
    transaction_id: String,
    network_trans_id: Option<Secret<String>>,
    pub account_number: Option<Secret<String>>,
    pub errors: Option<Vec<ErrorMessage>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetRefundResponse {
    pub transaction_response: RefundResponse,
    pub messages: ResponseMessages,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCreateConnectorCustomerRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    create_customer_profile_request: AuthorizedotnetZeroMandateRequest<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetZeroMandateRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    merchant_authentication: AuthorizedotnetAuthType,
    profile: Profile<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_mode: Option<ValidationMode>,
}

// ShipToList for customer shipping address
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ShipToList {
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    address: Option<Secret<String>>,
    city: Option<String>,
    state: Option<Secret<String>>,
    zip: Option<Secret<String>>,
    country: Option<common_enums::CountryAlpha2>,
    phone_number: Option<Secret<String>>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Profile<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    merchant_customer_id: Option<String>,
    description: Option<String>,
    email: Option<String>,
    payment_profiles: Option<Vec<PaymentProfiles<T>>>,
    ship_to_list: Option<Vec<ShipToList>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentProfiles<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    customer_type: CustomerType,
    payment: PaymentDetails<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CustomerType {
    Individual,
    Business,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationMode {
    // testMode performs a Luhn mod-10 check on the card number, without further validation at connector.
    TestMode,
    // liveMode submits a zero-dollar or one-cent transaction (depending on card type and processor support) to confirm that the card number belongs to an active credit or debit account.
    LiveMode,
}

// SetupMandate request structures - adds payment profile to existing customer
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetSetupMandateRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    create_customer_payment_profile_request: AuthorizedotnetPaymentProfileRequest<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetPaymentProfileRequest<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    merchant_authentication: AuthorizedotnetAuthType,
    customer_profile_id: Secret<String>,
    payment_profile: PaymentProfile<T>,
    validation_mode: ValidationMode,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentProfile<
    T: PaymentMethodDataTypes
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static
        + Serialize,
> {
    #[serde(skip_serializing_if = "Option::is_none")]
    bill_to: Option<BillTo>,
    payment: PaymentDetails<T>,
}

// SetupMandate response structure
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetSetupMandateResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub customer_payment_profile_id_list: Vec<String>,
    pub customer_profile_id: Option<String>,
    #[serde(rename = "customerPaymentProfileId")]
    pub customer_payment_profile_id: Option<String>,
    pub validation_direct_response_list: Option<Vec<Secret<String>>>,
    pub messages: ResponseMessages,
}

// PSync response wrapper - Using direct structure instead of wrapping AuthorizedotnetPaymentsResponse
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetPSyncResponse {
    pub transaction: Option<SyncTransactionResponse>,
    pub messages: ResponseMessages,
}

// Implement From/TryFrom for the response types
impl From<AuthorizedotnetPaymentsResponse> for AuthorizedotnetAuthorizeResponse {
    fn from(response: AuthorizedotnetPaymentsResponse) -> Self {
        Self(response)
    }
}

impl From<AuthorizedotnetPaymentsResponse> for AuthorizedotnetCaptureResponse {
    fn from(response: AuthorizedotnetPaymentsResponse) -> Self {
        Self(response)
    }
}

impl From<AuthorizedotnetPaymentsResponse> for AuthorizedotnetVoidResponse {
    fn from(response: AuthorizedotnetPaymentsResponse) -> Self {
        Self(response)
    }
}

impl From<AuthorizedotnetPaymentsResponse> for AuthorizedotnetRepeatPaymentResponse {
    fn from(response: AuthorizedotnetPaymentsResponse) -> Self {
        Self(response)
    }
}

// We no longer need the From implementation for AuthorizedotnetPSyncResponse since we're using the direct structure

// TryFrom implementations for the router data conversions

impl<
        F,
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize
            + Serialize,
    > TryFrom<ResponseRouterData<AuthorizedotnetAuthorizeResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetAuthorizeResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // Use our helper function to convert the response
        let (status, response_result, connector_response_data) =
            convert_to_payments_response_data_or_error(
                &response.0,
                http_code,
                Operation::Authorize,
                router_data.request.capture_method,
                router_data
                    .resource_common_data
                    .raw_connector_response
                    .clone(),
            )
            .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)?;

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status and connector_response in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = status;
        resource_common_data.connector_response = connector_response_data;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response
        new_router_data.response = response_result;

        Ok(new_router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<AuthorizedotnetCaptureResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetCaptureResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // Use our helper function to convert the response
        let (status, response_result, connector_response_data) =
            convert_to_payments_response_data_or_error(
                &response.0,
                http_code,
                Operation::Capture,
                None,
                router_data
                    .resource_common_data
                    .raw_connector_response
                    .clone(),
            )
            .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)?;

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status and connector_response in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = status;
        resource_common_data.connector_response = connector_response_data;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response
        new_router_data.response = response_result;

        Ok(new_router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<AuthorizedotnetVoidResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetVoidResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;
        // Use our helper function to convert the response
        let (status, response_result, connector_response_data) =
            convert_to_payments_response_data_or_error(
                &response.0,
                http_code,
                Operation::Void,
                None,
                router_data
                    .resource_common_data
                    .raw_connector_response
                    .clone(),
            )
            .change_context(HsInterfacesConnectorError::ResponseHandlingFailed)?;

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status and connector_response in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = status;
        resource_common_data.connector_response = connector_response_data;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response
        new_router_data.response = response_result;

        Ok(new_router_data)
    }
}

impl<F> TryFrom<ResponseRouterData<AuthorizedotnetRepeatPaymentResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetRepeatPaymentResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // Dedicated RepeatPayment response handling (matching Hyperswitch)
        let status = get_hs_status(
            &response.0,
            http_code,
            Operation::Authorize,
            Some(enums::CaptureMethod::Automatic),
        );

        // Extract connector response data
        let connector_response_data = match &response.0.transaction_response {
            Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
                convert_to_additional_payment_method_connector_response(trans_res)
                    .map(domain_types::router_data::ConnectorResponseData::with_additional_payment_method_data)
            }
            _ => None,
        };

        let response_result = match &response.0.transaction_response {
            Some(TransactionResponse::AuthorizedotnetTransactionResponse(transaction_response)) => {
                // Check for errors in the response
                let error = transaction_response.errors.as_ref().and_then(|errors| {
                    errors.first().map(|error| ErrorResponse {
                        code: error.error_code.clone(),
                        message: error.error_text.clone(),
                        reason: Some(error.error_text.clone()),
                        status_code: http_code,
                        attempt_status: Some(status),
                        connector_transaction_id: Some(transaction_response.transaction_id.clone()),
                        network_advice_code: None,
                        network_decline_code: None,
                        network_error_message: None,
                    })
                });

                // Build connector_metadata from account_number
                let connector_metadata = build_connector_metadata(transaction_response);

                // Extract mandate_reference from transaction_response.profile (RepeatPayment returns profile info)
                let mandate_reference = transaction_response.profile.as_ref().map(|profile| {
                    domain_types::connector_types::MandateReference {
                        connector_mandate_id: Some(format!(
                            "{}-{}",
                            profile.customer_profile_id, profile.customer_payment_profile_id
                        )),
                        payment_method_id: None,
                    }
                });

                match error {
                    Some(err) => Err(err),
                    None => Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(
                            transaction_response.transaction_id.clone(),
                        ),
                        redirection_data: None,
                        mandate_reference: mandate_reference.map(Box::new),
                        connector_metadata,
                        network_txn_id: transaction_response
                            .network_trans_id
                            .as_ref()
                            .map(|s| s.peek().clone()),
                        connector_response_reference_id: Some(
                            transaction_response.transaction_id.clone(),
                        ),
                        incremental_authorization_allowed: None,
                        status_code: http_code,
                    }),
                }
            }
            Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_)) | None => {
                let (error_code, error_message) = extract_error_details(&response.0, None);
                Err(create_error_response(
                    http_code,
                    error_code,
                    error_message,
                    status,
                    None,
                    router_data
                        .resource_common_data
                        .raw_connector_response
                        .clone(),
                ))
            }
        };

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status and connector_response in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = status;
        resource_common_data.connector_response = connector_response_data;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response
        new_router_data.response = response_result;

        Ok(new_router_data)
    }
}

impl TryFrom<ResponseRouterData<AuthorizedotnetRefundResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetRefundResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        let transaction_response = &response.transaction_response;
        let refund_status = enums::RefundStatus::from(transaction_response.response_code.clone());

        let error = transaction_response.errors.clone().and_then(|errors| {
            errors.first().map(|error| ErrorResponse {
                code: error.error_code.clone(),
                message: error.error_text.clone(),
                reason: Some(error.error_text.clone()),
                status_code: http_code,
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: Some(transaction_response.transaction_id.clone()),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
            })
        });

        // Create a new RouterDataV2 with updated fields
        let mut new_router_data = router_data;

        // Update the status in resource_common_data
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = refund_status;
        new_router_data.resource_common_data = resource_common_data;

        // Set the response based on whether there was an error
        new_router_data.response = match error {
            Some(err) => Err(err),
            None => Ok(RefundsResponseData {
                connector_refund_id: transaction_response.transaction_id.clone(),
                refund_status,
                status_code: http_code,
            }),
        };

        Ok(new_router_data)
    }
}

// Implementation for PSync flow
impl<F> TryFrom<ResponseRouterData<AuthorizedotnetPSyncResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetPSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // No need to transform the response since we're using the direct structure
        // Use the clean approach with the From trait implementation
        match response.transaction {
            Some(transaction) => {
                let payment_status = AttemptStatus::from(transaction.transaction_status);

                // Create a new RouterDataV2 with updated fields
                let mut new_router_data = router_data;

                // Update the status in resource_common_data
                let mut resource_common_data = new_router_data.resource_common_data.clone();
                resource_common_data.status = payment_status;
                new_router_data.resource_common_data = resource_common_data;

                // Set the response
                new_router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(
                        transaction.transaction_id.clone(),
                    ),
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(transaction.transaction_id.clone()),
                    incremental_authorization_allowed: None,
                    status_code: http_code,
                });

                Ok(new_router_data)
            }
            None => {
                // Handle missing transaction response
                let status = match response.messages.result_code {
                    ResultCode::Error => AttemptStatus::Failure,
                    ResultCode::Ok => AttemptStatus::Pending,
                };

                let error_response = ErrorResponse {
                    status_code: http_code,
                    code: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.code.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.text.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                    reason: None,
                    attempt_status: Some(status),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                };

                // Update router data with status and error response
                let mut new_router_data = router_data;
                let mut resource_common_data = new_router_data.resource_common_data.clone();
                resource_common_data.status = status;
                new_router_data.resource_common_data = resource_common_data;
                new_router_data.response = Err(error_response);

                Ok(new_router_data)
            }
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub enum AuthorizedotnetPaymentStatus {
    #[serde(rename = "1")]
    Approved,
    #[serde(rename = "2")]
    Declined,
    #[serde(rename = "3")]
    Error,
    #[serde(rename = "4")]
    #[default]
    HeldForReview,
    #[serde(rename = "5")]
    RequiresAction, // Maps to hyperswitch_common_enums::enums::AttemptStatus::AuthenticationPending
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub enum AuthorizedotnetRefundStatus {
    #[serde(rename = "1")]
    Approved,
    #[serde(rename = "2")]
    Declined,
    #[serde(rename = "3")]
    Error,
    #[serde(rename = "4")]
    #[default]
    HeldForReview,
}

/// Helper function to extract error code and message from response
fn extract_error_details(
    response: &AuthorizedotnetPaymentsResponse,
    trans_res: Option<&AuthorizedotnetTransactionResponse>,
) -> (String, String) {
    let error_code = trans_res
        .and_then(|tr| {
            tr.errors
                .as_ref()
                .and_then(|e| e.first().map(|e| e.error_code.clone()))
        })
        .or_else(|| response.messages.message.first().map(|m| m.code.clone()))
        .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());

    let error_message = trans_res
        .and_then(|tr| {
            tr.errors
                .as_ref()
                .and_then(|e| e.first().map(|e| e.error_text.clone()))
        })
        .or_else(|| response.messages.message.first().map(|m| m.text.clone()))
        .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string());

    (error_code, error_message)
}

/// Helper function to create error response
fn create_error_response(
    http_status_code: u16,
    error_code: String,
    error_message: String,
    status: AttemptStatus,
    connector_transaction_id: Option<String>,
    _raw_connector_response: Option<Secret<String>>,
) -> ErrorResponse {
    ErrorResponse {
        status_code: http_status_code,
        code: error_code,
        message: error_message,
        reason: None,
        attempt_status: Some(status),
        connector_transaction_id,
        network_decline_code: None,
        network_advice_code: None,
        network_error_message: None,
    }
}

impl From<AuthorizedotnetRefundStatus> for enums::RefundStatus {
    fn from(item: AuthorizedotnetRefundStatus) -> Self {
        match item {
            AuthorizedotnetRefundStatus::Declined | AuthorizedotnetRefundStatus::Error => {
                Self::Failure
            }
            AuthorizedotnetRefundStatus::Approved | AuthorizedotnetRefundStatus::HeldForReview => {
                Self::Pending
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorMessage {
    pub error_code: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthorizedotnetTransactionResponseError {
    _supplemental_data_qualification_indicator: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecureAcceptance {
    // Define fields for SecureAcceptance if it's actually used and its structure is known
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMessage {
    pub code: String,
    pub text: String,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ResultCode {
    #[default]
    Ok,
    Error,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMessages {
    result_code: ResultCode,
    pub message: Vec<ResponseMessage>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetPaymentsResponse {
    pub transaction_response: Option<TransactionResponse>,
    pub profile_response: Option<AuthorizedotnetNonZeroMandateResponse>,
    pub messages: ResponseMessages,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetNonZeroMandateResponse {
    customer_profile_id: Option<String>,
    customer_payment_profile_id_list: Option<Vec<String>>,
    pub messages: ResponseMessages,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Operation {
    Authorize,
    Capture,
    Void,
    Refund,
}

fn get_hs_status(
    response: &AuthorizedotnetPaymentsResponse,
    _http_status_code: u16,
    operation: Operation,
    capture_method: Option<enums::CaptureMethod>,
) -> AttemptStatus {
    // Return failure immediately if result code is Error
    if response.messages.result_code == ResultCode::Error {
        return AttemptStatus::Failure;
    }

    // Handle case when transaction_response is None
    if response.transaction_response.is_none() {
        return match operation {
            Operation::Void => AttemptStatus::Voided,
            Operation::Authorize | Operation::Capture => AttemptStatus::Pending,
            Operation::Refund => AttemptStatus::Failure,
        };
    }

    // Now handle transaction_response cases
    match response.transaction_response.as_ref().unwrap() {
        TransactionResponse::AuthorizedotnetTransactionResponseError(_) => AttemptStatus::Failure,
        TransactionResponse::AuthorizedotnetTransactionResponse(trans_res) => {
            match trans_res.response_code {
                AuthorizedotnetPaymentStatus::Declined | AuthorizedotnetPaymentStatus::Error => {
                    AttemptStatus::Failure
                }
                AuthorizedotnetPaymentStatus::HeldForReview => AttemptStatus::Pending,
                AuthorizedotnetPaymentStatus::RequiresAction => {
                    AttemptStatus::AuthenticationPending
                }
                AuthorizedotnetPaymentStatus::Approved => {
                    // For Approved status, determine specific status based on operation and capture method
                    match operation {
                        Operation::Authorize => match capture_method {
                            Some(enums::CaptureMethod::Manual) => AttemptStatus::Authorized,
                            _ => AttemptStatus::Charged, // Automatic or None defaults to Charged
                        },
                        Operation::Capture | Operation::Refund => AttemptStatus::Charged,
                        Operation::Void => AttemptStatus::Voided,
                    }
                }
            }
        }
    }
}

fn build_connector_metadata(
    transaction_response: &AuthorizedotnetTransactionResponse,
) -> Option<serde_json::Value> {
    // Check if accountNumber is available
    // Note: accountType contains card brand (e.g., "MasterCard"), not expiration date
    // Authorize.net does not return the expiration date in authorization response

    // Debug logging to understand what we're receiving
    tracing::info!(
        "build_connector_metadata: account_number={:?}, account_type={:?}",
        transaction_response
            .account_number
            .as_ref()
            .map(|n| n.peek()),
        transaction_response.account_type.as_ref().map(|t| t.peek())
    );

    if let Some(card_number) = &transaction_response.account_number {
        let card_number_value = card_number.peek();

        // Create nested credit card structure
        let credit_card_data = serde_json::json!({
            "cardNumber": card_number_value,
            "expirationDate": "XXXX"  // Hardcoded since Auth.net doesn't return it
        });

        // Serialize to JSON string for proto compatibility (proto expects map<string, string>)
        let credit_card_json =
            serde_json::to_string(&credit_card_data).unwrap_or_else(|_| "{}".to_string());

        // Create flat metadata map with JSON string value
        let metadata = serde_json::json!({
            "creditCard": credit_card_json
        });

        tracing::info!(
            "build_connector_metadata: Successfully built metadata: {:?}",
            metadata
        );
        return Some(metadata);
    }

    tracing::warn!("build_connector_metadata: account_number is None, returning empty metadata");
    None
}

type PaymentConversionResult = Result<
    (
        AttemptStatus,
        Result<PaymentsResponseData, ErrorResponse>,
        Option<domain_types::router_data::ConnectorResponseData>,
    ),
    HsInterfacesConnectorError,
>;

pub fn convert_to_payments_response_data_or_error(
    response: &AuthorizedotnetPaymentsResponse,
    http_status_code: u16,
    operation: Operation,
    capture_method: Option<enums::CaptureMethod>,
    raw_connector_response: Option<Secret<String>>,
) -> PaymentConversionResult {
    let status = get_hs_status(response, http_status_code, operation, capture_method);

    let is_successful_status = matches!(
        status,
        AttemptStatus::Authorized
            | AttemptStatus::Pending
            | AttemptStatus::AuthenticationPending
            | AttemptStatus::Charged
            | AttemptStatus::Voided
    );

    // Extract connector response data from transaction response if available
    let connector_response_data = match &response.transaction_response {
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
            convert_to_additional_payment_method_connector_response(trans_res)
                .map(domain_types::router_data::ConnectorResponseData::with_additional_payment_method_data)
        }
        _ => None,
    };

    let response_payload_result = match &response.transaction_response {
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res))
            if is_successful_status =>
        {
            let connector_metadata = build_connector_metadata(trans_res);

            // Extract mandate_reference from profile_response if available
            let mandate_reference = response.profile_response.as_ref().map(|profile_response| {
                let payment_profile_id = profile_response
                    .customer_payment_profile_id_list
                    .as_ref()
                    .and_then(|list| list.first().cloned());

                domain_types::connector_types::MandateReference {
                    connector_mandate_id: profile_response.customer_profile_id.as_ref().and_then(
                        |customer_profile_id| {
                            payment_profile_id.map(|payment_profile_id| {
                                format!("{customer_profile_id}-{payment_profile_id}")
                            })
                        },
                    ),
                    payment_method_id: None,
                }
            });

            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(trans_res.transaction_id.clone()),
                redirection_data: None,
                connector_metadata,
                mandate_reference: mandate_reference.map(Box::new),
                network_txn_id: trans_res
                    .network_trans_id
                    .as_ref()
                    .map(|s| s.peek().clone()),
                connector_response_reference_id: Some(trans_res.transaction_id.clone()),
                incremental_authorization_allowed: None,
                status_code: http_status_code,
            })
        }
        Some(TransactionResponse::AuthorizedotnetTransactionResponse(trans_res)) => {
            // Failure status or other non-successful statuses
            let (error_code, error_message) = extract_error_details(response, Some(trans_res));
            Err(create_error_response(
                http_status_code,
                error_code,
                error_message,
                status,
                Some(trans_res.transaction_id.clone()),
                raw_connector_response.clone(),
            ))
        }
        Some(TransactionResponse::AuthorizedotnetTransactionResponseError(_)) => {
            let (error_code, error_message) = extract_error_details(response, None);
            Err(create_error_response(
                http_status_code,
                error_code,
                error_message,
                status,
                None,
                raw_connector_response.clone(),
            ))
        }
        None if status == AttemptStatus::Voided && operation == Operation::Void => {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_status_code,
            })
        }
        None => {
            let (error_code, error_message) = extract_error_details(response, None);
            Err(create_error_response(
                http_status_code,
                error_code,
                error_message,
                status,
                None,
                raw_connector_response.clone(),
            ))
        }
    };

    Ok((status, response_payload_result, connector_response_data))
}

// Transaction details for sync response used in PSync implementation

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncStatus {
    CapturedPendingSettlement,
    SettledSuccessfully,
    AuthorizedPendingCapture,
    Declined,
    Voided,
    CouldNotVoid,
    GeneralError,
    RefundSettledSuccessfully,
    RefundPendingSettlement,
    #[serde(rename = "FDSPendingReview")]
    FDSPendingReview,
    #[serde(rename = "FDSAuthorizedPendingReview")]
    FDSAuthorizedPendingReview,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTransactionResponse {
    #[serde(rename = "transId")]
    pub transaction_id: String,
    #[serde(rename = "transactionStatus")]
    pub transaction_status: SyncStatus,
    pub response_code: Option<u8>,
    pub response_reason_code: Option<u8>,
    pub response_reason_description: Option<String>,
    pub network_trans_id: Option<String>,
    // Additional fields available but not needed for our implementation
}

impl From<SyncStatus> for enums::AttemptStatus {
    fn from(transaction_status: SyncStatus) -> Self {
        match transaction_status {
            SyncStatus::SettledSuccessfully | SyncStatus::CapturedPendingSettlement => {
                Self::Charged
            }
            SyncStatus::AuthorizedPendingCapture => Self::Authorized,
            SyncStatus::Declined => Self::AuthenticationFailed,
            SyncStatus::Voided => Self::Voided,
            SyncStatus::CouldNotVoid => Self::VoidFailed,
            SyncStatus::GeneralError => Self::Failure,
            SyncStatus::RefundSettledSuccessfully
            | SyncStatus::RefundPendingSettlement
            | SyncStatus::FDSPendingReview
            | SyncStatus::FDSAuthorizedPendingReview => Self::Pending,
        }
    }
}

// Removing duplicate implementation

// RSync related types for Refund Sync
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RSyncStatus {
    RefundSettledSuccessfully,
    RefundPendingSettlement,
    Declined,
    GeneralError,
    Voided,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RSyncTransactionResponse {
    #[serde(rename = "transId")]
    transaction_id: String,
    transaction_status: RSyncStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizedotnetRSyncResponse {
    transaction: Option<RSyncTransactionResponse>,
    messages: ResponseMessages,
}

impl From<RSyncStatus> for enums::RefundStatus {
    fn from(transaction_status: RSyncStatus) -> Self {
        match transaction_status {
            RSyncStatus::RefundSettledSuccessfully => Self::Success,
            RSyncStatus::RefundPendingSettlement => Self::Pending,
            RSyncStatus::Declined | RSyncStatus::GeneralError | RSyncStatus::Voided => {
                Self::Failure
            }
        }
    }
}

impl TryFrom<ResponseRouterData<AuthorizedotnetRSyncResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<HsInterfacesConnectorError>;

    fn try_from(
        value: ResponseRouterData<AuthorizedotnetRSyncResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        match response.transaction {
            Some(transaction) => {
                let refund_status = enums::RefundStatus::from(transaction.transaction_status);

                // Create a new RouterDataV2 with updated fields
                let mut new_router_data = router_data;

                // Update the status in resource_common_data
                let mut resource_common_data = new_router_data.resource_common_data.clone();
                resource_common_data.status = refund_status;
                new_router_data.resource_common_data = resource_common_data;

                // Set the response
                new_router_data.response = Ok(RefundsResponseData {
                    connector_refund_id: transaction.transaction_id,
                    refund_status,
                    status_code: http_code,
                });

                Ok(new_router_data)
            }
            None => {
                // Handle error response
                let error_response = ErrorResponse {
                    status_code: http_code,
                    code: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.code.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .messages
                        .message
                        .first()
                        .map(|m| m.text.clone())
                        .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                    reason: None,
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                };

                // Update router data with error response
                let mut new_router_data = router_data;
                let mut resource_common_data = new_router_data.resource_common_data.clone();
                resource_common_data.status = RefundStatus::Failure;
                new_router_data.resource_common_data = resource_common_data;
                new_router_data.response = Err(error_response);

                Ok(new_router_data)
            }
        }
    }
}

// SetupMandate (Zero Mandate) implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for AuthorizedotnetSetupMandateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, error_stack::Report<ConnectorError>> {
        let ccard = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => return Err(error_stack::report!(ConnectorError::RequestEncodingFailed)),
        };

        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        let validation_mode = match item.router_data.resource_common_data.test_mode {
            Some(true) | None => ValidationMode::TestMode,
            Some(false) => ValidationMode::LiveMode,
        };
        let customer_profile_id = item
            .router_data
            .resource_common_data
            .connector_customer
            .as_ref()
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "connector_customer_id is missing",
            })?
            .clone();

        // Build billing address if present - use get_optional_billing() method
        let bill_to = item
            .router_data
            .resource_common_data
            .get_optional_billing()
            .and_then(|billing| billing.address.as_ref())
            .map(|address| BillTo {
                first_name: address.first_name.clone(),
                last_name: address.last_name.clone(),
                address: address.line1.clone(),
                city: address.city.clone(),
                state: address.state.clone(),
                zip: address.zip.clone(),
                country: address.country,
            });

        // Create expiry date manually since we can't use the trait method generically
        let expiry_month = ccard.card_exp_month.peek().clone();
        let year = ccard.card_exp_year.peek().clone();
        let expiry_year = if year.len() == 2 {
            format!("20{year}")
        } else {
            year
        };
        let expiration_date = format!("{expiry_year}-{expiry_month}");

        let payment_profile = PaymentProfile {
            bill_to,
            payment: PaymentDetails::CreditCard(CreditCardDetails {
                card_number: ccard.card_number.clone(),
                expiration_date: Secret::new(expiration_date),
                card_code: Some(ccard.card_cvc.clone()),
            }),
        };

        Ok(Self {
            create_customer_payment_profile_request: AuthorizedotnetPaymentProfileRequest {
                merchant_authentication,
                customer_profile_id: Secret::new(customer_profile_id),
                payment_profile,
                validation_mode,
            },
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetCreateConnectorCustomerResponse {
    pub customer_profile_id: Option<String>,
    pub customer_payment_profile_id_list: Vec<String>,
    pub validation_direct_response_list: Option<Vec<Secret<String>>>,
    pub messages: ResponseMessages,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > TryFrom<ResponseRouterData<AuthorizedotnetSetupMandateResponse, Self>>
    for RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        value: ResponseRouterData<AuthorizedotnetSetupMandateResponse, Self>,
    ) -> Result<Self, error_stack::Report<ConnectorError>> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        // Get connector customer ID from resource_common_data - we need it to build mandate reference
        let connector_customer_id = router_data
            .resource_common_data
            .connector_customer
            .as_ref()
            .ok_or(ConnectorError::MissingRequiredField {
                field_name: "connector_customer_id",
            })?
            .clone();

        // Check if we have a successful response:
        // 1. resultCode == "Ok" (normal success)
        // 2. OR we have customer profile ID AND payment profile ID (E00039 duplicate case)
        //    E00039 = "A duplicate customer payment profile already exists"
        //    This is acceptable for idempotent SetupMandate - profile is available for use
        let is_success = response.messages.result_code == ResultCode::Ok
            || (response.customer_profile_id.is_some()
                && (response.customer_payment_profile_id.is_some()
                    || !response.customer_payment_profile_id_list.is_empty()));

        let status = if is_success {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };

        let mut new_router_data = router_data;
        let mut resource_common_data = new_router_data.resource_common_data.clone();
        resource_common_data.status = status;
        new_router_data.resource_common_data = resource_common_data;

        if response.customer_profile_id.is_some() {
            // Extract payment profile ID from response
            let payment_profile_id = response
                .customer_payment_profile_id_list
                .first()
                .or(response.customer_payment_profile_id.as_ref())
                .ok_or(ConnectorError::ResponseDeserializationFailed)?;

            // Create composite mandate ID: {customer_profile_id}-{payment_profile_id}
            let connector_mandate_id = format!("{connector_customer_id}-{payment_profile_id}");

            new_router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: None,
                connector_metadata: None,
                mandate_reference: Some(Box::new(MandateReference {
                    connector_mandate_id: Some(connector_mandate_id),
                    payment_method_id: None,
                })),
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: http_code,
            });
        } else {
            let error_response = ErrorResponse {
                status_code: http_code,
                code: response
                    .messages
                    .message
                    .first()
                    .map(|m| m.code.clone())
                    .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
                message: response
                    .messages
                    .message
                    .first()
                    .map(|m| m.text.clone())
                    .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
                reason: None,
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: None,
                network_decline_code: None,
                network_advice_code: None,
                network_error_message: None,
            };
            new_router_data.response = Err(error_response);
        }

        Ok(new_router_data)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetErrorResponse {
    pub messages: ResponseMessages,
}

fn get_the_truncate_id(id: Option<String>, max_length: usize) -> Option<String> {
    id.map(|s| {
        if s.len() > max_length {
            s[..max_length].to_string()
        } else {
            s
        }
    })
}

// Webhook-related structures
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetWebhookObjectId {
    pub webhook_id: String,
    pub event_type: AuthorizedotnetWebhookEvent,
    pub payload: AuthorizedotnetWebhookPayload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetWebhookPayload {
    pub id: Option<String>,
    // Fields specific to customer creation webhooks
    pub payment_profiles: Option<Vec<PaymentProfileInfo>>,
    pub merchant_customer_id: Option<String>,
    pub description: Option<String>,
    pub entity_name: Option<String>,
    // Fields specific to customer payment profile creation webhooks
    pub customer_profile_id: Option<u64>,
    pub customer_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentProfileInfo {
    pub id: String,
    pub customer_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedotnetWebhookEventType {
    pub event_type: AuthorizedotnetIncomingWebhookEventType,
}

#[derive(Debug, Clone, Deserialize)]
pub enum AuthorizedotnetWebhookEvent {
    #[serde(rename = "net.authorize.payment.authorization.created")]
    AuthorizationCreated,
    #[serde(rename = "net.authorize.payment.priorAuthCapture.created")]
    PriorAuthCapture,
    #[serde(rename = "net.authorize.payment.authcapture.created")]
    AuthCapCreated,
    #[serde(rename = "net.authorize.payment.capture.created")]
    CaptureCreated,
    #[serde(rename = "net.authorize.payment.void.created")]
    VoidCreated,
    #[serde(rename = "net.authorize.payment.refund.created")]
    RefundCreated,
    #[serde(rename = "net.authorize.customer.created")]
    CustomerCreated,
    #[serde(rename = "net.authorize.customer.paymentProfile.created")]
    CustomerPaymentProfileCreated,
}

/// Including Unknown to map unknown webhook events
#[derive(Debug, Clone, Deserialize)]
pub enum AuthorizedotnetIncomingWebhookEventType {
    #[serde(rename = "net.authorize.payment.authorization.created")]
    AuthorizationCreated,
    #[serde(rename = "net.authorize.payment.priorAuthCapture.created")]
    PriorAuthCapture,
    #[serde(rename = "net.authorize.payment.authcapture.created")]
    AuthCapCreated,
    #[serde(rename = "net.authorize.payment.capture.created")]
    CaptureCreated,
    #[serde(rename = "net.authorize.payment.void.created")]
    VoidCreated,
    #[serde(rename = "net.authorize.payment.refund.created")]
    RefundCreated,
    #[serde(rename = "net.authorize.customer.created")]
    CustomerCreated,
    #[serde(rename = "net.authorize.customer.paymentProfile.created")]
    CustomerPaymentProfileCreated,
    #[serde(other)]
    Unknown,
}

impl From<AuthorizedotnetIncomingWebhookEventType> for interfaces::webhooks::IncomingWebhookEvent {
    fn from(event_type: AuthorizedotnetIncomingWebhookEventType) -> Self {
        match event_type {
            AuthorizedotnetIncomingWebhookEventType::AuthorizationCreated
            | AuthorizedotnetIncomingWebhookEventType::PriorAuthCapture
            | AuthorizedotnetIncomingWebhookEventType::AuthCapCreated
            | AuthorizedotnetIncomingWebhookEventType::CaptureCreated
            | AuthorizedotnetIncomingWebhookEventType::VoidCreated
            | AuthorizedotnetIncomingWebhookEventType::CustomerCreated
            | AuthorizedotnetIncomingWebhookEventType::CustomerPaymentProfileCreated => {
                Self::PaymentIntentSuccess
            }
            AuthorizedotnetIncomingWebhookEventType::RefundCreated => Self::RefundSuccess,
            AuthorizedotnetIncomingWebhookEventType::Unknown => Self::EventNotSupported,
        }
    }
}

impl From<AuthorizedotnetWebhookEvent> for enums::AttemptStatus {
    // status mapping reference https://developer.authorize.net/api/reference/features/webhooks.html#Event_Types_and_Payloads
    fn from(event_type: AuthorizedotnetWebhookEvent) -> Self {
        match event_type {
            AuthorizedotnetWebhookEvent::AuthorizationCreated => Self::Authorized,
            AuthorizedotnetWebhookEvent::CaptureCreated
            | AuthorizedotnetWebhookEvent::AuthCapCreated
            | AuthorizedotnetWebhookEvent::PriorAuthCapture => Self::Charged,
            AuthorizedotnetWebhookEvent::VoidCreated => Self::Voided,
            AuthorizedotnetWebhookEvent::RefundCreated => Self::PartialCharged, // This will be used for refund status
            AuthorizedotnetWebhookEvent::CustomerCreated => Self::Charged, // Customer profile creation indicates successful setup mandate
            AuthorizedotnetWebhookEvent::CustomerPaymentProfileCreated => Self::Charged, // Payment profile creation indicates successful setup mandate
        }
    }
}

impl From<AuthorizedotnetWebhookEvent> for SyncStatus {
    // status mapping reference https://developer.authorize.net/api/reference/features/webhooks.html#Event_Types_and_Payloads
    fn from(event_type: AuthorizedotnetWebhookEvent) -> Self {
        match event_type {
            AuthorizedotnetWebhookEvent::AuthorizationCreated => Self::AuthorizedPendingCapture,
            AuthorizedotnetWebhookEvent::CaptureCreated
            | AuthorizedotnetWebhookEvent::AuthCapCreated => Self::CapturedPendingSettlement,
            AuthorizedotnetWebhookEvent::PriorAuthCapture => Self::SettledSuccessfully,
            AuthorizedotnetWebhookEvent::VoidCreated => Self::Voided,
            AuthorizedotnetWebhookEvent::RefundCreated => Self::RefundSettledSuccessfully,
            AuthorizedotnetWebhookEvent::CustomerCreated => Self::SettledSuccessfully, // Customer profile successfully created and settled
            AuthorizedotnetWebhookEvent::CustomerPaymentProfileCreated => Self::SettledSuccessfully, // Payment profile successfully created and settled
        }
    }
}

pub fn get_trans_id(details: &AuthorizedotnetWebhookObjectId) -> Result<String, ConnectorError> {
    match details.event_type {
        AuthorizedotnetWebhookEvent::CustomerPaymentProfileCreated => {
            // For payment profile creation, use the customer_profile_id as the primary identifier
            if let Some(customer_profile_id) = details.payload.customer_profile_id {
                tracing::debug!(
                    target: "authorizedotnet_webhook",
                    "Extracted customer profile ID {} for payment profile creation webhook",
                    customer_profile_id
                );
                Ok(customer_profile_id.to_string())
            } else {
                match details.payload.id.clone() {
                    Some(id) => {
                        tracing::debug!(
                            target: "authorizedotnet_webhook",
                            "Extracted transaction ID {} from payment profile webhook payload",
                            id
                        );
                        Ok(id)
                    }
                    None => {
                        tracing::error!(
                            target: "authorizedotnet_webhook",
                            "No customer_profile_id or id found in CustomerPaymentProfileCreated webhook payload"
                        );
                        Err(ConnectorError::WebhookReferenceIdNotFound)
                    }
                }
            }
        }
        _ => {
            // For all other events, use the standard id field
            match details.payload.id.clone() {
                Some(id) => {
                    tracing::debug!(
                        target: "authorizedotnet_webhook",
                        "Extracted transaction ID {} for webhook event type: {:?}",
                        id,
                        details.event_type
                    );
                    Ok(id)
                }
                None => {
                    tracing::error!(
                        target: "authorizedotnet_webhook",
                        "No transaction ID found in webhook payload for event type: {:?}",
                        details.event_type
                    );
                    Err(ConnectorError::WebhookReferenceIdNotFound)
                }
            }
        }
    }
}

impl TryFrom<AuthorizedotnetWebhookObjectId> for AuthorizedotnetPSyncResponse {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: AuthorizedotnetWebhookObjectId) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction: Some(SyncTransactionResponse {
                transaction_id: get_trans_id(&item)?,
                transaction_status: SyncStatus::from(item.event_type),
                response_code: Some(1),
                response_reason_code: Some(1),
                response_reason_description: Some("Approved".to_string()),
                network_trans_id: None,
            }),
            messages: ResponseMessages {
                result_code: ResultCode::Ok,
                message: vec![ResponseMessage {
                    code: "I00001".to_string(),
                    text: "Successful.".to_string(),
                }],
            },
        })
    }
}

// Helper function to extract customer profile ID from error message
// Message format: "A duplicate record with ID 933042598 already exists."
fn extract_customer_id_from_error(error_text: &str) -> Option<String> {
    // Look for pattern "ID <numbers>"
    error_text
        .split_whitespace()
        .skip_while(|&word| word != "ID")
        .nth(1) // Get the word after "ID"
        .and_then(|id_str| {
            // Remove any trailing punctuation and validate it's numeric
            let cleaned = id_str.trim_end_matches(|c: char| !c.is_numeric());
            if cleaned.chars().all(char::is_numeric) && !cleaned.is_empty() {
                Some(cleaned.to_string())
            } else {
                None
            }
        })
}

// TryFrom implementations for CreateConnectorCustomer flow

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        AuthorizedotnetRouterData<
            RouterDataV2<
                CreateConnectorCustomer,
                PaymentFlowData,
                ConnectorCustomerData,
                ConnectorCustomerResponse,
            >,
            T,
        >,
    > for AuthorizedotnetCreateConnectorCustomerRequest<T>
{
    type Error = Error;
    fn try_from(
        item: AuthorizedotnetRouterData<
            RouterDataV2<
                CreateConnectorCustomer,
                PaymentFlowData,
                ConnectorCustomerData,
                ConnectorCustomerResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let merchant_authentication =
            AuthorizedotnetAuthType::try_from(&item.router_data.connector_auth_type)?;

        // Build ship_to_list from shipping address if available
        let ship_to_list = item
            .router_data
            .resource_common_data
            .address
            .get_shipping()
            .and_then(|shipping| {
                shipping.address.as_ref().map(|address| {
                    vec![ShipToList {
                        first_name: address.first_name.clone(),
                        last_name: address.last_name.clone(),
                        address: address.line1.clone(),
                        city: address.city.clone(),
                        state: address.state.clone(),
                        zip: address.zip.clone(),
                        country: address.country,
                        phone_number: shipping
                            .phone
                            .as_ref()
                            .and_then(|phone| phone.number.clone()),
                    }]
                })
            });

        // Conditionally send merchant_customer_id (matching Hyperswitch parity)
        // Only send if customer_id exists and length <= MAX_ID_LENGTH (20 chars)
        let merchant_customer_id = item
            .router_data
            .request
            .customer_id
            .as_ref()
            .and_then(|id| {
                if id.peek().len() <= MAX_ID_LENGTH {
                    Some(id.peek().clone())
                } else {
                    None
                }
            });

        // Create a customer profile without payment method (zero mandate)
        Ok(Self {
            create_customer_profile_request: AuthorizedotnetZeroMandateRequest {
                merchant_authentication,
                profile: Profile {
                    merchant_customer_id,
                    description: None,
                    email: item
                        .router_data
                        .request
                        .email
                        .as_ref()
                        .map(|e| e.peek().clone().expose().expose()),
                    payment_profiles: None,
                    ship_to_list,
                },
                validation_mode: None,
            },
        })
    }
}

impl
    TryFrom<
        ResponseRouterData<
            AuthorizedotnetCreateConnectorCustomerResponse,
            RouterDataV2<
                CreateConnectorCustomer,
                PaymentFlowData,
                ConnectorCustomerData,
                ConnectorCustomerResponse,
            >,
        >,
    >
    for RouterDataV2<
        CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    >
{
    type Error = Error;
    fn try_from(
        value: ResponseRouterData<
            AuthorizedotnetCreateConnectorCustomerResponse,
            RouterDataV2<
                CreateConnectorCustomer,
                PaymentFlowData,
                ConnectorCustomerData,
                ConnectorCustomerResponse,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let ResponseRouterData {
            response,
            router_data,
            http_code,
        } = value;

        let mut new_router_data = router_data;

        if let Some(profile_id) = response.customer_profile_id {
            // Success - return the connector customer ID
            new_router_data.response = Ok(ConnectorCustomerResponse {
                connector_customer_id: profile_id,
            });
        } else {
            // Check if this is a "duplicate customer" error (E00039)
            let first_error = response.messages.message.first();
            let error_code = first_error.map(|m| m.code.as_str()).unwrap_or("");
            let error_text = first_error.map(|m| m.text.as_str()).unwrap_or("");

            if error_code == "E00039" {
                // Extract customer profile ID from error message
                // Message format: "A duplicate record with ID 933042598 already exists."
                if let Some(existing_profile_id) = extract_customer_id_from_error(error_text) {
                    tracing::info!(
                        "Customer profile already exists with ID: {}, treating as success",
                        existing_profile_id
                    );
                    new_router_data.response = Ok(ConnectorCustomerResponse {
                        connector_customer_id: existing_profile_id,
                    });
                } else {
                    // Couldn't extract ID, return error
                    new_router_data.response = Err(ErrorResponse {
                        status_code: http_code,
                        code: error_code.to_string(),
                        message: error_text.to_string(),
                        reason: None,
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    });
                }
            } else {
                // Other error - return error response
                new_router_data.response = Err(ErrorResponse {
                    status_code: http_code,
                    code: error_code.to_string(),
                    message: error_text.to_string(),
                    reason: None,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                });
            }
        }

        Ok(new_router_data)
    }
}
