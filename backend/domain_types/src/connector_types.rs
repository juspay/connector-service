use std::collections::HashMap;

use common_enums::{
    AttemptStatus, AuthenticationType, Currency, DisputeStatus, EventClass, PaymentMethod,
    PaymentMethodType,
};
use common_utils::{
    errors,
    ext_traits::{OptionExt, ValueExt},
    pii::IpAddress,
    types::MinorUnit,
    CustomResult, CustomerId, Email, SecretSerdeValue,
};
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::{
    errors::{ApiError, ApplicationErrorResponse},
    payment_address::{Address, AddressDetails, PhoneDetails},
    payment_method_data,
    payment_method_data::{Card, PaymentMethodData},
    router_data::PaymentMethodToken,
    router_request_types::{
        AcceptDisputeIntegrityObject, AuthoriseIntegrityObject, BrowserInformation,
        CaptureIntegrityObject, CreateOrderIntegrityObject, DefendDisputeIntegrityObject,
        PaymentSynIntegrityObject, PaymentVoidIntegrityObject, RefundIntegrityObject,
        RefundSyncIntegrityObject, SetupMandateIntegrityObject, SubmitEvidenceIntegrityObject,
        SyncRequestType,
    },
    types::{
        ConnectorInfo, Connectors, PaymentMethodDataType, PaymentMethodDetails,
        PaymentMethodTypeMetadata, SupportedPaymentMethods,
    },
    utils::{missing_field_err, Error, ForeignTryFrom},
};

// snake case for enum variants
#[derive(Clone, Debug, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectorEnum {
    Adyen,
    Razorpay,
    RazorpayV2,
    Fiserv,
    Elavon,
    Xendit,
    Checkout,
    Authorizedotnet,
    Phonepe,
    Cashfree,
    Fiuu,
    Payu,
    Cashtocode,
}

impl ForeignTryFrom<grpc_api_types::payments::Connector> for ConnectorEnum {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        connector: grpc_api_types::payments::Connector,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match connector {
            grpc_api_types::payments::Connector::Adyen => Ok(Self::Adyen),
            grpc_api_types::payments::Connector::Razorpay => Ok(Self::Razorpay),
            grpc_api_types::payments::Connector::Fiserv => Ok(Self::Fiserv),
            grpc_api_types::payments::Connector::Elavon => Ok(Self::Elavon),
            grpc_api_types::payments::Connector::Xendit => Ok(Self::Xendit),
            grpc_api_types::payments::Connector::Checkout => Ok(Self::Checkout),
            grpc_api_types::payments::Connector::Authorizedotnet => Ok(Self::Authorizedotnet),
            grpc_api_types::payments::Connector::Phonepe => Ok(Self::Phonepe),
            grpc_api_types::payments::Connector::Cashfree => Ok(Self::Cashfree),
            grpc_api_types::payments::Connector::Fiuu => Ok(Self::Fiuu),
            grpc_api_types::payments::Connector::Payu => Ok(Self::Payu),
            grpc_api_types::payments::Connector::Cashtocode => Ok(Self::Cashtocode),
            grpc_api_types::payments::Connector::Unspecified => {
                Err(ApplicationErrorResponse::BadRequest(ApiError {
                    sub_code: "UNSPECIFIED_CONNECTOR".to_owned(),
                    error_identifier: 400,
                    error_message: "Connector must be specified".to_owned(),
                    error_object: None,
                })
                .into())
            }
            _ => Err(ApplicationErrorResponse::BadRequest(ApiError {
                sub_code: "INVALID_CONNECTOR".to_owned(),
                error_identifier: 400,
                error_message: format!("Connector {connector:?} is not supported"),
                error_object: None,
            })
            .into()),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PaymentId(pub String);

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct UpdateHistory {
    pub connector_mandate_id: Option<String>,
    pub payment_method_id: String,
    pub original_payment_id: Option<PaymentId>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone, Eq, PartialEq)]
pub struct ConnectorMandateReferenceId {
    connector_mandate_id: Option<String>,
    payment_method_id: Option<String>,
    update_history: Option<Vec<UpdateHistory>>,
}

impl ConnectorMandateReferenceId {
    pub fn new(
        connector_mandate_id: Option<String>,
        payment_method_id: Option<String>,
        update_history: Option<Vec<UpdateHistory>>,
    ) -> Self {
        Self {
            connector_mandate_id,
            payment_method_id,
            update_history,
        }
    }

    pub fn get_connector_mandate_id(&self) -> Option<String> {
        self.connector_mandate_id.clone()
    }

    pub fn get_payment_method_id(&self) -> Option<&String> {
        self.payment_method_id.as_ref()
    }

    pub fn get_update_history(&self) -> Option<&Vec<UpdateHistory>> {
        self.update_history.as_ref()
    }
}

pub trait RawConnectorResponse {
    fn set_raw_connector_response(&mut self, response: Option<String>);
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone, Eq, PartialEq)]
pub struct NetworkTokenWithNTIRef {
    pub network_transaction_id: String,
    pub token_exp_month: Option<Secret<String>>,
    pub token_exp_year: Option<Secret<String>>,
}

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize, Clone)]
pub enum MandateReferenceId {
    ConnectorMandateId(ConnectorMandateReferenceId), // mandate_id send by connector
    NetworkMandateId(String), // network_txns_id send by Issuer to connector, Used for PG agnostic mandate txns along with card data
    NetworkTokenWithNTI(NetworkTokenWithNTIRef), // network_txns_id send by Issuer to connector, Used for PG agnostic mandate txns along with network token data
}

#[derive(Default, Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct MandateIds {
    pub mandate_id: Option<String>,
    pub mandate_reference_id: Option<MandateReferenceId>,
}

impl MandateIds {
    pub fn is_network_transaction_id_flow(&self) -> bool {
        matches!(
            self.mandate_reference_id,
            Some(MandateReferenceId::NetworkMandateId(_))
        )
    }

    pub fn new(mandate_id: String) -> Self {
        Self {
            mandate_id: Some(mandate_id),
            mandate_reference_id: None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct PaymentsSyncData {
    pub connector_transaction_id: ResponseId,
    pub encoded_data: Option<String>,
    pub capture_method: Option<common_enums::CaptureMethod>,
    pub connector_meta: Option<serde_json::Value>,
    pub sync_type: SyncRequestType,
    pub mandate_id: Option<MandateIds>,
    pub payment_method_type: Option<common_enums::PaymentMethodType>,
    pub currency: common_enums::Currency,
    pub payment_experience: Option<common_enums::PaymentExperience>,
    pub amount: MinorUnit,
    pub all_keys_required: Option<bool>,
    pub integrity_object: Option<PaymentSynIntegrityObject>,
}

impl PaymentsSyncData {
    pub fn is_auto_capture(&self) -> Result<bool, Error> {
        match self.capture_method {
            Some(common_enums::CaptureMethod::Automatic)
            | None
            | Some(common_enums::CaptureMethod::SequentialAutomatic) => Ok(true),
            Some(common_enums::CaptureMethod::Manual) => Ok(false),
            Some(_) => Err(crate::errors::ConnectorError::CaptureMethodNotSupported.into()),
        }
    }
    pub fn get_connector_transaction_id(
        &self,
    ) -> CustomResult<String, crate::errors::ConnectorError> {
        match self.connector_transaction_id.clone() {
            ResponseId::ConnectorTransactionId(txn_id) => Ok(txn_id),
            _ => Err(errors::ValidationError::IncorrectValueProvided {
                field_name: "connector_transaction_id",
            })
            .attach_printable("Expected connector transaction ID not found")
            .change_context(crate::errors::ConnectorError::MissingConnectorTransactionID)?,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PaymentFlowData {
    pub merchant_id: common_utils::id_type::MerchantId,
    pub customer_id: Option<common_utils::id_type::CustomerId>,
    pub connector_customer: Option<String>,
    pub payment_id: String,
    pub attempt_id: String,
    pub status: AttemptStatus,
    pub payment_method: PaymentMethod,
    pub description: Option<String>,
    pub return_url: Option<String>,
    pub address: crate::payment_address::PaymentAddress,
    pub auth_type: AuthenticationType,
    pub connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    pub amount_captured: Option<i64>,
    // minor amount for amount frameworka
    pub minor_amount_captured: Option<MinorUnit>,
    pub access_token: Option<String>,
    pub session_token: Option<String>,
    pub reference_id: Option<String>,
    pub payment_method_token: Option<PaymentMethodToken>,
    pub preprocessing_id: Option<String>,
    ///for switching between two different versions of the same connector
    pub connector_api_version: Option<String>,
    /// Contains a reference ID that should be sent in the connector request
    pub connector_request_reference_id: String,
    pub test_mode: Option<bool>,
    pub connector_http_status_code: Option<u16>,
    pub external_latency: Option<u128>,
    pub connectors: Connectors,
    pub raw_connector_response: Option<String>,
}

impl PaymentFlowData {
    pub fn get_billing(&self) -> Result<&Address, Error> {
        self.address
            .get_payment_method_billing()
            .ok_or_else(missing_field_err("billing"))
    }

    pub fn get_billing_country(&self) -> Result<common_enums::CountryAlpha2, Error> {
        self.address
            .get_payment_method_billing()
            .and_then(|a| a.address.as_ref())
            .and_then(|ad| ad.country)
            .ok_or_else(missing_field_err(
                "payment_method_data.billing.address.country",
            ))
    }

    pub fn get_billing_phone(&self) -> Result<&PhoneDetails, Error> {
        self.address
            .get_payment_method_billing()
            .and_then(|a| a.phone.as_ref())
            .ok_or_else(missing_field_err("billing.phone"))
    }

    pub fn get_optional_billing(&self) -> Option<&Address> {
        self.address.get_payment_method_billing()
    }

    pub fn get_optional_shipping(&self) -> Option<&Address> {
        self.address.get_shipping()
    }

    pub fn get_optional_shipping_first_name(&self) -> Option<Secret<String>> {
        self.address.get_shipping().and_then(|shipping_address| {
            shipping_address
                .clone()
                .address
                .and_then(|shipping_details| shipping_details.first_name)
        })
    }

    pub fn get_optional_shipping_last_name(&self) -> Option<Secret<String>> {
        self.address.get_shipping().and_then(|shipping_address| {
            shipping_address
                .clone()
                .address
                .and_then(|shipping_details| shipping_details.last_name)
        })
    }

    pub fn get_optional_shipping_line1(&self) -> Option<Secret<String>> {
        self.address.get_shipping().and_then(|shipping_address| {
            shipping_address
                .clone()
                .address
                .and_then(|shipping_details| shipping_details.line1)
        })
    }

    pub fn get_optional_shipping_line2(&self) -> Option<Secret<String>> {
        self.address.get_shipping().and_then(|shipping_address| {
            shipping_address
                .clone()
                .address
                .and_then(|shipping_details| shipping_details.line2)
        })
    }

    pub fn get_optional_shipping_city(&self) -> Option<String> {
        self.address.get_shipping().and_then(|shipping_address| {
            shipping_address
                .clone()
                .address
                .and_then(|shipping_details| shipping_details.city)
        })
    }

    pub fn get_optional_shipping_state(&self) -> Option<Secret<String>> {
        self.address.get_shipping().and_then(|shipping_address| {
            shipping_address
                .clone()
                .address
                .and_then(|shipping_details| shipping_details.state)
        })
    }

    pub fn get_optional_shipping_country(&self) -> Option<common_enums::CountryAlpha2> {
        self.address.get_shipping().and_then(|shipping_address| {
            shipping_address
                .clone()
                .address
                .and_then(|shipping_details| shipping_details.country)
        })
    }

    pub fn get_optional_shipping_zip(&self) -> Option<Secret<String>> {
        self.address.get_shipping().and_then(|shipping_address| {
            shipping_address
                .clone()
                .address
                .and_then(|shipping_details| shipping_details.zip)
        })
    }

    pub fn get_optional_shipping_email(&self) -> Option<Email> {
        self.address
            .get_shipping()
            .and_then(|shipping_address| shipping_address.clone().email)
    }

    pub fn get_optional_shipping_phone_number(&self) -> Option<Secret<String>> {
        self.address
            .get_shipping()
            .and_then(|shipping_address| shipping_address.clone().phone)
            .and_then(|phone_details| phone_details.get_number_with_country_code().ok())
    }

    pub fn get_description(&self) -> Result<String, Error> {
        self.description
            .clone()
            .ok_or_else(missing_field_err("description"))
    }
    pub fn get_billing_address(&self) -> Result<&AddressDetails, Error> {
        self.address
            .get_payment_method_billing()
            .as_ref()
            .and_then(|a| a.address.as_ref())
            .ok_or_else(missing_field_err("billing.address"))
    }

    pub fn get_connector_meta(&self) -> Result<SecretSerdeValue, Error> {
        self.connector_meta_data
            .clone()
            .ok_or_else(missing_field_err("connector_meta_data"))
    }

    pub fn get_session_token(&self) -> Result<String, Error> {
        self.session_token
            .clone()
            .ok_or_else(missing_field_err("session_token"))
    }

    pub fn get_billing_first_name(&self) -> Result<Secret<String>, Error> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.first_name.clone())
            })
            .ok_or_else(missing_field_err(
                "payment_method_data.billing.address.first_name",
            ))
    }

    pub fn get_billing_full_name(&self) -> Result<Secret<String>, Error> {
        self.get_optional_billing()
            .and_then(|billing_details| billing_details.address.as_ref())
            .and_then(|billing_address| billing_address.get_optional_full_name())
            .ok_or_else(missing_field_err(
                "payment_method_data.billing.address.first_name",
            ))
    }

    pub fn get_billing_last_name(&self) -> Result<Secret<String>, Error> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.last_name.clone())
            })
            .ok_or_else(missing_field_err(
                "payment_method_data.billing.address.last_name",
            ))
    }

    pub fn get_billing_line1(&self) -> Result<Secret<String>, Error> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.line1.clone())
            })
            .ok_or_else(missing_field_err(
                "payment_method_data.billing.address.line1",
            ))
    }
    pub fn get_billing_city(&self) -> Result<String, Error> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.city)
            })
            .ok_or_else(missing_field_err(
                "payment_method_data.billing.address.city",
            ))
    }

    pub fn get_billing_email(&self) -> Result<Email, Error> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| billing_address.email.clone())
            .ok_or_else(missing_field_err("payment_method_data.billing.email"))
    }

    pub fn get_billing_phone_number(&self) -> Result<Secret<String>, Error> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| billing_address.clone().phone)
            .map(|phone_details| phone_details.get_number_with_country_code())
            .transpose()?
            .ok_or_else(missing_field_err("payment_method_data.billing.phone"))
    }

    pub fn get_optional_billing_line1(&self) -> Option<Secret<String>> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.line1)
            })
    }

    pub fn get_optional_billing_line2(&self) -> Option<Secret<String>> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.line2)
            })
    }

    pub fn get_optional_billing_city(&self) -> Option<String> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.city)
            })
    }

    pub fn get_optional_billing_country(&self) -> Option<common_enums::CountryAlpha2> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.country)
            })
    }

    pub fn get_optional_billing_zip(&self) -> Option<Secret<String>> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.zip)
            })
    }

    pub fn get_optional_billing_state(&self) -> Option<Secret<String>> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.state)
            })
    }

    pub fn get_optional_billing_first_name(&self) -> Option<Secret<String>> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.first_name)
            })
    }

    pub fn get_optional_billing_last_name(&self) -> Option<Secret<String>> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .address
                    .and_then(|billing_details| billing_details.last_name)
            })
    }

    pub fn get_optional_billing_phone_number(&self) -> Option<Secret<String>> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| {
                billing_address
                    .clone()
                    .phone
                    .and_then(|phone_data| phone_data.number)
            })
    }

    pub fn get_optional_billing_email(&self) -> Option<Email> {
        self.address
            .get_payment_method_billing()
            .and_then(|billing_address| billing_address.clone().email)
    }
    pub fn to_connector_meta<T>(&self) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.get_connector_meta()?
            .parse_value(std::any::type_name::<T>())
            .change_context(crate::errors::ConnectorError::NoConnectorMetaData)
    }

    pub fn is_three_ds(&self) -> bool {
        matches!(self.auth_type, common_enums::AuthenticationType::ThreeDs)
    }

    pub fn get_shipping_address(&self) -> Result<&AddressDetails, Error> {
        self.address
            .get_shipping()
            .and_then(|a| a.address.as_ref())
            .ok_or_else(missing_field_err("shipping.address"))
    }

    pub fn get_shipping_address_with_phone_number(&self) -> Result<&Address, Error> {
        self.address
            .get_shipping()
            .ok_or_else(missing_field_err("shipping"))
    }

    pub fn get_payment_method_token(&self) -> Result<PaymentMethodToken, Error> {
        self.payment_method_token
            .clone()
            .ok_or_else(missing_field_err("payment_method_token"))
    }
    pub fn get_customer_id(&self) -> Result<CustomerId, Error> {
        self.customer_id
            .to_owned()
            .ok_or_else(missing_field_err("customer_id"))
    }
    pub fn get_connector_customer_id(&self) -> Result<String, Error> {
        self.connector_customer
            .to_owned()
            .ok_or_else(missing_field_err("connector_customer_id"))
    }
    pub fn get_preprocessing_id(&self) -> Result<String, Error> {
        self.preprocessing_id
            .to_owned()
            .ok_or_else(missing_field_err("preprocessing_id"))
    }

    pub fn get_optional_billing_full_name(&self) -> Option<Secret<String>> {
        self.get_optional_billing()
            .and_then(|billing_details| billing_details.address.as_ref())
            .and_then(|billing_address| billing_address.get_optional_full_name())
    }

    pub fn set_order_reference_id(mut self, reference_id: Option<String>) -> Self {
        if reference_id.is_some() && self.reference_id.is_none() {
            self.reference_id = reference_id;
        }
        self
    }
}

impl RawConnectorResponse for PaymentFlowData {
    fn set_raw_connector_response(&mut self, response: Option<String>) {
        self.raw_connector_response = response;
    }
}

#[derive(Debug, Clone)]
pub struct PaymentVoidData {
    pub connector_transaction_id: String,
    pub cancellation_reason: Option<String>,
    pub integrity_object: Option<PaymentVoidIntegrityObject>,
    pub raw_connector_response: Option<String>,
}

impl PaymentVoidData {
    // fn get_amount(&self) -> Result<i64, Error> {
    //     self.amount.ok_or_else(missing_field_err("amount"))
    // }
    // fn get_currency(&self) -> Result<common_enums::Currency, Error> {
    //     self.currency.ok_or_else(missing_field_err("currency"))
    // }
    pub fn get_cancellation_reason(&self) -> Result<String, Error> {
        self.cancellation_reason
            .clone()
            .ok_or_else(missing_field_err("cancellation_reason"))
    }
    // fn get_browser_info(&self) -> Result<BrowserInformation, Error> {
    //     self.browser_info
    //         .clone()
    //         .ok_or_else(missing_field_err("browser_info"))
    // }
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentsAuthorizeData {
    pub payment_method_data: crate::payment_method_data::PaymentMethodData,
    /// total amount (original_amount + surcharge_amount + tax_on_surcharge_amount)
    /// If connector supports separate field for surcharge amount, consider using below functions defined on `PaymentsAuthorizeData` to fetch original amount and surcharge amount separately
    /// ```text
    /// get_original_amount()
    /// get_surcharge_amount()
    /// get_tax_on_surcharge_amount()
    /// get_total_surcharge_amount() // returns surcharge_amount + tax_on_surcharge_amount
    /// ```
    pub amount: i64,
    pub order_tax_amount: Option<MinorUnit>,
    pub email: Option<common_utils::pii::Email>,
    pub customer_name: Option<String>,
    pub currency: Currency,
    pub confirm: bool,
    pub statement_descriptor_suffix: Option<String>,
    pub statement_descriptor: Option<String>,
    pub capture_method: Option<common_enums::CaptureMethod>,
    pub router_return_url: Option<String>,
    pub webhook_url: Option<String>,
    pub complete_authorize_url: Option<String>,
    // Mandates
    pub mandate_id: Option<MandateIds>,
    pub setup_future_usage: Option<common_enums::FutureUsage>,
    pub off_session: Option<bool>,
    pub browser_info: Option<crate::router_request_types::BrowserInformation>,
    pub order_category: Option<String>,
    pub session_token: Option<String>,
    pub enrolled_for_3ds: bool,
    pub related_transaction_id: Option<String>,
    pub payment_experience: Option<common_enums::PaymentExperience>,
    pub payment_method_type: Option<common_enums::PaymentMethodType>,
    pub customer_id: Option<common_utils::id_type::CustomerId>,
    pub request_incremental_authorization: bool,
    pub metadata: Option<serde_json::Value>,
    // New amount for amount frame work
    pub minor_amount: MinorUnit,
    /// Merchant's identifier for the payment/invoice. This will be sent to the connector
    /// if the connector provides support to accept multiple reference ids.
    /// In case the connector supports only one reference id, Hyperswitch's Payment ID will be sent as reference.
    pub merchant_order_reference_id: Option<String>,
    pub shipping_cost: Option<MinorUnit>,
    pub merchant_account_id: Option<String>,
    pub integrity_object: Option<AuthoriseIntegrityObject>,
    pub merchant_config_currency: Option<common_enums::Currency>,
    pub all_keys_required: Option<bool>,
}

impl PaymentsAuthorizeData {
    pub fn is_auto_capture(&self) -> Result<bool, Error> {
        match self.capture_method {
            Some(common_enums::CaptureMethod::Automatic)
            | None
            | Some(common_enums::CaptureMethod::SequentialAutomatic) => Ok(true),
            Some(common_enums::CaptureMethod::Manual) => Ok(false),
            Some(_) => Err(crate::errors::ConnectorError::CaptureMethodNotSupported.into()),
        }
    }
    pub fn get_email(&self) -> Result<Email, Error> {
        self.email.clone().ok_or_else(missing_field_err("email"))
    }
    pub fn get_optional_email(&self) -> Option<Email> {
        self.email.clone()
    }
    pub fn get_browser_info(&self) -> Result<BrowserInformation, Error> {
        self.browser_info
            .clone()
            .ok_or_else(missing_field_err("browser_info"))
    }
    // pub fn get_order_details(&self) -> Result<Vec<OrderDetailsWithAmount>, Error> {
    //     self.order_details
    //         .clone()
    //         .ok_or_else(missing_field_err("order_details"))
    // }

    pub fn get_card(&self) -> Result<Card, Error> {
        match self.payment_method_data.clone() {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(missing_field_err("card")()),
        }
    }

    pub fn get_complete_authorize_url(&self) -> Result<String, Error> {
        self.complete_authorize_url
            .clone()
            .ok_or_else(missing_field_err("complete_authorize_url"))
    }

    pub fn connector_mandate_id(&self) -> Option<String> {
        self.mandate_id
            .as_ref()
            .and_then(|mandate_ids| match &mandate_ids.mandate_reference_id {
                Some(MandateReferenceId::ConnectorMandateId(connector_mandate_ids)) => {
                    connector_mandate_ids.get_connector_mandate_id()
                }
                Some(MandateReferenceId::NetworkMandateId(_))
                | None
                | Some(MandateReferenceId::NetworkTokenWithNTI(_)) => None,
            })
    }

    pub fn get_optional_network_transaction_id(&self) -> Option<String> {
        self.mandate_id
            .as_ref()
            .and_then(|mandate_ids| match &mandate_ids.mandate_reference_id {
                Some(MandateReferenceId::NetworkMandateId(network_transaction_id)) => {
                    Some(network_transaction_id.clone())
                }
                Some(MandateReferenceId::ConnectorMandateId(_))
                | Some(MandateReferenceId::NetworkTokenWithNTI(_))
                | None => None,
            })
    }

    // pub fn is_mandate_payment(&self) -> bool {
    //     ((self.customer_acceptance.is_some() || self.setup_mandate_details.is_some())
    //         && self.setup_future_usage == Some(storage_enums::FutureUsage::OffSession))
    //         || self
    //             .mandate_id
    //             .as_ref()
    //             .and_then(|mandate_ids| mandate_ids.mandate_reference_id.as_ref())
    //             .is_some()
    // }
    // fn is_cit_mandate_payment(&self) -> bool {
    //     (self.customer_acceptance.is_some() || self.setup_mandate_details.is_some())
    //         && self.setup_future_usage == Some(storage_enums::FutureUsage::OffSession)
    // }
    pub fn get_webhook_url(&self) -> Result<String, Error> {
        self.webhook_url
            .clone()
            .ok_or_else(missing_field_err("webhook_url"))
    }
    pub fn get_router_return_url(&self) -> Result<String, Error> {
        self.router_return_url
            .clone()
            .ok_or_else(missing_field_err("return_url"))
    }
    pub fn is_wallet(&self) -> bool {
        matches!(self.payment_method_data, PaymentMethodData::Wallet(_))
    }
    pub fn is_card(&self) -> bool {
        matches!(self.payment_method_data, PaymentMethodData::Card(_))
    }

    pub fn get_payment_method_type(&self) -> Result<common_enums::PaymentMethodType, Error> {
        self.payment_method_type
            .to_owned()
            .ok_or_else(missing_field_err("payment_method_type"))
    }

    pub fn get_connector_mandate_id(&self) -> Result<String, Error> {
        self.connector_mandate_id()
            .ok_or_else(missing_field_err("connector_mandate_id"))
    }
    pub fn get_ip_address_as_optional(&self) -> Option<Secret<String, IpAddress>> {
        self.browser_info.clone().and_then(|browser_info| {
            browser_info
                .ip_address
                .map(|ip| Secret::new(ip.to_string()))
        })
    }
    // fn get_original_amount(&self) -> i64 {
    //     self.surcharge_details
    //         .as_ref()
    //         .map(|surcharge_details| surcharge_details.original_amount.get_amount_as_i64())
    //         .unwrap_or(self.amount)
    // }
    // fn get_surcharge_amount(&self) -> Option<i64> {
    //     self.surcharge_details
    //         .as_ref()
    //         .map(|surcharge_details| surcharge_details.surcharge_amount.get_amount_as_i64())
    // }
    // fn get_tax_on_surcharge_amount(&self) -> Option<i64> {
    //     self.surcharge_details.as_ref().map(|surcharge_details| {
    //         surcharge_details
    //             .tax_on_surcharge_amount
    //             .get_amount_as_i64()
    //     })
    // }
    // fn get_total_surcharge_amount(&self) -> Option<i64> {
    //     self.surcharge_details.as_ref().map(|surcharge_details| {
    //         surcharge_details
    //             .get_total_surcharge_amount()
    //             .get_amount_as_i64()
    //     })
    // }

    // fn is_customer_initiated_mandate_payment(&self) -> bool {
    //     (self.customer_acceptance.is_some() || self.setup_mandate_details.is_some())
    //         && self.setup_future_usage == Some(storage_enums::FutureUsage::OffSession)
    // }

    pub fn get_metadata_as_object(&self) -> Option<SecretSerdeValue> {
        self.metadata.clone().and_then(|meta_data| match meta_data {
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_)
            | serde_json::Value::Array(_) => None,
            serde_json::Value::Object(_) => Some(meta_data.into()),
        })
    }

    // fn get_authentication_data(&self) -> Result<AuthenticationData, Error> {
    //     self.authentication_data
    //         .clone()
    //         .ok_or_else(missing_field_err("authentication_data"))
    // }

    // fn get_connector_mandate_request_reference_id(&self) -> Result<String, Error> {
    //     self.mandate_id
    //         .as_ref()
    //         .and_then(|mandate_ids| match &mandate_ids.mandate_reference_id {
    //             Some(MandateReferenceId::ConnectorMandateId(connector_mandate_ids)) => {
    //                 connector_mandate_ids.get_connector_mandate_request_reference_id()
    //             }
    //             Some(MandateReferenceId::NetworkMandateId(_))
    //             | None
    //             | Some(MandateReferenceId::NetworkTokenWithNTI(_)) => None,
    //         })
    //         .ok_or_else(missing_field_err("connector_mandate_request_reference_id"))
    // }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ResponseId {
    ConnectorTransactionId(String),
    EncodedData(String),
    #[default]
    NoResponseId,
}
impl ResponseId {
    pub fn get_connector_transaction_id(
        &self,
    ) -> errors::CustomResult<String, errors::ValidationError> {
        match self {
            Self::ConnectorTransactionId(txn_id) => Ok(txn_id.to_string()),
            _ => Err(errors::ValidationError::IncorrectValueProvided {
                field_name: "connector_transaction_id",
            })
            .attach_printable("Expected connector transaction ID not found"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentsResponseData {
    TransactionResponse {
        resource_id: ResponseId,
        redirection_data: Option<Box<crate::router_response_types::RedirectForm>>,
        connector_metadata: Option<serde_json::Value>,
        mandate_reference: Option<Box<MandateReference>>,
        network_txn_id: Option<String>,
        connector_response_reference_id: Option<String>,
        incremental_authorization_allowed: Option<bool>,
        raw_connector_response: Option<String>,
        status_code: Option<u16>,
    },
    SessionResponse {
        session_token: String,
        status_code: Option<u16>,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct MandateReference {
    pub connector_mandate_id: Option<String>,
    pub payment_method_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PaymentCreateOrderData {
    pub amount: MinorUnit,
    pub currency: Currency,
    pub integrity_object: Option<CreateOrderIntegrityObject>,
    pub metadata: Option<serde_json::Value>,
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PaymentCreateOrderResponse {
    pub order_id: String,
}

#[derive(Debug, Default, Clone)]
pub struct RefundSyncData {
    pub connector_transaction_id: String,
    pub connector_refund_id: String,
    pub reason: Option<String>,
    pub refund_connector_metadata: Option<common_utils::pii::SecretSerdeValue>,
    pub refund_status: common_enums::RefundStatus,
    pub all_keys_required: Option<bool>,
    pub integrity_object: Option<RefundSyncIntegrityObject>,
}

#[derive(Debug, Clone)]
pub struct RefundsResponseData {
    pub connector_refund_id: String,
    pub refund_status: common_enums::RefundStatus,
    pub raw_connector_response: Option<String>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct RefundFlowData {
    pub status: common_enums::RefundStatus,
    pub refund_id: Option<String>,
    pub connectors: Connectors,
    pub raw_connector_response: Option<String>,
}

impl RawConnectorResponse for RefundFlowData {
    fn set_raw_connector_response(&mut self, response: Option<String>) {
        self.raw_connector_response = response;
    }
}

#[derive(Debug, Clone)]
pub struct WebhookDetailsResponse {
    pub resource_id: Option<ResponseId>,
    pub status: common_enums::AttemptStatus,
    pub connector_response_reference_id: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub raw_connector_response: Option<String>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct RefundWebhookDetailsResponse {
    pub connector_refund_id: Option<String>,
    pub status: common_enums::RefundStatus,
    pub connector_response_reference_id: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub raw_connector_response: Option<String>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct DisputeWebhookDetailsResponse {
    pub dispute_id: String,
    pub status: common_enums::DisputeStatus,
    pub stage: common_enums::DisputeStage,
    pub connector_response_reference_id: Option<String>,
    pub dispute_message: Option<String>,
    pub raw_connector_response: Option<String>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Options,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch,
}

#[derive(Debug, Clone)]
pub struct RequestDetails {
    pub method: HttpMethod,
    pub uri: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub query_params: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectorWebhookSecrets {
    pub secret: Vec<u8>,
    pub additional_secret: Option<hyperswitch_masking::Secret<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    Payment,
    Refund,
    Dispute,
}

impl ForeignTryFrom<grpc_api_types::payments::WebhookEventType> for EventType {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::WebhookEventType,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            grpc_api_types::payments::WebhookEventType::WebhookPayment => Ok(Self::Payment),
            grpc_api_types::payments::WebhookEventType::WebhookRefund => Ok(Self::Refund),
            grpc_api_types::payments::WebhookEventType::WebhookDispute => Ok(Self::Dispute),
            grpc_api_types::payments::WebhookEventType::Unspecified => Ok(Self::Payment), // Default to Payment
        }
    }
}

impl ForeignTryFrom<EventType> for grpc_api_types::payments::WebhookEventType {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(value: EventType) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            EventType::Payment => Ok(Self::WebhookPayment),
            EventType::Refund => Ok(Self::WebhookRefund),
            EventType::Dispute => Ok(Self::WebhookDispute),
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::HttpMethod> for HttpMethod {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::HttpMethod,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        match value {
            grpc_api_types::payments::HttpMethod::Unspecified => Ok(Self::Get), // Default
            grpc_api_types::payments::HttpMethod::Get => Ok(Self::Get),
            grpc_api_types::payments::HttpMethod::Post => Ok(Self::Post),
            grpc_api_types::payments::HttpMethod::Put => Ok(Self::Put),
            grpc_api_types::payments::HttpMethod::Delete => Ok(Self::Delete),
        }
    }
}

impl ForeignTryFrom<grpc_api_types::payments::RequestDetails> for RequestDetails {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::RequestDetails,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let method = HttpMethod::foreign_try_from(value.method())?;

        Ok(Self {
            method,
            uri: value.uri,
            headers: value.headers,
            body: value.body,
            query_params: value.query_params,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::payments::WebhookSecrets> for ConnectorWebhookSecrets {
    type Error = ApplicationErrorResponse;

    fn foreign_try_from(
        value: grpc_api_types::payments::WebhookSecrets,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        Ok(Self {
            secret: value.secret.into(),
            additional_secret: value.additional_secret.map(Secret::new),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RefundsData {
    pub refund_id: String,
    pub connector_transaction_id: String,
    pub connector_refund_id: Option<String>,
    pub currency: Currency,
    pub payment_amount: i64,
    pub reason: Option<String>,
    pub webhook_url: Option<String>,
    pub refund_amount: i64,
    pub connector_metadata: Option<serde_json::Value>,
    pub refund_connector_metadata: Option<common_utils::pii::SecretSerdeValue>,
    pub minor_payment_amount: MinorUnit,
    pub minor_refund_amount: MinorUnit,
    pub refund_status: common_enums::RefundStatus,
    pub merchant_account_id: Option<String>,
    pub capture_method: Option<common_enums::CaptureMethod>,
    pub integrity_object: Option<RefundIntegrityObject>,
}

impl RefundsData {
    #[track_caller]
    pub fn get_connector_refund_id(&self) -> Result<String, Error> {
        self.connector_refund_id
            .clone()
            .get_required_value("connector_refund_id")
            .change_context(crate::errors::ConnectorError::MissingConnectorTransactionID)
    }
    pub fn get_webhook_url(&self) -> Result<String, Error> {
        self.webhook_url
            .clone()
            .ok_or_else(missing_field_err("webhook_url"))
    }
    pub fn get_connector_metadata(&self) -> Result<serde_json::Value, Error> {
        self.connector_metadata
            .clone()
            .ok_or_else(missing_field_err("connector_metadata"))
    }
}

#[derive(Debug, Clone, Default)]
pub struct MultipleCaptureRequestData {
    pub capture_sequence: i64,
    pub capture_reference: String,
}

#[derive(Debug, Default, Clone)]
pub struct PaymentsCaptureData {
    pub amount_to_capture: i64,
    pub minor_amount_to_capture: MinorUnit,
    pub currency: Currency,
    pub connector_transaction_id: ResponseId,
    pub multiple_capture_data: Option<MultipleCaptureRequestData>,
    pub connector_metadata: Option<serde_json::Value>,
    pub integrity_object: Option<CaptureIntegrityObject>,
}

impl PaymentsCaptureData {
    pub fn is_multiple_capture(&self) -> bool {
        self.multiple_capture_data.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct SetupMandateRequestData {
    pub currency: Currency,
    pub payment_method_data: crate::payment_method_data::PaymentMethodData,
    pub amount: Option<i64>,
    pub confirm: bool,
    pub statement_descriptor_suffix: Option<String>,
    pub statement_descriptor: Option<String>,
    pub customer_acceptance: Option<crate::mandates::CustomerAcceptance>,
    pub mandate_id: Option<MandateIds>,
    pub setup_future_usage: Option<common_enums::FutureUsage>,
    pub off_session: Option<bool>,
    pub setup_mandate_details: Option<crate::mandates::MandateData>,
    pub router_return_url: Option<String>,
    pub webhook_url: Option<String>,
    pub browser_info: Option<crate::router_request_types::BrowserInformation>,
    pub email: Option<common_utils::pii::Email>,
    pub customer_name: Option<String>,
    pub return_url: Option<String>,
    pub payment_method_type: Option<common_enums::PaymentMethodType>,
    pub request_incremental_authorization: bool,
    pub metadata: Option<serde_json::Value>,
    pub complete_authorize_url: Option<String>,
    pub capture_method: Option<common_enums::CaptureMethod>,
    pub merchant_order_reference_id: Option<String>,
    pub minor_amount: Option<MinorUnit>,
    pub shipping_cost: Option<MinorUnit>,
    pub customer_id: Option<common_utils::id_type::CustomerId>,
    pub integrity_object: Option<SetupMandateIntegrityObject>,
}

impl SetupMandateRequestData {
    pub fn get_browser_info(&self) -> Result<BrowserInformation, Error> {
        self.browser_info
            .clone()
            .ok_or_else(missing_field_err("browser_info"))
    }
    pub fn get_email(&self) -> Result<Email, Error> {
        self.email.clone().ok_or_else(missing_field_err("email"))
    }
    pub fn is_card(&self) -> bool {
        matches!(self.payment_method_data, PaymentMethodData::Card(_))
    }
}

#[derive(Debug, Clone)]
pub struct RepeatPaymentData {
    pub mandate_reference: MandateReferenceId,
    pub amount: i64,
    pub minor_amount: MinorUnit,
    pub currency: Currency,
    pub merchant_order_reference_id: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub webhook_url: Option<String>,
    pub integrity_object: Option<crate::router_request_types::RepeatPaymentIntegrityObject>,
}

impl RepeatPaymentData {
    pub fn get_mandate_reference(&self) -> &MandateReferenceId {
        &self.mandate_reference
    }
}

#[derive(Debug, Clone)]
pub struct AcceptDisputeData {
    pub connector_dispute_id: String,
    pub integrity_object: Option<AcceptDisputeIntegrityObject>,
}

#[derive(Debug, Clone)]
pub struct DisputeFlowData {
    pub dispute_id: Option<String>,
    pub connector_dispute_id: String,
    pub connectors: Connectors,
    pub defense_reason_code: Option<String>,
    pub raw_connector_response: Option<String>,
}

impl RawConnectorResponse for DisputeFlowData {
    fn set_raw_connector_response(&mut self, response: Option<String>) {
        self.raw_connector_response = response;
    }
}

#[derive(Debug, Clone)]
pub struct DisputeResponseData {
    pub connector_dispute_id: String,
    pub dispute_status: DisputeStatus,
    pub connector_dispute_status: Option<String>,
    pub raw_connector_response: Option<String>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, Default)]
pub struct SubmitEvidenceData {
    pub dispute_id: Option<String>,
    pub connector_dispute_id: String,
    pub integrity_object: Option<SubmitEvidenceIntegrityObject>,
    pub access_activity_log: Option<String>,
    pub billing_address: Option<String>,

    pub cancellation_policy: Option<Vec<u8>>,
    pub cancellation_policy_file_type: Option<String>,
    pub cancellation_policy_provider_file_id: Option<String>,
    pub cancellation_policy_disclosure: Option<String>,
    pub cancellation_rebuttal: Option<String>,

    pub customer_communication: Option<Vec<u8>>,
    pub customer_communication_file_type: Option<String>,
    pub customer_communication_provider_file_id: Option<String>,
    pub customer_email_address: Option<String>,
    pub customer_name: Option<String>,
    pub customer_purchase_ip: Option<String>,

    pub customer_signature: Option<Vec<u8>>,
    pub customer_signature_file_type: Option<String>,
    pub customer_signature_provider_file_id: Option<String>,

    pub product_description: Option<String>,

    pub receipt: Option<Vec<u8>>,
    pub receipt_file_type: Option<String>,
    pub receipt_provider_file_id: Option<String>,

    pub refund_policy: Option<Vec<u8>>,
    pub refund_policy_file_type: Option<String>,
    pub refund_policy_provider_file_id: Option<String>,
    pub refund_policy_disclosure: Option<String>,
    pub refund_refusal_explanation: Option<String>,

    pub service_date: Option<String>,
    pub service_documentation: Option<Vec<u8>>,
    pub service_documentation_file_type: Option<String>,
    pub service_documentation_provider_file_id: Option<String>,

    pub shipping_address: Option<String>,
    pub shipping_carrier: Option<String>,
    pub shipping_date: Option<String>,
    pub shipping_documentation: Option<Vec<u8>>,
    pub shipping_documentation_file_type: Option<String>,
    pub shipping_documentation_provider_file_id: Option<String>,
    pub shipping_tracking_number: Option<String>,

    pub invoice_showing_distinct_transactions: Option<Vec<u8>>,
    pub invoice_showing_distinct_transactions_file_type: Option<String>,
    pub invoice_showing_distinct_transactions_provider_file_id: Option<String>,

    pub recurring_transaction_agreement: Option<Vec<u8>>,
    pub recurring_transaction_agreement_file_type: Option<String>,
    pub recurring_transaction_agreement_provider_file_id: Option<String>,

    pub uncategorized_file: Option<Vec<u8>>,
    pub uncategorized_file_type: Option<String>,
    pub uncategorized_file_provider_file_id: Option<String>,
    pub uncategorized_text: Option<String>,
}

/// The trait that provides specifications about the connector
pub trait ConnectorSpecifications {
    /// Details related to payment method supported by the connector
    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        None
    }

    /// Supported webhooks flows
    fn get_supported_webhook_flows(&self) -> Option<&'static [EventClass]> {
        None
    }

    /// About the connector
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        None
    }
}

#[macro_export]
macro_rules! capture_method_not_supported {
    ($connector:expr, $capture_method:expr) => {
        Err(errors::ConnectorError::NotSupported {
            message: format!("{} for selected payment method", $capture_method),
            connector: $connector,
        }
        .into())
    };
    ($connector:expr, $capture_method:expr, $payment_method_type:expr) => {
        Err(errors::ConnectorError::NotSupported {
            message: format!("{} for {}", $capture_method, $payment_method_type),
            connector: $connector,
        }
        .into())
    };
}

#[macro_export]
macro_rules! payment_method_not_supported {
    ($connector:expr, $payment_method:expr, $payment_method_type:expr) => {
        Err(errors::ConnectorError::NotSupported {
            message: format!(
                "Payment method {} with type {} is not supported",
                $payment_method, $payment_method_type
            ),
            connector: $connector,
        }
        .into())
    };
}

impl From<PaymentMethodData> for PaymentMethodDataType {
    fn from(pm_data: PaymentMethodData) -> Self {
        match pm_data {
            PaymentMethodData::Card(_) => Self::Card,
            PaymentMethodData::CardRedirect(card_redirect_data) => match card_redirect_data {
                payment_method_data::CardRedirectData::Knet {} => Self::Knet,
                payment_method_data::CardRedirectData::Benefit {} => Self::Benefit,
                payment_method_data::CardRedirectData::MomoAtm {} => Self::MomoAtm,
                payment_method_data::CardRedirectData::CardRedirect {} => Self::CardRedirect,
            },
            PaymentMethodData::Wallet(wallet_data) => match wallet_data {
                payment_method_data::WalletData::AliPayQr(_) => Self::AliPayQr,
                payment_method_data::WalletData::AliPayRedirect(_) => Self::AliPayRedirect,
                payment_method_data::WalletData::AliPayHkRedirect(_) => Self::AliPayHkRedirect,
                payment_method_data::WalletData::MomoRedirect(_) => Self::MomoRedirect,
                payment_method_data::WalletData::KakaoPayRedirect(_) => Self::KakaoPayRedirect,
                payment_method_data::WalletData::GoPayRedirect(_) => Self::GoPayRedirect,
                payment_method_data::WalletData::GcashRedirect(_) => Self::GcashRedirect,
                payment_method_data::WalletData::ApplePay(_) => Self::ApplePay,
                payment_method_data::WalletData::ApplePayRedirect(_) => Self::ApplePayRedirect,
                payment_method_data::WalletData::ApplePayThirdPartySdk(_) => {
                    Self::ApplePayThirdPartySdk
                }
                payment_method_data::WalletData::DanaRedirect {} => Self::DanaRedirect,
                payment_method_data::WalletData::GooglePay(_) => Self::GooglePay,
                payment_method_data::WalletData::GooglePayRedirect(_) => Self::GooglePayRedirect,
                payment_method_data::WalletData::GooglePayThirdPartySdk(_) => {
                    Self::GooglePayThirdPartySdk
                }
                payment_method_data::WalletData::MbWayRedirect(_) => Self::MbWayRedirect,
                payment_method_data::WalletData::MobilePayRedirect(_) => Self::MobilePayRedirect,
                payment_method_data::WalletData::PaypalRedirect(_) => Self::PaypalRedirect,
                payment_method_data::WalletData::PaypalSdk(_) => Self::PaypalSdk,
                payment_method_data::WalletData::SamsungPay(_) => Self::SamsungPay,
                payment_method_data::WalletData::TwintRedirect {} => Self::TwintRedirect,
                payment_method_data::WalletData::VippsRedirect {} => Self::VippsRedirect,
                payment_method_data::WalletData::TouchNGoRedirect(_) => Self::TouchNGoRedirect,
                payment_method_data::WalletData::WeChatPayRedirect(_) => Self::WeChatPayRedirect,
                payment_method_data::WalletData::WeChatPayQr(_) => Self::WeChatPayQr,
                payment_method_data::WalletData::CashappQr(_) => Self::CashappQr,
                payment_method_data::WalletData::SwishQr(_) => Self::SwishQr,
                payment_method_data::WalletData::Mifinity(_) => Self::Mifinity,
                payment_method_data::WalletData::AmazonPayRedirect(_) => Self::AmazonPayRedirect,
                payment_method_data::WalletData::Paze(_) => Self::Paze,
                payment_method_data::WalletData::RevolutPay(_) => Self::RevolutPay,
            },
            PaymentMethodData::PayLater(pay_later_data) => match pay_later_data {
                payment_method_data::PayLaterData::KlarnaRedirect { .. } => Self::KlarnaRedirect,
                payment_method_data::PayLaterData::KlarnaSdk { .. } => Self::KlarnaSdk,
                payment_method_data::PayLaterData::AffirmRedirect {} => Self::AffirmRedirect,
                payment_method_data::PayLaterData::AfterpayClearpayRedirect { .. } => {
                    Self::AfterpayClearpayRedirect
                }
                payment_method_data::PayLaterData::PayBrightRedirect {} => Self::PayBrightRedirect,
                payment_method_data::PayLaterData::WalleyRedirect {} => Self::WalleyRedirect,
                payment_method_data::PayLaterData::AlmaRedirect {} => Self::AlmaRedirect,
                payment_method_data::PayLaterData::AtomeRedirect {} => Self::AtomeRedirect,
            },
            PaymentMethodData::BankRedirect(bank_redirect_data) => match bank_redirect_data {
                payment_method_data::BankRedirectData::BancontactCard { .. } => {
                    Self::BancontactCard
                }
                payment_method_data::BankRedirectData::Bizum {} => Self::Bizum,
                payment_method_data::BankRedirectData::Blik { .. } => Self::Blik,
                payment_method_data::BankRedirectData::Eps { .. } => Self::Eps,
                payment_method_data::BankRedirectData::Giropay { .. } => Self::Giropay,
                payment_method_data::BankRedirectData::Ideal { .. } => Self::Ideal,
                payment_method_data::BankRedirectData::Interac { .. } => Self::Interac,
                payment_method_data::BankRedirectData::OnlineBankingCzechRepublic { .. } => {
                    Self::OnlineBankingCzechRepublic
                }
                payment_method_data::BankRedirectData::OnlineBankingFinland { .. } => {
                    Self::OnlineBankingFinland
                }
                payment_method_data::BankRedirectData::OnlineBankingPoland { .. } => {
                    Self::OnlineBankingPoland
                }
                payment_method_data::BankRedirectData::OnlineBankingSlovakia { .. } => {
                    Self::OnlineBankingSlovakia
                }
                payment_method_data::BankRedirectData::OpenBankingUk { .. } => Self::OpenBankingUk,
                payment_method_data::BankRedirectData::Przelewy24 { .. } => Self::Przelewy24,
                payment_method_data::BankRedirectData::Sofort { .. } => Self::Sofort,
                payment_method_data::BankRedirectData::Trustly { .. } => Self::Trustly,
                payment_method_data::BankRedirectData::OnlineBankingFpx { .. } => {
                    Self::OnlineBankingFpx
                }
                payment_method_data::BankRedirectData::OnlineBankingThailand { .. } => {
                    Self::OnlineBankingThailand
                }
                payment_method_data::BankRedirectData::LocalBankRedirect {} => {
                    Self::LocalBankRedirect
                }
                payment_method_data::BankRedirectData::Eft { .. } => Self::Eft,
            },
            PaymentMethodData::BankDebit(bank_debit_data) => match bank_debit_data {
                payment_method_data::BankDebitData::AchBankDebit { .. } => Self::AchBankDebit,
                payment_method_data::BankDebitData::SepaBankDebit { .. } => Self::SepaBankDebit,
                payment_method_data::BankDebitData::BecsBankDebit { .. } => Self::BecsBankDebit,
                payment_method_data::BankDebitData::BacsBankDebit { .. } => Self::BacsBankDebit,
            },
            PaymentMethodData::BankTransfer(bank_transfer_data) => match *bank_transfer_data {
                payment_method_data::BankTransferData::AchBankTransfer { .. } => {
                    Self::AchBankTransfer
                }
                payment_method_data::BankTransferData::SepaBankTransfer { .. } => {
                    Self::SepaBankTransfer
                }
                payment_method_data::BankTransferData::BacsBankTransfer { .. } => {
                    Self::BacsBankTransfer
                }
                payment_method_data::BankTransferData::MultibancoBankTransfer { .. } => {
                    Self::MultibancoBankTransfer
                }
                payment_method_data::BankTransferData::PermataBankTransfer { .. } => {
                    Self::PermataBankTransfer
                }
                payment_method_data::BankTransferData::BcaBankTransfer { .. } => {
                    Self::BcaBankTransfer
                }
                payment_method_data::BankTransferData::BniVaBankTransfer { .. } => {
                    Self::BniVaBankTransfer
                }
                payment_method_data::BankTransferData::BriVaBankTransfer { .. } => {
                    Self::BriVaBankTransfer
                }
                payment_method_data::BankTransferData::CimbVaBankTransfer { .. } => {
                    Self::CimbVaBankTransfer
                }
                payment_method_data::BankTransferData::DanamonVaBankTransfer { .. } => {
                    Self::DanamonVaBankTransfer
                }
                payment_method_data::BankTransferData::MandiriVaBankTransfer { .. } => {
                    Self::MandiriVaBankTransfer
                }
                payment_method_data::BankTransferData::Pix { .. } => Self::Pix,
                payment_method_data::BankTransferData::Pse {} => Self::Pse,
                payment_method_data::BankTransferData::LocalBankTransfer { .. } => {
                    Self::LocalBankTransfer
                }
                payment_method_data::BankTransferData::InstantBankTransfer { .. } => {
                    Self::InstantBankTransfer
                }
                payment_method_data::BankTransferData::InstantBankTransferFinland { .. } => {
                    Self::InstantBankTransferFinland
                }
                payment_method_data::BankTransferData::InstantBankTransferPoland { .. } => {
                    Self::InstantBankTransferPoland
                }
            },
            PaymentMethodData::Crypto(_) => Self::Crypto,
            PaymentMethodData::MandatePayment => Self::MandatePayment,
            PaymentMethodData::Reward => Self::Reward,
            PaymentMethodData::Upi(_) => Self::Upi,
            PaymentMethodData::Voucher(voucher_data) => match voucher_data {
                payment_method_data::VoucherData::Boleto(_) => Self::Boleto,
                payment_method_data::VoucherData::Efecty => Self::Efecty,
                payment_method_data::VoucherData::PagoEfectivo => Self::PagoEfectivo,
                payment_method_data::VoucherData::RedCompra => Self::RedCompra,
                payment_method_data::VoucherData::RedPagos => Self::RedPagos,
                payment_method_data::VoucherData::Alfamart(_) => Self::Alfamart,
                payment_method_data::VoucherData::Indomaret(_) => Self::Indomaret,
                payment_method_data::VoucherData::Oxxo => Self::Oxxo,
                payment_method_data::VoucherData::SevenEleven(_) => Self::SevenEleven,
                payment_method_data::VoucherData::Lawson(_) => Self::Lawson,
                payment_method_data::VoucherData::MiniStop(_) => Self::MiniStop,
                payment_method_data::VoucherData::FamilyMart(_) => Self::FamilyMart,
                payment_method_data::VoucherData::Seicomart(_) => Self::Seicomart,
                payment_method_data::VoucherData::PayEasy(_) => Self::PayEasy,
            },
            PaymentMethodData::RealTimePayment(real_time_payment_data) => {
                match *real_time_payment_data {
                    payment_method_data::RealTimePaymentData::DuitNow {} => Self::DuitNow,
                    payment_method_data::RealTimePaymentData::Fps {} => Self::Fps,
                    payment_method_data::RealTimePaymentData::PromptPay {} => Self::PromptPay,
                    payment_method_data::RealTimePaymentData::VietQr {} => Self::VietQr,
                }
            }
            PaymentMethodData::GiftCard(gift_card_data) => match *gift_card_data {
                payment_method_data::GiftCardData::Givex(_) => Self::Givex,
                payment_method_data::GiftCardData::PaySafeCard {} => Self::PaySafeCar,
            },
            PaymentMethodData::CardToken(_) => Self::CardToken,
            PaymentMethodData::OpenBanking(data) => match data {
                payment_method_data::OpenBankingData::OpenBankingPIS {} => Self::OpenBanking,
            },
            PaymentMethodData::CardDetailsForNetworkTransactionId(_) => {
                Self::CardDetailsForNetworkTransactionId
            }
            PaymentMethodData::NetworkToken(_) => Self::NetworkToken,
            PaymentMethodData::MobilePayment(mobile_payment_data) => match mobile_payment_data {
                payment_method_data::MobilePaymentData::DirectCarrierBilling { .. } => {
                    Self::DirectCarrierBilling
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct DisputeDefendData {
    pub dispute_id: String,
    pub connector_dispute_id: String,
    pub defense_reason_code: String,
    pub integrity_object: Option<DefendDisputeIntegrityObject>,
}

pub trait SupportedPaymentMethodsExt {
    fn add(
        &mut self,
        payment_method: PaymentMethod,
        payment_method_type: PaymentMethodType,
        payment_method_details: PaymentMethodDetails,
    );
}

impl SupportedPaymentMethodsExt for SupportedPaymentMethods {
    fn add(
        &mut self,
        payment_method: PaymentMethod,
        payment_method_type: PaymentMethodType,
        payment_method_details: PaymentMethodDetails,
    ) {
        if let Some(payment_method_data) = self.get_mut(&payment_method) {
            payment_method_data.insert(payment_method_type, payment_method_details);
        } else {
            let mut payment_method_type_metadata = PaymentMethodTypeMetadata::new();
            payment_method_type_metadata.insert(payment_method_type, payment_method_details);

            self.insert(payment_method, payment_method_type_metadata);
        }
    }
}
