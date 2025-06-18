use common_enums as api_enums;
use common_utils::ext_traits::ConfigExt;
use common_utils::pii::Email;
use masking::{PeekInterface, Secret};
use utoipa::ToSchema;

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

#[derive(Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize, Clone)]
pub enum MandateReferenceId {
    ConnectorMandateId(ConnectorMandateReferenceId), // mandate_id send by connector
    NetworkMandateId(String), // network_txns_id send by Issuer to connector, Used for PG agnostic mandate txns along with card data
    NetworkTokenWithNTI(NetworkTokenWithNTIRef), // network_txns_id send by Issuer to connector, Used for PG agnostic mandate txns along with network token data
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone, Eq, PartialEq)]
pub struct NetworkTokenWithNTIRef {
    pub network_transaction_id: String,
    pub token_exp_month: Option<Secret<String>>,
    pub token_exp_year: Option<Secret<String>>,
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

    pub fn get_connector_mandate_id(&self) -> Option<&String> {
        self.connector_mandate_id.as_ref()
    }

    pub fn get_payment_method_id(&self) -> Option<&String> {
        self.payment_method_id.as_ref()
    }

    pub fn get_update_history(&self) -> Option<&Vec<UpdateHistory>> {
        self.update_history.as_ref()
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

#[derive(Default, Clone, Debug, Eq, PartialEq, ToSchema, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    /// Provide the address details
    pub address: Option<AddressDetails>,

    pub phone: Option<PhoneDetails>,

    #[schema(value_type = Option<String>)]
    pub email: Option<Email>,
}

impl masking::SerializableSecret for Address {}

impl Address {
    /// Unify the address, giving priority to `self` when details are present in both
    pub fn unify_address(self, other: Option<&Self>) -> Self {
        let other_address_details = other.and_then(|address| address.address.as_ref());
        Self {
            address: self
                .address
                .map(|address| address.unify_address_details(other_address_details))
                .or(other_address_details.cloned()),
            email: self.email.or(other.and_then(|other| other.email.clone())),
            phone: self.phone.or(other.and_then(|other| other.phone.clone())),
        }
    }
}

// used by customers also, could be moved outside
/// Address details
#[derive(Clone, Default, Debug, Eq, serde::Deserialize, serde::Serialize, PartialEq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressDetails {
    /// The city, district, suburb, town, or village of the address.
    #[schema(max_length = 50, example = "New York")]
    pub city: Option<String>,

    /// The two-letter ISO 3166-1 alpha-2 country code (e.g., US, GB).
    #[schema(value_type = Option<CountryAlpha2>, example = "US")]
    pub country: Option<api_enums::CountryAlpha2>,

    /// The first line of the street address or P.O. Box.
    #[schema(value_type = Option<String>, max_length = 200, example = "123, King Street")]
    pub line1: Option<Secret<String>>,

    /// The second line of the street address or P.O. Box (e.g., apartment, suite, unit, or building).
    #[schema(value_type = Option<String>, max_length = 50, example = "Powelson Avenue")]
    pub line2: Option<Secret<String>>,

    /// The third line of the street address, if applicable.
    #[schema(value_type = Option<String>, max_length = 50, example = "Bridgewater")]
    pub line3: Option<Secret<String>>,

    /// The zip/postal code for the address
    #[schema(value_type = Option<String>, max_length = 50, example = "08807")]
    pub zip: Option<Secret<String>>,

    /// The address state
    #[schema(value_type = Option<String>, example = "New York")]
    pub state: Option<Secret<String>>,

    /// The first name for the address
    #[schema(value_type = Option<String>, max_length = 255, example = "John")]
    pub first_name: Option<Secret<String>>,

    /// The last name for the address
    #[schema(value_type = Option<String>, max_length = 255, example = "Doe")]
    pub last_name: Option<Secret<String>>,
}

impl AddressDetails {
    pub fn get_optional_full_name(&self) -> Option<Secret<String>> {
        match (self.first_name.as_ref(), self.last_name.as_ref()) {
            (Some(first_name), Some(last_name)) => Some(Secret::new(format!(
                "{} {}",
                first_name.peek(),
                last_name.peek()
            ))),
            (Some(name), None) | (None, Some(name)) => Some(name.to_owned()),
            _ => None,
        }
    }

    pub fn unify_address_details(self, other: Option<&Self>) -> Self {
        if let Some(other) = other {
            let (first_name, last_name) = if self
                .first_name
                .as_ref()
                .is_some_and(|first_name| !first_name.is_empty_after_trim())
            {
                (self.first_name, self.last_name)
            } else {
                (other.first_name.clone(), other.last_name.clone())
            };

            Self {
                first_name,
                last_name,
                city: self.city.or(other.city.clone()),
                country: self.country.or(other.country),
                line1: self.line1.or(other.line1.clone()),
                line2: self.line2.or(other.line2.clone()),
                line3: self.line3.or(other.line3.clone()),
                zip: self.zip.or(other.zip.clone()),
                state: self.state.or(other.state.clone()),
            }
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, ToSchema, serde::Deserialize, serde::Serialize)]
pub struct PhoneDetails {
    /// The contact number
    #[schema(value_type = Option<String>, example = "9123456789")]
    pub number: Option<Secret<String>>,
    /// The country code attached to the number
    #[schema(example = "+1")]
    pub country_code: Option<String>,
}
