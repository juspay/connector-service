// Provider models and mappings ported from Hyperswitch adyenplatform/transformers/payouts.rs.
use common_utils::{pii, types::MinorUnit};
use domain_types::{
    connector_flow::PayoutTransfer,
    connector_types::EventType,
    errors::IntegrationError,
    payment_method_data::PaymentMethodDataTypes,
    payouts::payouts_types::PayoutTransferResponse,
    payouts::{
        payout_method_data::{Bank, PayoutMethodData},
        payouts_types::{PayoutFlowData, PayoutTransferRequest},
    },
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Amount {
    currency: common_enums::Currency,
    value: MinorUnit,
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenTransferRequest {
    amount: Amount,
    balance_account_id: Secret<String>,
    category: AdyenPayoutMethod,
    counterparty: AdyenPayoutMethodDetails,
    priority: Option<AdyenPayoutPriority>,
    reference: String,
    reference_for_beneficiary: String,
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdyenPayoutMethod {
    Bank,
    Card,
    PlatformPayment,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AdyenPayoutMethodDetails {
    BankAccount(AdyenBankAccountDetails),
    Card(AdyenCardDetails),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenBankAccountDetails {
    account_holder: AdyenAccountHolder,
    account_identification: AdyenBankAccountIdentification,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenAccountHolder {
    address: Option<AdyenAddress>,
    first_name: Option<Secret<String>>,
    last_name: Option<Secret<String>>,
    full_name: Option<Secret<String>>,
    email: Option<pii::Email>,
    #[serde(rename = "reference")]
    customer_id: Option<String>,
    #[serde(rename = "type")]
    entity_type: Option<EntityType>,
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenAddress {
    line1: Secret<String>,
    line2: Secret<String>,
    postal_code: Option<Secret<String>>,
    state_or_province: Option<Secret<String>>,
    city: String,
    country: common_enums::CountryAlpha2,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdyenBankAccountIdentification {
    #[serde(rename = "type")]
    bank_type: String,
    #[serde(flatten)]
    account_details: AdyenBankAccountIdentificationDetails,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AdyenBankAccountIdentificationDetails {
    Sepa(SepaDetails),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SepaDetails {
    iban: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenCardDetails {
    card_holder: AdyenAccountHolder,
    card_identification: AdyenCardIdentification,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum AdyenCardIdentification {
    Card(AdyenRawCardIdentification),
    Stored(AdyenStoredCardIdentification),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenRawCardIdentification {
    #[serde(rename = "number")]
    card_number: cards::CardNumber,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    issue_number: Option<String>,
    start_month: Option<String>,
    start_year: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenStoredCardIdentification {
    stored_payment_method_id: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdyenPayoutPriority {
    Instant,
    Fast,
    Regular,
    Wire,
    CrossBorder,
    Internal,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityType {
    Individual,
    Organization,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenTransferResponse {
    id: String,
    account_holder: AdyenPlatformAccountHolder,
    amount: Amount,
    balance_account: AdyenBalanceAccount,
    category: AdyenPayoutMethod,
    category_data: Option<AdyenCategoryData>,
    direction: AdyenTransactionDirection,
    reference: String,
    reference_for_beneficiary: String,
    status: AdyenTransferStatus,
    #[serde(rename = "type")]
    transaction_type: AdyenTransactionType,
    reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdyenPlatformAccountHolder {
    description: Option<String>,
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdyenCategoryData {
    priority: AdyenPayoutPriority,
    #[serde(rename = "type")]
    category: AdyenPayoutMethod,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdyenBalanceAccount {
    description: Option<String>,
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdyenTransactionDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "lowercase")]
pub enum AdyenTransferStatus {
    Authorised,
    Refused,
    Error,
    Pending,
    Booked,
    Received,
    Returned,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdyenTransactionType {
    BankTransfer,
    CardTransfer,
    InternalTransfer,
    Payment,
    Refund,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenplatformIncomingWebhook {
    pub data: AdyenplatformIncomingWebhookData,
    #[serde(rename = "type")]
    pub webhook_type: AdyenplatformWebhookEventType,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenplatformIncomingWebhookData {
    pub status: AdyenplatformWebhookStatus,
    pub reference: String,
    pub tracking: Option<AdyenplatformTrackingData>,
    pub reason: Option<String>,
    pub category: Option<AdyenPayoutMethod>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenplatformTrackingData {
    pub status: TrackingStatus,
    pub reason: Option<String>,
    pub estimated_arrival_time: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrackingStatus {
    Accepted,
    Pending,
    Credited,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AdyenplatformWebhookEventType {
    #[serde(rename = "balancePlatform.transfer.created")]
    PayoutCreated,
    #[serde(rename = "balancePlatform.transfer.updated")]
    PayoutUpdated,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdyenplatformWebhookStatus {
    Authorised,
    Booked,
    Pending,
    Failed,
    Returned,
    Received,
}
pub fn get_adyen_payout_webhook_event(
    event_type: AdyenplatformWebhookEventType,
    status: AdyenplatformWebhookStatus,
    tracking_data: Option<AdyenplatformTrackingData>,
) -> EventType {
    match (event_type, status, tracking_data) {
        (AdyenplatformWebhookEventType::PayoutCreated, _, _) => EventType::PayoutCreated,
        (AdyenplatformWebhookEventType::PayoutUpdated, _, Some(tracking_data)) => {
            match tracking_data.status {
                TrackingStatus::Credited | TrackingStatus::Accepted => EventType::PayoutSuccess,
                TrackingStatus::Pending => EventType::PayoutProcessing,
            }
        }
        (AdyenplatformWebhookEventType::PayoutUpdated, status, _) => match status {
            AdyenplatformWebhookStatus::Authorised | AdyenplatformWebhookStatus::Received => {
                EventType::PayoutCreated
            }
            AdyenplatformWebhookStatus::Booked | AdyenplatformWebhookStatus::Pending => {
                EventType::PayoutProcessing
            }
            AdyenplatformWebhookStatus::Failed => EventType::PayoutFailure,
            AdyenplatformWebhookStatus::Returned => EventType::PayoutReversed,
        },
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenTransferErrorResponse {
    pub error_code: String,
    #[serde(rename = "type")]
    pub error_type: String,
    pub status: u16,
    pub title: String,
    pub detail: Option<String>,
    pub request_id: Option<String>,
    pub invalid_fields: Option<Vec<AdyenInvalidField>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdyenInvalidField {
    pub name: Option<String>,
    pub value: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Metadata {
    source_balance_account: Option<Secret<String>>,
    entity_type: Option<String>,
    payout_type: Option<String>,
    card_holder_name: Option<Secret<String>>,
}
fn missing(field_name: &'static str) -> error_stack::Report<IntegrationError> {
    IntegrationError::MissingRequiredField {
        field_name,
        context: Default::default(),
    }
    .into()
}
fn required<V>(
    v: Option<V>,
    field: &'static str,
) -> Result<V, error_stack::Report<IntegrationError>> {
    v.ok_or_else(|| missing(field))
}
fn invalid(field_name: &'static str) -> error_stack::Report<IntegrationError> {
    IntegrationError::InvalidDataFormat {
        field_name,
        context: Default::default(),
    }
    .into()
}
fn split_name(
    name: Secret<String>,
) -> Result<(Secret<String>, Secret<String>), error_stack::Report<IntegrationError>> {
    let name = name.expose();
    let mut words = name.split_whitespace();
    let first = required(words.next(), "card_holder_name")?;
    let last = words.collect::<Vec<_>>().join(" ");
    if last.is_empty() {
        return Err(missing("card_holder_name.last_name"));
    }
    Ok((first.to_owned().into(), last.into()))
}
impl<T: PaymentMethodDataTypes>
    TryFrom<
        &RouterDataV2<
            PayoutTransfer,
            PayoutFlowData,
            PayoutTransferRequest<T>,
            PayoutTransferResponse,
        >,
    > for AdyenTransferRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        data: &RouterDataV2<
            PayoutTransfer,
            PayoutFlowData,
            PayoutTransferRequest<T>,
            PayoutTransferResponse,
        >,
    ) -> Result<Self, Self::Error> {
        let req = &data.request;
        let metadata: Metadata = req
            .payout_connector_metadata
            .as_ref()
            .map(|m| serde_json::from_value(m.clone().expose()))
            .transpose()
            .map_err(|_| invalid("payout_connector_metadata"))?
            .unwrap_or_default();
        let configured_source = match &data.connector_config {
            ConnectorSpecificConfig::Adyenplatform {
                source_balance_account,
                ..
            } => source_balance_account.clone(),
            _ => {
                return Err(IntegrationError::FailedToObtainAuthType {
                    context: Default::default(),
                }
                .into())
            }
        };
        let balance_account_id = required(
            configured_source.or(metadata.source_balance_account),
            "source_balance_account",
        )?;
        let billing = req.get_billing()?;
        let address = req.get_billing_address()?;
        let adyen_address = AdyenAddress {
            line1: required(address.line1.clone(), "billing.address.line1")?,
            line2: required(address.line2.clone(), "billing.address.line2")?,
            postal_code: address.zip.clone(),
            state_or_province: address.state.clone(),
            city: required(address.city.clone(), "billing.address.city")?.expose(),
            country: required(address.country, "billing.address.country")?,
        };
        let entity_type = match metadata.entity_type.as_deref().unwrap_or("Individual") {
            "Individual" | "Personal" | "NaturalPerson" => EntityType::Individual,
            "Company" | "Business" => EntityType::Organization,
            "NonProfit" | "PublicSector" => EntityType::Unknown,
            _ => return Err(invalid("payout_connector_metadata.entity_type")),
        };
        let mut holder = AdyenAccountHolder {
            address: Some(adyen_address),
            first_name: None,
            last_name: None,
            full_name: None,
            email: billing.email.clone(),
            customer_id: Some(required(
                req.customer
                    .as_ref()
                    .and_then(|c| c.connector_customer_id.clone()),
                "customer.connector_customer_id",
            )?),
            entity_type: Some(entity_type),
        };
        let (category, counterparty, priority) = if let Some(stored) =
            &req.connector_payout_method_id
        {
            let is_card = matches!(req.payout_method_data, Some(PayoutMethodData::Card(_)))
                || (req.payout_method_data.is_none()
                    && metadata.payout_type.as_deref() == Some("card"));
            if !is_card {
                return Err(invalid("payout_connector_metadata.payout_type"));
            }
            let names = address
                .first_name
                .clone()
                .zip(address.last_name.clone())
                .filter(|(a, b)| {
                    !a.clone().expose().trim().is_empty() && !b.clone().expose().trim().is_empty()
                });
            let (first, last) = match names {
                Some((a, b)) => (
                    a.expose().trim().to_owned().into(),
                    b.expose().trim().to_owned().into(),
                ),
                None => {
                    let raw_name = req.payout_method_data.as_ref().and_then(|m| match m {
                        PayoutMethodData::Card(c) => c.card_holder_name.clone(),
                        _ => None,
                    });
                    split_name(required(
                        raw_name.or(metadata.card_holder_name),
                        "card_holder_name",
                    )?)?
                }
            };
            holder.full_name =
                Some(format!("{} {}", first.clone().expose(), last.clone().expose()).into());
            holder.first_name = Some(first);
            holder.last_name = Some(last);
            (
                AdyenPayoutMethod::Card,
                AdyenPayoutMethodDetails::Card(AdyenCardDetails {
                    card_holder: holder,
                    card_identification: AdyenCardIdentification::Stored(
                        AdyenStoredCardIdentification {
                            stored_payment_method_id: stored.clone().into(),
                        },
                    ),
                }),
                None,
            )
        } else {
            match required(req.payout_method_data.as_ref(), "payout_method_data")? {
                PayoutMethodData::Card(card) => {
                    let (first, last) =
                        split_name(required(card.card_holder_name.clone(), "card_holder_name")?)?;
                    holder.first_name = Some(first);
                    holder.last_name = Some(last);
                    let year = card.expiry_year.clone().expose();
                    let year = if year.len() == 2 {
                        format!("20{year}")
                    } else {
                        year
                    };
                    (
                        AdyenPayoutMethod::Card,
                        AdyenPayoutMethodDetails::Card(AdyenCardDetails {
                            card_holder: holder,
                            card_identification: AdyenCardIdentification::Card(
                                AdyenRawCardIdentification {
                                    card_number: T::try_card_number(
                                        &card.card_number,
                                        "adyenplatform",
                                    )?,
                                    expiry_month: card.expiry_month.clone(),
                                    expiry_year: year.into(),
                                    issue_number: None,
                                    start_month: None,
                                    start_year: None,
                                },
                            ),
                        }),
                        None,
                    )
                }
                PayoutMethodData::Bank(Bank::Sepa(bank)) => {
                    holder.full_name = Some(required(
                        address.get_optional_full_name(),
                        "billing.address.full_name",
                    )?);
                    let priority = required(req.priority, "priority")?;
                    let priority = match priority {
                        common_enums::PayoutPriority::Instant => AdyenPayoutPriority::Instant,
                        common_enums::PayoutPriority::Fast => AdyenPayoutPriority::Fast,
                        common_enums::PayoutPriority::Regular => AdyenPayoutPriority::Regular,
                        common_enums::PayoutPriority::Wire => AdyenPayoutPriority::Wire,
                        common_enums::PayoutPriority::CrossBorder => {
                            AdyenPayoutPriority::CrossBorder
                        }
                        common_enums::PayoutPriority::Internal => AdyenPayoutPriority::Internal,
                    };
                    (
                        AdyenPayoutMethod::Bank,
                        AdyenPayoutMethodDetails::BankAccount(AdyenBankAccountDetails {
                            account_holder: holder,
                            account_identification: AdyenBankAccountIdentification {
                                bank_type: "iban".into(),
                                account_details: AdyenBankAccountIdentificationDetails::Sepa(
                                    SepaDetails {
                                        iban: bank.iban.clone(),
                                    },
                                ),
                            },
                        }),
                        Some(priority),
                    )
                }
                _ => {
                    return Err(IntegrationError::connector_flow_not_supported(
                        "adyenplatform",
                        "payout_method",
                        Default::default(),
                    )
                    .into())
                }
            }
        };
        Ok(Self {
            amount: Amount {
                currency: req.destination_currency,
                value: req.amount,
            },
            balance_account_id,
            category,
            counterparty,
            priority,
            reference: data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            reference_for_beneficiary: data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            description: data.resource_common_data.description.clone(),
        })
    }
}
impl AdyenTransferResponse {
    pub fn into_result(
        self,
        merchant_payout_id: Option<String>,
        http_code: u16,
    ) -> Result<PayoutTransferResponse, domain_types::router_data::ErrorResponse> {
        use common_enums::PayoutStatus;
        let status = match self.status {
            AdyenTransferStatus::Authorised | AdyenTransferStatus::Booked => {
                PayoutStatus::Initiated
            }
            AdyenTransferStatus::Pending | AdyenTransferStatus::Received => PayoutStatus::Pending,
            AdyenTransferStatus::Returned => PayoutStatus::Reversed,
            AdyenTransferStatus::Error
            | AdyenTransferStatus::Refused
            | AdyenTransferStatus::Failed => PayoutStatus::Failure,
        };
        if status == PayoutStatus::Failure {
            let code = self.status.to_string();
            let message = self
                .reason
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| code.clone());
            Err(domain_types::router_data::ErrorResponse {
                code,
                message,
                connector_transaction_id: Some(self.id),
                status_code: http_code,
                ..Default::default()
            })
        } else {
            Ok(PayoutTransferResponse {
                merchant_payout_id,
                connector_payout_id: Some(self.id),
                payout_status: status,
                status_code: http_code,
            })
        }
    }
}

// Bridge adapters for the standard UCS connector macros.
impl<T: PaymentMethodDataTypes + std::fmt::Debug + Send + Sync + 'static + Serialize>
    TryFrom<
        crate::payout_connectors::adyenplatform::AdyenplatformPayoutsRouterData<
            RouterDataV2<
                PayoutTransfer,
                PayoutFlowData,
                PayoutTransferRequest<T>,
                PayoutTransferResponse,
            >,
            T,
        >,
    > for AdyenTransferRequest
{
    type Error = error_stack::Report<IntegrationError>;
    fn try_from(
        item: crate::payout_connectors::adyenplatform::AdyenplatformPayoutsRouterData<
            RouterDataV2<
                PayoutTransfer,
                PayoutFlowData,
                PayoutTransferRequest<T>,
                PayoutTransferResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&item.router_data)
    }
}
impl<T: PaymentMethodDataTypes>
    TryFrom<crate::types::ResponseRouterData<AdyenTransferResponse, Self>>
    for RouterDataV2<
        PayoutTransfer,
        PayoutFlowData,
        PayoutTransferRequest<T>,
        PayoutTransferResponse,
    >
{
    type Error = error_stack::Report<domain_types::errors::ConnectorError>;
    fn try_from(
        item: crate::types::ResponseRouterData<AdyenTransferResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let response = item.response.into_result(
            item.router_data.request.merchant_payout_id.clone(),
            item.http_code,
        );
        Ok(Self {
            response,
            ..item.router_data
        })
    }
}
