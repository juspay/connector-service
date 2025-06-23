use common_enums::RegulatedName;
use common_enums::{CardNetwork, CountryAlpha2};
use utoipa::ToSchema;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CoBadgedCardData {
    pub co_badged_card_networks: Vec<CardNetwork>,
    pub issuer_country_code: CountryAlpha2,
    pub is_regulated: bool,
    pub regulated_name: Option<RegulatedName>,
}

#[derive(
    Debug,
    serde::Deserialize,
    serde::Serialize,
    Clone,
    ToSchema,
    strum::EnumString,
    strum::Display,
    Eq,
    PartialEq,
)]
#[serde(rename_all = "snake_case")]
pub enum CardType {
    Credit,
    Debit,
}
