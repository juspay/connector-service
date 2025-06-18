use hyperswitch_common_enums::{CardNetwork, CountryAlpha2};


#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CoBadgedCardData {
    pub co_badged_card_networks: Vec<CardNetwork>,
    pub issuer_country_code: CountryAlpha2,
    pub is_regulated: bool,
    pub regulated_name: Option<RegulatedName>,
}