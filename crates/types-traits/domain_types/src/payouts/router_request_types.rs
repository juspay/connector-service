use common_enums::Currency;
use common_utils::MinorUnit;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PayoutCreateIntegrityObject {
    pub amount: MinorUnit,
    pub currency: Currency,
}
