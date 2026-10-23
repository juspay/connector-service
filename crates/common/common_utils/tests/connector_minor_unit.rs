#![allow(clippy::unwrap_used)]

use common_enums::Currency;
use ucs_common_utils::{
    AmountConvertor, ConnectorMinorUnit, ConnectorMinorUnitForConnector, MinorUnit,
    MinorUnitForConnector,
};

#[test]
fn conversion_preserves_minor_units_for_each_currency_scale() {
    for currency in [Currency::JPY, Currency::USD, Currency::BHD, Currency::CLF] {
        for value in [i64::MIN, -1099, 0, 1099, 9_007_199_254_740_993, i64::MAX] {
            let connector_amount = ConnectorMinorUnitForConnector
                .convert(MinorUnit::new(value), currency)
                .unwrap();

            assert_eq!(connector_amount.get_amount_as_i64(), value);
            assert_eq!(
                ConnectorMinorUnitForConnector
                    .convert_back(connector_amount, currency)
                    .unwrap(),
                MinorUnit::new(value),
            );
        }
    }
}

#[test]
fn json_preserves_the_integer_wire_representation() {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct ConnectorPayload {
        amount: ConnectorMinorUnit,
    }

    for value in [i64::MIN, -1099, 0, 1099, 9_007_199_254_740_993, i64::MAX] {
        let amount = ConnectorMinorUnitForConnector
            .convert(MinorUnit::new(value), Currency::USD)
            .unwrap();
        let wire = format!("{{\"amount\":{value}}}");

        assert_eq!(
            serde_json::to_string(&ConnectorPayload { amount }).unwrap(),
            wire,
        );
        let decoded: ConnectorPayload = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded.amount, amount);
        assert_eq!(decoded.amount.to_string(), value.to_string());
    }
}

#[test]
fn json_rejects_non_integer_and_out_of_range_amounts() {
    for wire in [
        "\"1099\"",
        "10.99",
        "null",
        "9223372036854775808",
        "-9223372036854775809",
    ] {
        assert!(serde_json::from_str::<ConnectorMinorUnit>(wire).is_err());
    }
}

#[test]
fn zero_connector_amount_is_an_integer_zero() {
    let zero = ConnectorMinorUnit::zero();

    assert_eq!(zero.get_amount_as_i64(), 0);
    assert_eq!(serde_json::to_string(&zero).unwrap(), "0");
}

#[test]
fn legacy_converter_still_returns_domain_minor_units() {
    let amount: MinorUnit = MinorUnitForConnector
        .convert(MinorUnit::new(1099), Currency::USD)
        .unwrap();

    assert_eq!(amount, MinorUnit::new(1099));
}
