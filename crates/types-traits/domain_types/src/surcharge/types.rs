use crate::errors::{IntegrationError, IntegrationErrorContext};
use crate::surcharge::surcharge_types::{
    SurchargeCalculateRequest, SurchargeFlowData, SurchargeStrategy,
};
use crate::types::Connectors;
use crate::utils::{extract_merchant_id_from_metadata, ForeignTryFrom};
use common_utils::metadata::MaskedMetadata;
use common_utils::types::MinorUnit;
use error_stack::ResultExt;
impl
    ForeignTryFrom<(
        grpc_api_types::surcharge::SurchargeServiceCalculateRequest,
        Connectors,
        &MaskedMetadata,
    )> for SurchargeFlowData
{
    type Error = IntegrationError;

    fn foreign_try_from(
        (value, connectors, metadata): (
            grpc_api_types::surcharge::SurchargeServiceCalculateRequest,
            Connectors,
            &MaskedMetadata,
        ),
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let merchant_id = extract_merchant_id_from_metadata(metadata)?;

        Ok(Self {
            merchant_id,
            connector_request_reference_id: value.merchant_surcharge_id.clone().unwrap_or_default(),
            connectors,
            raw_connector_response: None,
            raw_connector_request: None,
            connector_response_headers: None,
        })
    }
}

impl ForeignTryFrom<grpc_api_types::surcharge::SurchargeServiceCalculateRequest>
    for SurchargeCalculateRequest
{
    type Error = IntegrationError;

    fn foreign_try_from(
        value: grpc_api_types::surcharge::SurchargeServiceCalculateRequest,
    ) -> Result<Self, error_stack::Report<Self::Error>> {
        let amount = value.amount.ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "amount",
                context: IntegrationErrorContext {
                    additional_context: Some(
                        "Amount is required for surcharge calculation".to_owned()
                    ),
                    ..Default::default()
                },
            })
        })?;

        let currency = {
            let curr = grpc_api_types::payments::Currency::try_from(amount.currency)
                .change_context(IntegrationError::InvalidDataFormat {
                    field_name: "currency",
                    context: IntegrationErrorContext {
                        additional_context: Some(
                            "Invalid currency in surcharge request".to_owned(),
                        ),
                        ..Default::default()
                    },
                })?;
            common_enums::Currency::foreign_try_from(curr)?
        };

        let country = value
            .country
            .map(|country| {
                let country = grpc_api_types::payments::CountryAlpha2::try_from(country)
                    .change_context(IntegrationError::InvalidDataFormat {
                        field_name: "country",
                        context: IntegrationErrorContext {
                            additional_context: Some("Invalid country code".to_owned()),
                            ..Default::default()
                        },
                    })?;
                common_enums::CountryAlpha2::foreign_try_from(country)
            })
            .transpose()?;

        let surcharge_strategy = value.surcharge_strategy.map(|surcharge_strategy| {
            let grpc_strategy =
                grpc_api_types::surcharge::SurchargeStrategy::try_from(surcharge_strategy)
                    .unwrap_or(grpc_api_types::surcharge::SurchargeStrategy::Unspecified);

            match grpc_strategy {
                grpc_api_types::surcharge::SurchargeStrategy::Apply => SurchargeStrategy::Apply,
                grpc_api_types::surcharge::SurchargeStrategy::Waive => SurchargeStrategy::Waive,
                grpc_api_types::surcharge::SurchargeStrategy::Unspecified => {
                    SurchargeStrategy::Unspecified
                }
            }
        });

        let postal_code = value.postal_code.ok_or_else(|| {
            error_stack::report!(IntegrationError::MissingRequiredField {
                field_name: "postal_code",
                context: IntegrationErrorContext {
                    additional_context: Some(
                        "Postal code is required for surcharge calculation".to_owned()
                    ),
                    ..Default::default()
                },
            })
        })?;

        Ok(Self {
            connector_request_reference_id: value.merchant_surcharge_id,
            amount: MinorUnit::new(amount.minor_amount),
            currency,
            previous_connector_surcharge_id: value.previous_connector_surcharge_id,
            surcharge_strategy,
            card_bin: value.card_bin,
            postal_code,
            country,
        })
    }
}
