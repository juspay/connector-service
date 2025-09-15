pub mod transformers;
pub mod constants;

use common_utils::{errors::CustomResult, types::StringMinorUnit};
use domain_types::{
    connector_flow::{Authorize, PSync},
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
    },
    payment_method_data::PaymentMethodDataTypes,
    router_data_v2::RouterDataV2,
    types::Connectors,
};
use hyperswitch_masking::Maskable;
use interfaces::{
    api::ConnectorCommon,
    connector_integration_v2::ConnectorIntegrationV2,
};
use serde::Serialize;
use transformers::{
    CcavenueV2PaymentsRequest, CcavenueV2PaymentsResponse,
    CcavenueV2PaymentsSyncRequest, CcavenueV2PaymentsSyncResponse,
};

use super::macros;

// impl<T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize>
//     interfaces::connector_types::ConnectorServiceTrait<T> for CcavenueV2<T>
// {
// }







// Set up connector using macros with all framework integrations
macros::create_all_prerequisites!(
    connector_name: CcavenueV2,
    generic_type: T,
    api: [
        (
            flow: Authorize,
            request_body: CcavenueV2PaymentsRequest,
            response_body: CcavenueV2PaymentsResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
        (
            flow: PSync,
            request_body: CcavenueV2PaymentsSyncRequest,
            response_body: CcavenueV2PaymentsSyncResponse,
            router_data: RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        )
    ],
    amount_converters: [
        amount_converter: StringMinorUnit
    ],
    member_functions: {
        pub fn build_headers<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
        ) -> CustomResult<Vec<(String, Maskable<String>)>, domain_types::errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(vec![
                ("Content-Type".to_string(), "application/json".into()),
                ("Accept".to_string(), "application/json".into()),
            ])
        }

        pub fn get_base_url<F, FCD, Req, Res>(
            &self,
            _req: &RouterDataV2<F, FCD, Req, Res>,
            connectors: &Connectors,
        ) -> CustomResult<String, domain_types::errors::ConnectorError>
        where
            Self: ConnectorIntegrationV2<F, FCD, Req, Res>,
        {
            Ok(connectors.ccavenuev2.base_url.clone())
        }
    }
);

// Custom implementation of ConnectorCommon trait
impl<T> ConnectorCommon for CcavenueV2<T>
where
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
{
    fn id(&self) -> &'static str {
        "ccavenuev2"
    }

    fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
        common_enums::CurrencyUnit::Minor
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        &connectors.ccavenuev2.base_url
    }
}

