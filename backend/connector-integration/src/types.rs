use domain_types::connector_types::{BoxedConnector, ConnectorEnum};

use crate::connectors::{Adyen, Paytm, Payu, PhonePe, Razorpay};

#[derive(Clone)]
pub struct ConnectorData {
    pub connector: BoxedConnector,
    pub connector_name: ConnectorEnum,
}

impl ConnectorData {
    pub fn get_connector_by_name(connector_name: &ConnectorEnum) -> Self {
        let connector = Self::convert_connector(connector_name.clone());
        Self {
            connector,
            connector_name: connector_name.clone(),
        }
    }

    fn convert_connector(connector_name: ConnectorEnum) -> BoxedConnector {
        match connector_name {
            ConnectorEnum::Adyen => Box::new(Adyen::new()),
            ConnectorEnum::Razorpay => Box::new(Razorpay::new()),
            ConnectorEnum::Payu => Box::new(Payu::new()),
            ConnectorEnum::PhonePe => Box::new(PhonePe::new()),
            ConnectorEnum::Paytm => Box::new(Paytm::new()), // Assuming Paytm is similar to Payu
        }
    }
}

pub struct ResponseRouterData<Response, RouterData> {
    pub response: Response,
    pub router_data: RouterData,
    pub http_code: u16,
}
