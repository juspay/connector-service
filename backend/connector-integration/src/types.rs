use domain_types::connector_types::ConnectorEnum;
use interfaces::connector_types::BoxedConnector;

use crate::connectors::{Adyen, Authorizedotnet, Checkout, Elavon, Fiserv, Fiuu, Razorpay, Xendit};

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
            ConnectorEnum::Fiserv => Box::new(Fiserv::new()),
            ConnectorEnum::Elavon => Box::new(Elavon::new()),
            ConnectorEnum::Xendit => Box::new(Xendit::new()),
            ConnectorEnum::Checkout => Box::new(Checkout::new()),
            ConnectorEnum::Authorizedotnet => Box::new(Authorizedotnet::new()),
            ConnectorEnum::Fiuu => Box::new(Fiuu::new()),
        }
    }
}

pub struct ResponseRouterData<Response, RouterData> {
    pub response: Response,
    pub router_data: RouterData,
    pub http_code: u16,
}
