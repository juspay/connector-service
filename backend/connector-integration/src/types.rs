use domain_types::connector_types::ConnectorEnum;
use interfaces::connector_types::BoxedConnector;

use crate::connectors::{
    Adyen, Authorizedotnet, Cashfree, Cashtocode, Checkout, Elavon, Fiserv, Fiuu, Mifinity, Payu,
    Phonepe, Razorpay, RazorpayV2, Xendit,
};

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
            ConnectorEnum::RazorpayV2 => Box::new(RazorpayV2::new()),
            ConnectorEnum::Fiserv => Box::new(Fiserv::new()),
            ConnectorEnum::Elavon => Box::new(Elavon::new()),
            ConnectorEnum::Xendit => Box::new(Xendit::new()),
            ConnectorEnum::Checkout => Box::new(Checkout::new()),
            ConnectorEnum::Authorizedotnet => Box::new(Authorizedotnet::new()),
            ConnectorEnum::Mifinity => Box::new(Mifinity::new()),
            ConnectorEnum::Phonepe => Box::new(Phonepe::new()),
            ConnectorEnum::Cashfree => Box::new(Cashfree::new()),
            ConnectorEnum::Fiuu => Box::new(Fiuu::new()),
            ConnectorEnum::Payu => Box::new(Payu::new()),
            ConnectorEnum::Cashtocode => Box::new(Cashtocode::new()),
        }
    }
}

pub struct ResponseRouterData<Response, RouterData> {
    pub response: Response,
    pub router_data: RouterData,
    pub http_code: u16,
}
