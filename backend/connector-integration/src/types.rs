use std::fmt::Debug;

use domain_types::{connector_types::ConnectorEnum, payment_method_data::PaymentMethodDataTypes};
use interfaces::connector_types::BoxedConnector;

use crate::connectors::{
    Aci, Adyen, Authorizedotnet, Bluecode, Braintree, Cashfree, Cashtocode, Checkout, Cryptopay,
    Cybersource, Dlocal, Elavon, Fiserv, Fiuu, Helcim, IciciUpi, Mifinity, Nexinets, Noon, Novalnet, Paytm,
    Payu, Phonepe, Placetopay, Rapyd, Razorpay, RazorpayV2, Stripe, Trustpay, Volt, Xendit,
};

#[derive(Clone)]
pub struct ConnectorData<T: PaymentMethodDataTypes + Debug + Default + Send + Sync + 'static> {
    pub connector: BoxedConnector<T>,
    pub connector_name: ConnectorEnum,
}

impl<T: PaymentMethodDataTypes + Debug + Default + Send + Sync + 'static + serde::Serialize>
    ConnectorData<T>
{
    pub fn get_connector_by_name(connector_name: &ConnectorEnum) -> Self {
        let connector = Self::convert_connector(*connector_name);
        Self {
            connector,
            connector_name: *connector_name,
        }
    }

    fn convert_connector(connector_name: ConnectorEnum) -> BoxedConnector<T> {
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
            ConnectorEnum::Paytm => Box::new(Paytm::new()),
            ConnectorEnum::Cashtocode => Box::new(Cashtocode::new()),
            ConnectorEnum::Novalnet => Box::new(Novalnet::new()),
            ConnectorEnum::Nexinets => Box::new(Nexinets::new()),
            ConnectorEnum::Noon => Box::new(Noon::new()),
            ConnectorEnum::Volt => Box::new(Volt::new()),
            ConnectorEnum::Braintree => Box::new(Braintree::new()),
            ConnectorEnum::Bluecode => Box::new(Bluecode::new()),
            ConnectorEnum::Cryptopay => Box::new(Cryptopay::new()),
            ConnectorEnum::Helcim => Box::new(Helcim::new()),
            ConnectorEnum::Dlocal => Box::new(Dlocal::new()),
            ConnectorEnum::Placetopay => Box::new(Placetopay::new()),
            ConnectorEnum::Rapyd => Box::new(Rapyd::new()),
            ConnectorEnum::Aci => Box::new(Aci::new()),
            ConnectorEnum::Trustpay => Box::new(Trustpay::new()),
            ConnectorEnum::Stripe => Box::new(Stripe::new()),
            ConnectorEnum::Cybersource => Box::new(Cybersource::new()),
        }
    }
}

pub struct ResponseRouterData<Response, RouterData> {
    pub response: Response,
    pub router_data: RouterData,
    pub http_code: u16,
}
