use std::marker::PhantomData;
use common_utils::Maskable;

use common_utils::{errors::CustomResult, ext_traits::BytesExt};
use domain_types::{errors, router_data_v2::RouterDataV2};
use error_stack::ResultExt;
use crate::types;

pub trait FlowTypes {
    type Flow;
    type FlowCommonData;
    type Request;
    type Response;
}

impl<F, FCD, Req, Resp> FlowTypes for RouterDataV2<F, FCD, Req, Resp> {
    type Flow = F;
    type FlowCommonData = FCD;
    type Request = Req;
    type Response = Resp;
}

impl<F, FCD, Req, Resp> FlowTypes for &RouterDataV2<F, FCD, Req, Resp> {
    type Flow = F;
    type FlowCommonData = FCD;
    type Request = Req;
    type Response = Resp;
}

pub trait GetFormData {
    fn get_form_data(&self) -> reqwest::multipart::Form;
}

pub struct NoRequestBody;
pub struct NoRequestBodyTemplating;

impl<F, FCD, Req, Resp> TryFrom<RouterDataV2<F, FCD, Req, Resp>> for NoRequestBody {
    type Error = error_stack::Report<errors::ConnectorError>;
    
    fn try_from(_value: RouterDataV2<F, FCD, Req, Resp>) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

type RouterDataType<T> = RouterDataV2<
    <T as FlowTypes>::Flow,
    <T as FlowTypes>::FlowCommonData,
    <T as FlowTypes>::Request,
    <T as FlowTypes>::Response,
>;

type ResponseRouterDataType<T, R> = types::ResponseRouterData<
    R,
    RouterDataV2<
        <T as FlowTypes>::Flow,
        <T as FlowTypes>::FlowCommonData,
        <T as FlowTypes>::Request,
        <T as FlowTypes>::Response,
    >,
>;

pub trait BridgeRequestResponse: Send + Sync {
    type RequestBody;
    type ResponseBody;
    type ConnectorInputData: FlowTypes;
    
    fn request_body(
        &self,
        rd: Self::ConnectorInputData,
    ) -> CustomResult<Self::RequestBody, errors::ConnectorError>
    where
        Self::RequestBody:
            TryFrom<Self::ConnectorInputData, Error = error_stack::Report<errors::ConnectorError>>,
    {
        Self::RequestBody::try_from(rd)
    }
    
    fn response(
        bytes: bytes::Bytes,
    ) -> CustomResult<Self::ResponseBody, errors::ConnectorError>
    where
        Self::ResponseBody: for<'a> serde::Deserialize<'a>,
    {
        if bytes.is_empty() {
            serde_json::from_str("{}")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)
        } else {
            bytes
                .parse_struct(std::any::type_name::<Self::ResponseBody>())
        }
    }
    
    fn router_data(
        response: ResponseRouterDataType<Self::ConnectorInputData, Self::ResponseBody>,
    ) -> CustomResult<RouterDataType<Self::ConnectorInputData>, errors::ConnectorError>
    where
        RouterDataType<Self::ConnectorInputData>: TryFrom<
            ResponseRouterDataType<Self::ConnectorInputData, Self::ResponseBody>,
            Error = error_stack::Report<errors::ConnectorError>,
        >,
    {
        RouterDataType::<Self::ConnectorInputData>::try_from(response)
    }
}

#[derive(Clone)]
pub struct Bridge<Q, S, T>(pub PhantomData<(Q, S, T)>);

#[macro_export]
macro_rules! expand_fn_get_request_body {
    ($connector: ident, $curl_res: ty, $flow: ident, $resource_common_data: ty, $request: ident, $response: ty) => {
        paste::paste! {
            fn get_request_body(
                &self,
                _req: &RouterDataV2<$flow, $resource_common_data, $request, $response>,
            ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError>
            {
                // always return None
                Ok(None)
            }
        }
    };
    (
        $connector: ident,
        $curl_req: ty,
        FormData,
        $curl_res: ty,
        $flow: ident,
        $resource_common_data: ty,
        $request: ty,
        $response: ty
    ) => {
        paste::paste! {
            fn get_request_body(
                &self,
                req: &RouterDataV2<$flow, $resource_common_data, $request, $response>,
            ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError>
            {
                let connector_req = $curl_req::try_from(req)?;
                Ok(Some(common_utils::request::RequestContent::FormUrlEncoded(Box::new(connector_req))))
            }
        }
    };
    (
        $connector: ident,
        $curl_req: ty,
        Json,
        $curl_res: ty,
        $flow: ident,
        $resource_common_data: ty,
        $request: ty,
        $response: ty
    ) => {
        paste::paste! {
            fn get_request_body(
                &self,
                req: &RouterDataV2<$flow, $resource_common_data, $request, $response>,
            ) -> CustomResult<Option<common_utils::request::RequestContent>, errors::ConnectorError>
            {
                let connector_req = $curl_req::try_from(req)?;
                Ok(Some(common_utils::request::RequestContent::Json(Box::new(connector_req))))
            }
        }
    };
}

#[macro_export]
macro_rules! expand_fn_handle_response {
    ($connector: ident, $curl_req: ty, $curl_res: ty, $flow: ident, $resource_common_data: ty, $request: ident, $response: ty) => {
        paste::paste! {
            fn handle_response_v2(
                &self,
                data: &RouterDataV2<$flow, $resource_common_data, $request, $response>,
                res: common_utils::types::Response,
                event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
            ) -> CustomResult<RouterDataV2<$flow, $resource_common_data, $request, $response>, errors::ConnectorError>
            {
                let response: $curl_res = res
                    .response
                    .parse_struct(stringify!($curl_res))
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                if let Some(i) = event_builder {
                    i.set_response_body(&response);
                }
                RouterDataV2::foreign_try_from((response, data.clone(), res.status_code))
                    .change_context(errors::ConnectorError::ResponseHandlingFailed)
            }
        }
    };
}

#[macro_export]
macro_rules! expand_fn_get_url {
    ($connector: ident, $flow: ident, $resource_common_data: ty, $request: ident, $response: ty, $url: expr) => {
        paste::paste! {
            fn get_url(
                &self,
                _req: &RouterDataV2<$flow, $resource_common_data, $request, $response>,
                _connectors: &domain_types::types::Connectors,
            ) -> CustomResult<String, errors::ConnectorError> {
                Ok($url.to_string())
            }
        }
    };
}

#[macro_export]
macro_rules! expand_fn_get_headers {
    ($connector: ident, $flow: ident, $resource_common_data: ty, $request: ident, $response: ty) => {
        paste::paste! {
            fn get_headers(
                &self,
                req: &RouterDataV2<$flow, $resource_common_data, $request, $response>,
            ) -> CustomResult<Vec<(String, common_utils::Maskable<String>)>, errors::ConnectorError>
            {
                self.build_headers(req)
            }
        }
    };
}

#[macro_export]
macro_rules! expand_fn_get_http_method {
    ($connector: ident, $flow: ident, $resource_common_data: ty, $request: ident, $response: ty, $method: expr) => {
        paste::paste! {
            fn get_http_method(&self) -> common_utils::request::Method {
                $method
            }
        }
    };
}

#[macro_export]
macro_rules! expand_fn_get_error_response {
    ($connector: ident, $flow: ident, $resource_common_data: ty, $request: ident, $response: ty) => {
        paste::paste! {
            fn get_error_response_v2(
                &self,
                res: common_utils::types::Response,
                event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
            ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
                Self::build_error_response(res, event_builder)
            }
        }
    };
}

#[macro_export]
macro_rules! expand_fn_get_5xx_error_response {
    ($connector: ident, $flow: ident, $resource_common_data: ty, $request: ident, $response: ty) => {
        paste::paste! {
            fn get_5xx_error_response(
                &self,
                res: common_utils::types::Response,
                event_builder: Option<&mut interfaces::events::connector_api_logs::ConnectorEvent>,
            ) -> CustomResult<domain_types::router_data::ErrorResponse, errors::ConnectorError> {
                Self::build_error_response(res, event_builder)
            }
        }
    };
}

#[macro_export]
macro_rules! create_all_prerequisites {
    (
        connector_name: $connector: ident,
        generic_type: $generic_type: ident,
        api: [
            $(
                (
                    flow: $flow: ident,
                    request_body: $request_body: ty,
                    response_body: $response_body: ty,
                    router_data: $router_data: ty,
                )
            ),* $(,)?
        ],
        amount_converters: [
            $(
                amount_converter: $amount_converter: ty
            ),* $(,)?
        ],
        member_functions: {
            $($member_function: item)*
        } $(,)?
    ) => {
        paste::paste! {
            $(
                impl<$generic_type> interfaces::connector_integration_v2::ConnectorIntegrationV2<
                    $flow,
                    domain_types::connector_types::PaymentFlowData,
                    <$router_data as domain_types::router_data_v2::RouterDataV2<
                        $flow,
                        domain_types::connector_types::PaymentFlowData,
                        _, _
                    >>::Request,
                    <$router_data as domain_types::router_data_v2::RouterDataV2<
                        $flow,
                        domain_types::connector_types::PaymentFlowData,
                        _, _
                    >>::Response,
                > for $connector<$generic_type> {
                    expand_fn_get_http_method!($connector, $flow, domain_types::connector_types::PaymentFlowData, _, _, common_utils::request::Method::Post);
                    expand_fn_get_headers!($connector, $flow, domain_types::connector_types::PaymentFlowData, _, _);
                    expand_fn_get_url!($connector, $flow, domain_types::connector_types::PaymentFlowData, _, _, "");
                    expand_fn_get_request_body!($connector, $request_body, Json, $response_body, $flow, domain_types::connector_types::PaymentFlowData, _, _);
                    expand_fn_handle_response!($connector, $request_body, $response_body, $flow, domain_types::connector_types::PaymentFlowData, _, _);
                    expand_fn_get_error_response!($connector, $flow, domain_types::connector_types::PaymentFlowData, _, _);
                    expand_fn_get_5xx_error_response!($connector, $flow, domain_types::connector_types::PaymentFlowData, _, _);
                }
            )*
        }
    };
}

#[macro_export]
macro_rules! create_amount_converter_wrapper {
    (connector_name: $connector: ident, amount_type: $amount_type: ty) => {
        paste::paste! {
            impl<$generic_type> $connector<$generic_type> {
                pub fn convert_amount(
                    &self,
                    amount: i64,
                    currency: common_enums::Currency,
                ) -> CustomResult<f64, errors::ConnectorError> {
                    let converter = $amount_type::new();
                    converter.convert(amount, currency)
                        .change_context(errors::ConnectorError::AmountConversionFailed)
                }
            }
        }
    };
}

pub(crate) use expand_fn_get_request_body;
pub(crate) use expand_fn_handle_response;
pub(crate) use expand_fn_get_url;
pub(crate) use expand_fn_get_headers;
pub(crate) use expand_fn_get_http_method;
pub(crate) use expand_fn_get_error_response;
pub(crate) use expand_fn_get_5xx_error_response;
pub(crate) use create_all_prerequisites;
pub(crate) use create_amount_converter_wrapper;