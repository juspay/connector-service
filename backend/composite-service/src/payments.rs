use connector_integration::types::ConnectorData;
use domain_types::{
    connector_types::{AccessTokenResponseData, ConnectorEnum},
    utils::ForeignTryFrom as _,
};
use grpc_api_types::payments::{
    composite_payment_method_authentication_service_server::CompositePaymentMethodAuthenticationService,
    composite_payment_service_server::CompositePaymentService,
    composite_refund_service_server::CompositeRefundService,
    customer_service_server::CustomerService,
    merchant_authentication_service_server::MerchantAuthenticationService,
    payment_method_authentication_service_server::PaymentMethodAuthenticationService,
    payment_service_server::PaymentService, refund_service_server::RefundService,
    CompositeAuthenticateRequest, CompositeAuthenticateResponse, CompositeAuthorizeRequest,
    CompositeAuthorizeResponse, CompositeCaptureRequest, CompositeCaptureResponse,
    CompositeGetRequest, CompositeGetResponse, CompositePreauthenticateRequest,
    CompositePreauthenticateResponse, CompositeRefundGetRequest, CompositeRefundGetResponse,
    CompositeRefundRequest, CompositeRefundResponse, CompositeVoidRequest, CompositeVoidResponse,
    ConnectorState, CustomerServiceCreateResponse,
    MerchantAuthenticationServiceCreateAccessTokenRequest,
    MerchantAuthenticationServiceCreateAccessTokenResponse, PaymentMethod,
    PaymentMethodAuthenticationServiceAuthenticateRequest,
    PaymentMethodAuthenticationServiceAuthenticateResponse,
    PaymentMethodAuthenticationServicePreAuthenticateRequest,
    PaymentMethodAuthenticationServicePreAuthenticateResponse, PaymentServiceAuthorizeRequest,
    PaymentServiceAuthorizeResponse, PaymentServiceCaptureRequest, PaymentServiceCaptureResponse,
    PaymentServiceGetResponse, PaymentServiceRefundRequest, PaymentServiceVoidRequest,
    PaymentServiceVoidResponse, RefundResponse, RefundServiceGetRequest,
};

use crate::transformers::ForeignFrom;
use crate::utils::connector_from_composite_request_metadata;

/// Trait for abstracting access to common fields needed for access token creation.
pub trait CompositeAccessTokenRequest {
    fn payment_method(&self) -> Option<PaymentMethod>;
    fn state(&self) -> Option<&ConnectorState>;
    fn build_access_token_request(
        &self,
        connector: &ConnectorEnum,
    ) -> MerchantAuthenticationServiceCreateAccessTokenRequest;
}

/// Trait for abstracting pre-authenticate request conversion.
pub trait CompositePreAuthNRequest {
    fn build_pre_authenticate_request(
        &self,
    ) -> PaymentMethodAuthenticationServicePreAuthenticateRequest;

    fn should_do_pre_authenticate(
        &self,
        connector: &ConnectorEnum,
    ) -> Result<bool, Box<tonic::Status>>;
}

impl CompositeAccessTokenRequest for CompositeAuthorizeRequest {
    fn payment_method(&self) -> Option<PaymentMethod> {
        self.payment_method.clone()
    }

    fn state(&self) -> Option<&ConnectorState> {
        self.state.as_ref()
    }

    fn build_access_token_request(
        &self,
        connector: &ConnectorEnum,
    ) -> MerchantAuthenticationServiceCreateAccessTokenRequest {
        MerchantAuthenticationServiceCreateAccessTokenRequest::foreign_from((self, connector))
    }
}

impl CompositeAccessTokenRequest for CompositeGetRequest {
    fn payment_method(&self) -> Option<PaymentMethod> {
        self.payment_method.clone()
    }

    fn state(&self) -> Option<&ConnectorState> {
        self.state.as_ref()
    }

    fn build_access_token_request(
        &self,
        connector: &ConnectorEnum,
    ) -> MerchantAuthenticationServiceCreateAccessTokenRequest {
        MerchantAuthenticationServiceCreateAccessTokenRequest::foreign_from((self, connector))
    }
}

impl CompositeAccessTokenRequest for CompositeRefundRequest {
    fn payment_method(&self) -> Option<PaymentMethod> {
        self.payment_method.clone()
    }

    fn state(&self) -> Option<&ConnectorState> {
        self.state.as_ref()
    }

    fn build_access_token_request(
        &self,
        connector: &ConnectorEnum,
    ) -> MerchantAuthenticationServiceCreateAccessTokenRequest {
        MerchantAuthenticationServiceCreateAccessTokenRequest::foreign_from((self, connector))
    }
}

impl CompositeAccessTokenRequest for CompositeRefundGetRequest {
    fn payment_method(&self) -> Option<PaymentMethod> {
        self.payment_method.clone()
    }

    fn state(&self) -> Option<&ConnectorState> {
        self.state.as_ref()
    }

    fn build_access_token_request(
        &self,
        connector: &ConnectorEnum,
    ) -> MerchantAuthenticationServiceCreateAccessTokenRequest {
        MerchantAuthenticationServiceCreateAccessTokenRequest::foreign_from((self, connector))
    }
}

impl CompositeAccessTokenRequest for CompositeVoidRequest {
    fn payment_method(&self) -> Option<PaymentMethod> {
        self.payment_method.clone()
    }

    fn state(&self) -> Option<&ConnectorState> {
        self.state.as_ref()
    }

    fn build_access_token_request(
        &self,
        connector: &ConnectorEnum,
    ) -> MerchantAuthenticationServiceCreateAccessTokenRequest {
        MerchantAuthenticationServiceCreateAccessTokenRequest::foreign_from((self, connector))
    }
}

impl CompositeAccessTokenRequest for CompositeCaptureRequest {
    fn payment_method(&self) -> Option<PaymentMethod> {
        self.payment_method.clone()
    }

    fn state(&self) -> Option<&ConnectorState> {
        self.state.as_ref()
    }

    fn build_access_token_request(
        &self,
        connector: &ConnectorEnum,
    ) -> MerchantAuthenticationServiceCreateAccessTokenRequest {
        MerchantAuthenticationServiceCreateAccessTokenRequest::foreign_from((self, connector))
    }
}

impl CompositePreAuthNRequest for CompositePreauthenticateRequest {
    fn build_pre_authenticate_request(
        &self,
    ) -> PaymentMethodAuthenticationServicePreAuthenticateRequest {
        PaymentMethodAuthenticationServicePreAuthenticateRequest::foreign_from(self)
    }

    fn should_do_pre_authenticate(
        &self,
        _connector: &ConnectorEnum,
    ) -> Result<bool, Box<tonic::Status>> {
        Ok(true)
    }
}

impl CompositePreAuthNRequest for CompositeAuthenticateRequest {
    fn build_pre_authenticate_request(
        &self,
    ) -> PaymentMethodAuthenticationServicePreAuthenticateRequest {
        PaymentMethodAuthenticationServicePreAuthenticateRequest::foreign_from(self)
    }

    fn should_do_pre_authenticate(
        &self,
        connector: &ConnectorEnum,
    ) -> Result<bool, Box<tonic::Status>> {
        if self.redirection_response.is_none() {
            let connector_data =
                ConnectorData::<domain_types::payment_method_data::DefaultPCIHolder>::get_connector_by_name(connector);

            let auth_type = if self.enrolled_for_3ds {
                common_enums::AuthenticationType::ThreeDs
            } else {
                common_enums::AuthenticationType::NoThreeDs
            };

            let payment_method_data = self
                .payment_method
                .clone()
                .map(domain_types::payment_method_data::PaymentMethodData::foreign_try_from)
                .transpose()
                .map_err(|err| {
                    Box::new(tonic::Status::invalid_argument(format!(
                        "Failed to convert payment method data: {err:?}"
                    )))
                })?;

            Ok(connector_data
                .connector
                .should_do_pre_authenticate_before_authenticate(auth_type, &payment_method_data))
        } else {
            Ok(false)
        }
    }
}

#[derive(Clone)]
pub struct Payments<P, M, C, R, A> {
    payment_service: P,
    merchant_authentication_service: M,
    customer_service: C,
    refund_service: R,
    payment_method_authentication_service: A,
}

impl<P, M, C, R, A> Payments<P, M, C, R, A> {
    pub fn new(
        payment_service: P,
        merchant_authentication_service: M,
        customer_service: C,
        refund_service: R,
        payment_method_authentication_service: A,
    ) -> Self {
        Self {
            payment_service,
            merchant_authentication_service,
            customer_service,
            refund_service,
            payment_method_authentication_service,
        }
    }
}

impl<P, M, C, R, A> Payments<P, M, C, R, A>
where
    P: PaymentService + Clone + Send + Sync + 'static,
    M: MerchantAuthenticationService + Clone + Send + Sync + 'static,
    C: CustomerService + Clone + Send + Sync + 'static,
    R: RefundService + Clone + Send + Sync + 'static,
    A: PaymentMethodAuthenticationService + Clone + Send + Sync + 'static,
{
    async fn create_access_token<Req: CompositeAccessTokenRequest>(
        &self,
        connector: &ConnectorEnum,
        payload: &Req,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<Option<MerchantAuthenticationServiceCreateAccessTokenResponse>, tonic::Status> {
        let should_do_access_token = {
            let payment_method = payload
                .payment_method()
                .map(common_enums::PaymentMethod::foreign_try_from)
                .transpose()
                .map_err(|err| {
                    tonic::Status::invalid_argument(format!(
                        "invalid payment_method in request payload: {err}"
                    ))
                })?;
            let connector_data = ConnectorData::<
                domain_types::payment_method_data::DefaultPCIHolder,
            >::get_connector_by_name(connector);
            connector_data
                .connector
                .should_do_access_token(payment_method)
        };
        let payload_access_token = payload
            .state()
            .and_then(|state| state.access_token.as_ref())
            .and_then(|token| AccessTokenResponseData::foreign_try_from(token).ok());
        let should_create_access_token = should_do_access_token && payload_access_token.is_none();

        let access_token_response = match should_create_access_token {
            true => {
                let access_token_payload = payload.build_access_token_request(connector);
                let mut access_token_request = tonic::Request::new(access_token_payload);
                *access_token_request.metadata_mut() = metadata.clone();
                *access_token_request.extensions_mut() = extensions.clone();

                let access_token_response = self
                    .merchant_authentication_service
                    .create_access_token(access_token_request)
                    .await?
                    .into_inner();

                Some(access_token_response)
            }
            false => None,
        };

        Ok(access_token_response)
    }

    async fn create_connector_customer(
        &self,
        connector: &ConnectorEnum,
        payload: &CompositeAuthorizeRequest,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<Option<CustomerServiceCreateResponse>, tonic::Status> {
        let connector_data = ConnectorData::<domain_types::payment_method_data::DefaultPCIHolder>::get_connector_by_name(connector);
        let connector_customer_id = payload
            .state
            .as_ref()
            .and_then(|state| state.connector_customer_id.as_ref())
            .or_else(|| {
                payload
                    .customer
                    .as_ref()
                    .and_then(|c| c.connector_customer_id.as_ref())
            });
        let should_create_connector_customer =
            connector_data.connector.should_create_connector_customer()
                && connector_customer_id.is_none();

        let create_customer_response = match should_create_connector_customer {
            true => {
                let create_customer_payload =
                    grpc_api_types::payments::CustomerServiceCreateRequest::foreign_from(payload);
                let mut create_customer_request = tonic::Request::new(create_customer_payload);
                *create_customer_request.metadata_mut() = metadata.clone();
                *create_customer_request.extensions_mut() = extensions.clone();

                let create_customer_response = self
                    .customer_service
                    .create(create_customer_request)
                    .await?
                    .into_inner();

                Some(create_customer_response)
            }
            false => None,
        };

        Ok(create_customer_response)
    }

    async fn authorize(
        &self,
        payload: &CompositeAuthorizeRequest,
        access_token_response: Option<&MerchantAuthenticationServiceCreateAccessTokenResponse>,
        create_customer_response: Option<&CustomerServiceCreateResponse>,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<PaymentServiceAuthorizeResponse, tonic::Status> {
        let authorize_payload = PaymentServiceAuthorizeRequest::foreign_from((
            payload,
            access_token_response,
            create_customer_response,
        ));

        let mut authorize_request = tonic::Request::new(authorize_payload);
        *authorize_request.metadata_mut() = metadata.clone();
        *authorize_request.extensions_mut() = extensions.clone();

        let authorize_response = self
            .payment_service
            .authorize(authorize_request)
            .await?
            .into_inner();

        Ok(authorize_response)
    }

    async fn process_composite_authorize(
        &self,
        request: tonic::Request<CompositeAuthorizeRequest>,
    ) -> Result<tonic::Response<CompositeAuthorizeResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let connector = connector_from_composite_request_metadata(&metadata).map_err(|err| *err)?;
        let access_token_response = self
            .create_access_token(&connector, &payload, &metadata, &extensions)
            .await?;
        let create_customer_response = self
            .create_connector_customer(&connector, &payload, &metadata, &extensions)
            .await?;
        let authorize_response = self
            .authorize(
                &payload,
                access_token_response.as_ref(),
                create_customer_response.as_ref(),
                &metadata,
                &extensions,
            )
            .await?;

        Ok(tonic::Response::new(CompositeAuthorizeResponse {
            access_token_response,
            create_customer_response,
            authorize_response: Some(authorize_response),
        }))
    }

    async fn get(
        &self,
        payload: &CompositeGetRequest,
        access_token_response: Option<&MerchantAuthenticationServiceCreateAccessTokenResponse>,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<PaymentServiceGetResponse, tonic::Status> {
        let get_payload = grpc_api_types::payments::PaymentServiceGetRequest::foreign_from((
            payload,
            access_token_response,
        ));

        let mut get_request = tonic::Request::new(get_payload);
        *get_request.metadata_mut() = metadata.clone();
        *get_request.extensions_mut() = extensions.clone();

        let get_response = self.payment_service.get(get_request).await?.into_inner();

        Ok(get_response)
    }

    async fn process_composite_get(
        &self,
        request: tonic::Request<CompositeGetRequest>,
    ) -> Result<tonic::Response<CompositeGetResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let connector = connector_from_composite_request_metadata(&metadata).map_err(|err| *err)?;
        let access_token_response = self
            .create_access_token(&connector, &payload, &metadata, &extensions)
            .await?;
        let get_response = self
            .get(
                &payload,
                access_token_response.as_ref(),
                &metadata,
                &extensions,
            )
            .await?;

        Ok(tonic::Response::new(CompositeGetResponse {
            access_token_response,
            get_response: Some(get_response),
        }))
    }

    async fn refund(
        &self,
        payload: &CompositeRefundRequest,
        access_token_response: Option<&MerchantAuthenticationServiceCreateAccessTokenResponse>,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<RefundResponse, tonic::Status> {
        let refund_payload =
            PaymentServiceRefundRequest::foreign_from((payload, access_token_response));

        let mut refund_request = tonic::Request::new(refund_payload);
        *refund_request.metadata_mut() = metadata.clone();
        *refund_request.extensions_mut() = extensions.clone();

        let refund_response = self
            .payment_service
            .refund(refund_request)
            .await?
            .into_inner();

        Ok(refund_response)
    }

    async fn process_composite_refund(
        &self,
        request: tonic::Request<CompositeRefundRequest>,
    ) -> Result<tonic::Response<CompositeRefundResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let connector = connector_from_composite_request_metadata(&metadata).map_err(|err| *err)?;
        let access_token_response = self
            .create_access_token(&connector, &payload, &metadata, &extensions)
            .await?;
        let refund_response = self
            .refund(
                &payload,
                access_token_response.as_ref(),
                &metadata,
                &extensions,
            )
            .await?;

        Ok(tonic::Response::new(CompositeRefundResponse {
            access_token_response,
            refund_response: Some(refund_response),
        }))
    }

    async fn refund_get(
        &self,
        payload: &CompositeRefundGetRequest,
        access_token_response: Option<&MerchantAuthenticationServiceCreateAccessTokenResponse>,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<RefundResponse, tonic::Status> {
        let refund_get_payload =
            RefundServiceGetRequest::foreign_from((payload, access_token_response));

        let mut refund_get_request = tonic::Request::new(refund_get_payload);
        *refund_get_request.metadata_mut() = metadata.clone();
        *refund_get_request.extensions_mut() = extensions.clone();

        let refund_get_response = self
            .refund_service
            .get(refund_get_request)
            .await?
            .into_inner();

        Ok(refund_get_response)
    }

    async fn process_composite_refund_get(
        &self,
        request: tonic::Request<CompositeRefundGetRequest>,
    ) -> Result<tonic::Response<CompositeRefundGetResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let connector = connector_from_composite_request_metadata(&metadata).map_err(|err| *err)?;
        let access_token_response = self
            .create_access_token(&connector, &payload, &metadata, &extensions)
            .await?;
        let refund_get_response = self
            .refund_get(
                &payload,
                access_token_response.as_ref(),
                &metadata,
                &extensions,
            )
            .await?;

        Ok(tonic::Response::new(CompositeRefundGetResponse {
            access_token_response,
            refund_response: Some(refund_get_response),
        }))
    }

    async fn void(
        &self,
        payload: &CompositeVoidRequest,
        access_token_response: Option<&MerchantAuthenticationServiceCreateAccessTokenResponse>,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<PaymentServiceVoidResponse, tonic::Status> {
        let void_payload =
            PaymentServiceVoidRequest::foreign_from((payload, access_token_response));

        let mut void_request = tonic::Request::new(void_payload);
        *void_request.metadata_mut() = metadata.clone();
        *void_request.extensions_mut() = extensions.clone();

        let void_response = self.payment_service.void(void_request).await?.into_inner();

        Ok(void_response)
    }

    async fn process_composite_void(
        &self,
        request: tonic::Request<CompositeVoidRequest>,
    ) -> Result<tonic::Response<CompositeVoidResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let connector = connector_from_composite_request_metadata(&metadata).map_err(|err| *err)?;
        let access_token_response = self
            .create_access_token(&connector, &payload, &metadata, &extensions)
            .await?;
        let void_response = self
            .void(
                &payload,
                access_token_response.as_ref(),
                &metadata,
                &extensions,
            )
            .await?;

        Ok(tonic::Response::new(CompositeVoidResponse {
            access_token_response,
            void_response: Some(void_response),
        }))
    }

    async fn capture(
        &self,
        payload: &CompositeCaptureRequest,
        access_token_response: Option<&MerchantAuthenticationServiceCreateAccessTokenResponse>,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<PaymentServiceCaptureResponse, tonic::Status> {
        let capture_payload =
            PaymentServiceCaptureRequest::foreign_from((payload, access_token_response));

        let mut capture_request = tonic::Request::new(capture_payload);
        *capture_request.metadata_mut() = metadata.clone();
        *capture_request.extensions_mut() = extensions.clone();

        let capture_response = self
            .payment_service
            .capture(capture_request)
            .await?
            .into_inner();

        Ok(capture_response)
    }

    async fn process_composite_capture(
        &self,
        request: tonic::Request<CompositeCaptureRequest>,
    ) -> Result<tonic::Response<CompositeCaptureResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let connector = connector_from_composite_request_metadata(&metadata).map_err(|err| *err)?;
        let access_token_response = self
            .create_access_token(&connector, &payload, &metadata, &extensions)
            .await?;
        let capture_response = self
            .capture(
                &payload,
                access_token_response.as_ref(),
                &metadata,
                &extensions,
            )
            .await?;

        Ok(tonic::Response::new(CompositeCaptureResponse {
            access_token_response,
            capture_response: Some(capture_response),
        }))
    }

    async fn pre_authenticate<Req: CompositePreAuthNRequest>(
        &self,
        payload: &Req,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<Option<PaymentMethodAuthenticationServicePreAuthenticateResponse>, tonic::Status>
    {
        let connector = connector_from_composite_request_metadata(metadata).map_err(|err| *err)?;

        let pre_authenticate_response = if payload
            .should_do_pre_authenticate(&connector)
            .map_err(|err| *err)?
        {
            let pre_authenticate_payload = payload.build_pre_authenticate_request();

            let mut pre_authenticate_request = tonic::Request::new(pre_authenticate_payload);
            *pre_authenticate_request.metadata_mut() = metadata.clone();
            *pre_authenticate_request.extensions_mut() = extensions.clone();

            Some(
                self.payment_method_authentication_service
                    .pre_authenticate(pre_authenticate_request)
                    .await?
                    .into_inner(),
            )
        } else {
            None
        };

        Ok(pre_authenticate_response)
    }

    async fn process_composite_pre_authenticate(
        &self,
        request: tonic::Request<CompositePreauthenticateRequest>,
    ) -> Result<tonic::Response<CompositePreauthenticateResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let pre_authenticate_response = self
            .pre_authenticate(&payload, &metadata, &extensions)
            .await?;

        Ok(tonic::Response::new(CompositePreauthenticateResponse {
            pre_authenticate_response,
        }))
    }

    async fn authenticate(
        &self,
        payload: &CompositeAuthenticateRequest,
        pre_authenticate_response: Option<
            &PaymentMethodAuthenticationServicePreAuthenticateResponse,
        >,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<PaymentMethodAuthenticationServiceAuthenticateResponse, tonic::Status> {
        let authenticate_payload =
            PaymentMethodAuthenticationServiceAuthenticateRequest::foreign_from((
                payload,
                pre_authenticate_response,
            ));

        let mut authenticate_request = tonic::Request::new(authenticate_payload);
        *authenticate_request.metadata_mut() = metadata.clone();
        *authenticate_request.extensions_mut() = extensions.clone();

        let authenticate_response = self
            .payment_method_authentication_service
            .authenticate(authenticate_request)
            .await?
            .into_inner();

        Ok(authenticate_response)
    }

    async fn process_composite_authenticate(
        &self,
        request: tonic::Request<CompositeAuthenticateRequest>,
    ) -> Result<tonic::Response<CompositeAuthenticateResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let pre_authenticate_response = self
            .pre_authenticate(&payload, &metadata, &extensions)
            .await?;

        let authenticate_response = self
            .authenticate(
                &payload,
                pre_authenticate_response.as_ref(),
                &metadata,
                &extensions,
            )
            .await?;

        Ok(tonic::Response::new(CompositeAuthenticateResponse {
            authenticate_response: Some(authenticate_response),
            pre_authenticate_response,
        }))
    }
}

#[tonic::async_trait]
impl<P, M, C, R, A> CompositePaymentService for Payments<P, M, C, R, A>
where
    P: PaymentService + Clone + Send + Sync + 'static,
    M: MerchantAuthenticationService + Clone + Send + Sync + 'static,
    C: CustomerService + Clone + Send + Sync + 'static,
    R: RefundService + Clone + Send + Sync + 'static,
    A: PaymentMethodAuthenticationService + Clone + Send + Sync + 'static,
{
    async fn authorize(
        &self,
        request: tonic::Request<CompositeAuthorizeRequest>,
    ) -> Result<tonic::Response<CompositeAuthorizeResponse>, tonic::Status> {
        self.process_composite_authorize(request).await
    }

    async fn get(
        &self,
        request: tonic::Request<CompositeGetRequest>,
    ) -> Result<tonic::Response<CompositeGetResponse>, tonic::Status> {
        self.process_composite_get(request).await
    }

    async fn refund(
        &self,
        request: tonic::Request<CompositeRefundRequest>,
    ) -> Result<tonic::Response<CompositeRefundResponse>, tonic::Status> {
        self.process_composite_refund(request).await
    }

    async fn void(
        &self,
        request: tonic::Request<CompositeVoidRequest>,
    ) -> Result<tonic::Response<CompositeVoidResponse>, tonic::Status> {
        self.process_composite_void(request).await
    }

    async fn capture(
        &self,
        request: tonic::Request<CompositeCaptureRequest>,
    ) -> Result<tonic::Response<CompositeCaptureResponse>, tonic::Status> {
        self.process_composite_capture(request).await
    }
}

#[tonic::async_trait]
impl<P, M, C, R, A> CompositeRefundService for Payments<P, M, C, R, A>
where
    P: PaymentService + Clone + Send + Sync + 'static,
    M: MerchantAuthenticationService + Clone + Send + Sync + 'static,
    C: CustomerService + Clone + Send + Sync + 'static,
    R: RefundService + Clone + Send + Sync + 'static,
    A: PaymentMethodAuthenticationService + Clone + Send + Sync + 'static,
{
    async fn get(
        &self,
        request: tonic::Request<CompositeRefundGetRequest>,
    ) -> Result<tonic::Response<CompositeRefundGetResponse>, tonic::Status> {
        self.process_composite_refund_get(request).await
    }
}

#[tonic::async_trait]
impl<P, M, C, R, A> CompositePaymentMethodAuthenticationService for Payments<P, M, C, R, A>
where
    P: PaymentService + Clone + Send + Sync + 'static,
    M: MerchantAuthenticationService + Clone + Send + Sync + 'static,
    C: CustomerService + Clone + Send + Sync + 'static,
    R: RefundService + Clone + Send + Sync + 'static,
    A: PaymentMethodAuthenticationService + Clone + Send + Sync + 'static,
{
    async fn preauthenticate(
        &self,
        request: tonic::Request<CompositePreauthenticateRequest>,
    ) -> Result<tonic::Response<CompositePreauthenticateResponse>, tonic::Status> {
        self.process_composite_pre_authenticate(request).await
    }

    async fn authenticate(
        &self,
        request: tonic::Request<CompositeAuthenticateRequest>,
    ) -> Result<tonic::Response<CompositeAuthenticateResponse>, tonic::Status> {
        self.process_composite_authenticate(request).await
    }
}
