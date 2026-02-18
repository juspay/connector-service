use connector_integration::types::ConnectorData;
use domain_types::{
    connector_types::{AccessTokenResponseData, ConnectorEnum},
    utils::ForeignTryFrom as _,
};
use grpc_api_types::payments::{
    composite_payment_service_server::CompositePaymentService,
    payment_service_server::PaymentService, CompositeAuthorizeRequest, CompositeAuthorizeResponse,
    PaymentServiceAuthorizeResponse, PaymentServiceCreateAccessTokenResponse,
    PaymentServiceCreateConnectorCustomerResponse,
};

use crate::transformers::ForeignFrom;
use crate::utils::connector_from_composite_authorize_metadata;

#[derive(Clone)]
pub struct Payments<S> {
    payment_service: S,
}

impl<S> Payments<S> {
    pub fn new(payment_service: S) -> Self {
        Self { payment_service }
    }
}

impl<S> Payments<S>
where
    S: PaymentService + Clone + Send + Sync + 'static,
{
    async fn call_create_access_token(
        &self,
        connector: &ConnectorEnum,
        payload: &CompositeAuthorizeRequest,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<Option<PaymentServiceCreateAccessTokenResponse>, tonic::Status> {
        let should_do_access_token = match payload.payment_method.clone() {
            Some(payment_method) => {
                let payment_method = common_enums::PaymentMethod::foreign_try_from(payment_method)
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
            }
            None => false,
        };
        let access_token_result = payload
            .state
            .as_ref()
            .and_then(|state| state.access_token.as_ref())
            .and_then(|token| AccessTokenResponseData::foreign_try_from(token).ok());
        let should_call_create_access_token = match (should_do_access_token, access_token_result) {
            (true, None) => true,
            (true, Some(_)) | (false, _) => false,
        };

        let access_token_response = match should_call_create_access_token {
            true => {
                let access_token_payload =
                    grpc_api_types::payments::PaymentServiceCreateAccessTokenRequest::foreign_from(
                        (payload, connector),
                    );
                let mut access_token_request = tonic::Request::new(access_token_payload);
                *access_token_request.metadata_mut() = metadata.clone();
                *access_token_request.extensions_mut() = extensions.clone();

                let access_token_response = self
                    .payment_service
                    .create_access_token(access_token_request)
                    .await?
                    .into_inner();

                Some(access_token_response)
            }
            false => None,
        };

        Ok(access_token_response)
    }

    async fn call_create_connector_customer(
        &self,
        connector: &ConnectorEnum,
        payload: &CompositeAuthorizeRequest,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<Option<PaymentServiceCreateConnectorCustomerResponse>, tonic::Status> {
        let connector_data = ConnectorData::<domain_types::payment_method_data::DefaultPCIHolder>::get_connector_by_name(connector);
        let should_create_connector_customer =
            connector_data.connector.should_create_connector_customer()
                && payload.connector_customer_id.is_none();

        let create_customer_response = match should_create_connector_customer {
            true => {
                let create_customer_payload =
                    grpc_api_types::payments::PaymentServiceCreateConnectorCustomerRequest::foreign_from(
                        payload,
                    );
                let mut create_customer_request = tonic::Request::new(create_customer_payload);
                *create_customer_request.metadata_mut() = metadata.clone();
                *create_customer_request.extensions_mut() = extensions.clone();

                let create_customer_response = self
                    .payment_service
                    .create_connector_customer(create_customer_request)
                    .await?
                    .into_inner();

                Some(create_customer_response)
            }
            false => None,
        };

        Ok(create_customer_response)
    }

    async fn call_authorize_only(
        &self,
        payload: &CompositeAuthorizeRequest,
        access_token_response: Option<&PaymentServiceCreateAccessTokenResponse>,
        create_customer_response: Option<&PaymentServiceCreateConnectorCustomerResponse>,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<PaymentServiceAuthorizeResponse, tonic::Status> {
        let authorize_only_payload =
            grpc_api_types::payments::PaymentServiceAuthorizeOnlyRequest::foreign_from((
                payload,
                access_token_response,
                create_customer_response,
            ));

        let mut authorize_only_request = tonic::Request::new(authorize_only_payload);
        *authorize_only_request.metadata_mut() = metadata.clone();
        *authorize_only_request.extensions_mut() = extensions.clone();

        let authorize_response = self
            .payment_service
            .authorize_only(authorize_only_request)
            .await?
            .into_inner();

        Ok(authorize_response)
    }

    async fn process_composite_authorize(
        &self,
        request: tonic::Request<CompositeAuthorizeRequest>,
    ) -> Result<tonic::Response<CompositeAuthorizeResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();

        let connector =
            connector_from_composite_authorize_metadata(&metadata).map_err(|err| *err)?;
        let access_token_response = self
            .call_create_access_token(&connector, &payload, &metadata, &extensions)
            .await?;
        let create_customer_response = self
            .call_create_connector_customer(&connector, &payload, &metadata, &extensions)
            .await?;
        let authorize_response = self
            .call_authorize_only(
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
}

#[tonic::async_trait]
impl<S> CompositePaymentService for Payments<S>
where
    S: PaymentService + Clone + Send + Sync + 'static,
{
    async fn composite_authorize(
        &self,
        request: tonic::Request<CompositeAuthorizeRequest>,
    ) -> Result<tonic::Response<CompositeAuthorizeResponse>, tonic::Status> {
        self.process_composite_authorize(request).await
    }
}
