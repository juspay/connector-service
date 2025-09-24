use std::marker::PhantomData;

use crate::router_data::{ConnectorAuthType, ErrorResponse};

#[derive(Debug, Clone)]
pub struct RouterDataV2<Flow, ResourceCommonData, FlowSpecificRequest, FlowSpecificResponse> {
    pub flow: PhantomData<Flow>,
    // pub tenant_id: id_type::TenantId, // TODO: Should we add this
    pub resource_common_data: ResourceCommonData,
    pub connector_auth_type: ConnectorAuthType,
    /// Contains flow-specific data required to construct a request and send it to the connector.
    pub request: FlowSpecificRequest,
    /// Contains flow-specific data that the connector responds with.
    pub response: Result<FlowSpecificResponse, ErrorResponse>,
}

impl<Flow, ResourceCommonData, FlowSpecificRequest, FlowSpecificResponse>
    RouterDataV2<Flow, ResourceCommonData, FlowSpecificRequest, FlowSpecificResponse>
{
    /// Builder method to set the response field
    pub fn set_response(mut self, response: Result<FlowSpecificResponse, ErrorResponse>) -> Self {
        self.response = response;
        self
    }

    /// Builder method to update resource common data
    pub fn update_resource_common_data<F>(mut self, updater: F) -> Self
    where
        F: FnOnce(ResourceCommonData) -> ResourceCommonData,
    {
        self.resource_common_data = updater(self.resource_common_data);
        self
    }
}
