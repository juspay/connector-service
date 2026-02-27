use std::marker::PhantomData;

use crate::router_data::{ConnectorSpecificAuth, ErrorResponse};

#[derive(Debug, Clone)]
pub struct RouterDataV2<Flow, ResourceCommonData, FlowSpecificRequest, FlowSpecificResponse> {
    pub flow: PhantomData<Flow>,
    // pub tenant_id: id_type::TenantId, // TODO: Should we add this
    pub resource_common_data: ResourceCommonData,
    pub connector_auth_type: ConnectorSpecificAuth,
    /// Contains flow-specific data required to construct a request and send it to the connector.
    pub request: FlowSpecificRequest,
    /// Contains flow-specific data that the connector responds with.
    pub response: Result<FlowSpecificResponse, ErrorResponse>,
}
