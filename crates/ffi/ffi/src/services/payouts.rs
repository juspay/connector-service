use grpc_api_types::payouts::{PayoutServiceCreateRequest, PayoutServiceCreateResponse};

use crate::macros::{req_transformer, res_transformer};

use domain_types::{
    connector_flow::PayoutCreate,
    payouts::connector_types::{PayoutCreateRequest, PayoutCreateResponse, PayoutFlowData},
};

// payout create request transformer
req_transformer!(
    fn_name: payout_create_req_transformer,
    request_type: PayoutServiceCreateRequest,
    flow_marker: PayoutCreate,
    resource_common_data_type: PayoutFlowData,
    request_data_type: PayoutCreateRequest,
    response_data_type: PayoutCreateResponse,
);

// payout create response transformer
res_transformer!(
    fn_name: payout_create_res_transformer,
    request_type: PayoutServiceCreateRequest,
    response_type: PayoutServiceCreateResponse,
    flow_marker: PayoutCreate,
    resource_common_data_type: PayoutFlowData,
    request_data_type: PayoutCreateRequest,
    response_data_type: PayoutCreateResponse,
    generate_response_fn: generate_payout_create_response,
);
