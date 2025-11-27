# Connector Flow Implementation Guide
This guide provides step-by-step instructions for adding support for a new connector flow.
## Adding a NewConnectorFlow (NewConnectorFlow=the connector flow name which is needed to be integrated)
### File: backend/domain_types/src/connector_flow.rs
1. Add the NewConnectorFlow struct and add it in FlowName enum in the above file
```rust
#[derive(Debug, Clone)]
pub struct NewConnectorFlow;
pub enum FlowName {
    CreateOrder,
    IncomingWebhook,
    Dsync,
    NewConnectorFlow, // Add here
}
```
### File: backend/domain_types/src/connector_types.rs
2.  Define the request data structure for the new flow (e.g., `NewConnectorFlowRequestData`).
    ```rust
    #[derive(Debug, Clone)]
    pub struct NewConnectorFlowRequestData {
        // ... fields for the new flow's request
    }
    ```
3.  Determine the response data structure.
    a.  Consult `HyperswitchReference.md` to understand the expected response for the flow.
    b.  Search the codebase (primarily in `domain_types`) to see if a suitable response struct or enum already exists.
    c.  If a suitable type exists, use it.
    d.  If not, follow the pattern from the reference document to either add a new variant to an existing enum (like `PaymentsResponseData`) or create a new response struct.
    **Example (adding a variant to `PaymentsResponseData`):**
    ```rust
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum PaymentsResponseData {
        // ... existing variants
        NewConnectorFlowResponse {
            // ... fields for the new flow's response
        },
    }
    ```
    **Example (creating a separate struct):**
    ```rust
    #[derive(Debug, Clone)]
    pub struct NewConnectorFlowResponseData {
        // ... fields for the new flow's response
    }
    ```
4.  Implement the `ForeignTryFrom` trait to convert the gRPC request to your new request data struct.
    ```rust
    impl<T: PaymentMethodDataTypes>
        ForeignTryFrom<grpc_api_types::payments::PaymentServiceAuthorizeRequest>
        for NewConnectorFlowRequestData<T>
    {
        type Error = ApplicationErrorResponse;
        fn foreign_try_from(
            payload: grpc_api_types::payments::PaymentServiceAuthorizeRequest,
        ) -> Result<Self, error_stack::Report<Self::Error>> {
            // ... implementation to map fields from payload to your struct
        }
    }
    ```
### File: backend/grpc-server/src/server/payments.rs
5.  Add a handler function for the new flow, using the reference for architectural guidance.
    ```rust
    async fn handle_new_connector_flow<
        T: PaymentMethodDataTypes
            + Default
            + Eq
            + Debug
            + Send
            + serde::Serialize
            + serde::de::DeserializeOwned
            + Clone
            + Sync
            + domain_types::types::CardConversionHelper<T>
            + 'static,
        P,
        Res, // The response type determined in the previous step
    >(
        &self,
        connector_data: ConnectorData<T>,
        payment_flow_data: &PaymentFlowData,
        connector_auth_details: ConnectorAuthType,
        payload: &P,
        connector_name: &str,
        service_name: &str,
    ) -> Result<Res, PaymentAuthorizationError>
    where
        P: Clone,
        NewConnectorFlowRequestData<T>: ForeignTryFrom<P, Error = ApplicationErrorResponse>,
        Res: 'static, // Ensure response type has a static lifetime
    {
        // Get connector integration
        let connector_integration: BoxedConnectorIntegrationV2<
            '_,
            NewConnectorFlow,
            PaymentFlowData,
            NewConnectorFlowRequestData<T>,
            Res, // Use the determined response type
        > = connector_data.connector.get_connector_integration_v2();
        // Create request data
        let new_flow_request_data =
            NewConnectorFlowRequestData::foreign_try_from(payload.clone()).map_err(|e| {
                // ... error handling
            })?;
        let new_flow_router_data = RouterDataV2::<
            NewConnectorFlow,
            PaymentFlowData,
            NewConnectorFlowRequestData<T>,
            Res,
        > {
            // ... router data fields
        };
        // Execute connector processing
        let response = external_services::service::execute_connector_processing_step(
            &self.config.proxy,
            connector_integration,
            new_flow_router_data,
            None,
            connector_name,
            service_name,
        )
        .await
        .switch()
        .map_err(|e: error_stack::Report<ApplicationErrorResponse>| {
            // ... error handling
        })?;
        match response.response {
            Ok(response_data) => {
                // Handle success
                Ok(response_data)
            }
            Err(error) => {
                // Handle error
            },
        }
    }
    ```

### File: backend/interfaces/src/connector_types.rs

6. Add a new connector service trait for new flow.
```rust
pub trait ConnectorServiceTrait<T: PaymentMethodDataTypes>:
    ConnectorCommon
    + ValidationTrait
    + PaymentAuthorizeV2<T>
    + PaymentSyncV2
    + NewConnectorFlowTrait
{
}
```

7. Add a trait bound for new connector service trait
```rust
pub trait NewConnectorFlowTrait:
    ConnectorIntegrationV2<
    connector_flow::NewConnectorFlow,
    PaymentFlowData,
    NewConnectorFlowRequestData,
    NewConnectorFlowResponse,
>
{
}
```

### File: backend/domain_types/src/router_request_types.rs

8. Add a NewConnectorFlow IntegrityObject struct
```rust
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NewConnectorFlowIntegrityObject {
  // ... fields for the new flow's integrity object
}
```

### File: backend/interfaces/src/integrity.rs

9. Add integrity checking implementation for the new flow by implementing the required traits:

   a. Add the `CheckIntegrity` implementation using the macro:
   ```rust
   impl_check_integrity!(NewConnectorFlowData);
   ```

   b. Implement `GetIntegrityObject` trait for the new flow request data:
   ```rust
   impl GetIntegrityObject<NewConnectorFlowIntegrityObject> for NewConnectorFlowData {
       fn get_response_integrity_object(&self) -> Option<NewConnectorFlowIntegrityObject> {
           self.integrity_object.clone()
       }

       fn get_request_integrity_object(&self) -> NewConnectorFlowIntegrityObject {
           NewConnectorFlowIntegrityObject {
               // Map relevant fields from request data
               // Example: amount: self.amount,
               // Example: currency: self.currency,
           }
       }
   }
   ```

   c. Implement `FlowIntegrity` trait for the integrity object:
   ```rust
   impl FlowIntegrity for NewConnectorFlowIntegrityObject {
       type IntegrityObject = Self;

       fn compare(
           req_integrity_object: Self,
           res_integrity_object: Self,
           connector_transaction_id: Option<String>,
       ) -> Result<(), IntegrityCheckError> {
           let mut mismatched_fields = Vec::new();

           // Compare each field and add mismatches
           // Example for amount field:
           // if req_integrity_object.amount != res_integrity_object.amount {
           //     mismatched_fields.push(format_mismatch(
           //         "amount",
           //         &req_integrity_object.amount.to_string(),
           //         &res_integrity_object.amount.to_string(),
           //     ));
           // }

           // Example for currency field:
           // if req_integrity_object.currency != res_integrity_object.currency {
           //     mismatched_fields.push(format_mismatch(
           //         "currency",
           //         &req_integrity_object.currency.to_string(),
           //         &res_integrity_object.currency.to_string(),
           //     ));
           // }

           check_integrity_result(mismatched_fields, connector_transaction_id)
       }
   }
   ```
