# Phase 4: Server Implementation Updates

## Overview
Update the gRPC server implementation to use the new proto interfaces and domain type conversions. This phase focuses on implementing the actual business logic with the new message structures.

## Completion Target
All gRPC service handlers implemented and working. Server starts successfully and serves all endpoints.

## Tasks (Execute in parallel)

### Task 4A: PaymentService Handler Implementation
**Assigned to**: Sub-agent Alpha  
**Dependencies**: Phase 3 completion

#### Objectives
- Implement all PaymentService gRPC handlers with new message structures
- Update payment flow logic for new field mappings
- Ensure proper error handling and response formatting

#### Steps
1. **Update PaymentService Trait Implementation**
   ```rust
   #[tonic::async_trait]
   impl grpc_api_types::payment_service_server::PaymentService for PaymentServiceImpl {
       async fn authorize(
           &self,
           request: Request<grpc_api_types::PaymentServiceAuthorizeRequest>,
       ) -> Result<Response<grpc_api_types::PaymentServiceAuthorizeResponse>, Status> {
           let proto_request = request.into_inner();
           
           // Convert proto to domain
           let domain_request = domain_types::DomainAuthorizeRequest::try_from(proto_request)
               .map_err(|e| Status::invalid_argument(format!("Invalid request: {}", e)))?;
           
           // Call business logic
           let domain_response = self.payment_core.authorize(domain_request).await
               .map_err(|e| Status::internal(format!("Authorization failed: {}", e)))?;
           
           // Convert domain to proto
           let proto_response = grpc_api_types::PaymentServiceAuthorizeResponse::from(domain_response);
           
           Ok(Response::new(proto_response))
       }
   }
   ```

2. **Implement Get (Sync) Handler**
   ```rust
   async fn get(
       &self,
       request: Request<grpc_api_types::PaymentServiceGetRequest>,
   ) -> Result<Response<grpc_api_types::PaymentServiceGetResponse>, Status> {
       // Similar pattern: proto -> domain -> business logic -> domain -> proto
   }
   ```

3. **Implement Void Handler**
   ```rust
   async fn void(
       &self,
       request: Request<grpc_api_types::PaymentServiceVoidRequest>,
   ) -> Result<Response<grpc_api_types::PaymentServiceVoidResponse>, Status> {
       // Handle void-specific logic with new request_ref_id field
   }
   ```

4. **Implement Capture Handler**
   ```rust
   async fn capture(
       &self,
       request: Request<grpc_api_types::PaymentServiceCaptureRequest>,
   ) -> Result<Response<grpc_api_types::PaymentServiceCaptureResponse>, Status> {
       // Handle multiple capture scenarios
   }
   ```

5. **Implement Refund Handler**
   ```rust
   async fn refund(
       &self,
       request: Request<grpc_api_types::PaymentServiceRefundRequest>,
   ) -> Result<Response<grpc_api_types::RefundResponse>, Status> {
       // Note: Returns unified RefundResponse
   }
   ```

6. **Implement Register (Mandate) Handler**
   ```rust
   async fn register(
       &self,
       request: Request<grpc_api_types::PaymentServiceRegisterRequest>,
   ) -> Result<Response<grpc_api_types::PaymentServiceRegisterResponse>, Status> {
       // Handle mandate setup with new payment method structure
   }
   ```

7. **Implement Dispute Handler**
   ```rust
   async fn dispute(
       &self,
       request: Request<grpc_api_types::PaymentServiceDisputeRequest>,
   ) -> Result<Response<grpc_api_types::DisputeResponse>, Status> {
       // Note: Returns unified DisputeResponse
   }
   ```

8. **Implement Transform (Webhook) Handler**
   ```rust
   async fn transform(
       &self,
       request: Request<grpc_api_types::PaymentServiceTransformRequest>,
   ) -> Result<Response<grpc_api_types::PaymentServiceTransformResponse>, Status> {
       // Handle webhook transformation logic
   }
   ```

#### Deliverables
- Complete PaymentService implementation
- Proper error handling for all endpoints
- Integration tests for all handlers
- Performance benchmarks

#### Acceptance Criteria
- All PaymentService endpoints work correctly
- Proper HTTP status codes returned
- Error messages are clear and actionable
- No performance regression

---

### Task 4B: RefundService Handler Implementation
**Assigned to**: Sub-agent Beta  
**Dependencies**: Phase 3 completion

#### Objectives
- Implement RefundService gRPC handlers
- Handle unified RefundResponse structure
- Ensure webhook transformation works correctly

#### Steps
1. **Implement RefundService Trait**
   ```rust
   #[tonic::async_trait]
   impl grpc_api_types::refund_service_server::RefundService for RefundServiceImpl {
       async fn get(
           &self,
           request: Request<grpc_api_types::RefundServiceGetRequest>,
       ) -> Result<Response<grpc_api_types::RefundResponse>, Status> {
           let proto_request = request.into_inner();
           
           // Convert to domain types
           let domain_request = domain_types::DomainRefundGetRequest::try_from(proto_request)
               .map_err(|e| Status::invalid_argument(format!("Invalid request: {}", e)))?;
           
           // Call business logic
           let domain_response = self.refund_core.get_refund(domain_request).await
               .map_err(|e| Status::internal(format!("Refund sync failed: {}", e)))?;
           
           // Convert to unified RefundResponse
           let proto_response = grpc_api_types::RefundResponse::from(domain_response);
           
           Ok(Response::new(proto_response))
       }
   }
   ```

2. **Implement Transform Handler**
   ```rust
   async fn transform(
       &self,
       request: Request<grpc_api_types::RefundServiceTransformRequest>,
   ) -> Result<Response<grpc_api_types::RefundServiceTransformResponse>, Status> {
       // Handle refund webhook transformations
       // Parse incoming webhook and convert to RefundResponse
   }
   ```

3. **Update Refund Business Logic**
   - Handle new field mappings (request_ref_id, transaction_id)
   - Ensure refund metadata is properly processed
   - Update refund status handling

4. **Create Integration Tests**
   ```rust
   #[cfg(test)]
   mod refund_integration_tests {
       #[tokio::test]
       async fn test_refund_get_flow() {
           // Test complete refund sync flow
       }
       
       #[tokio::test]
       async fn test_refund_webhook_transformation() {
           // Test webhook parsing and response generation
       }
   }
   ```

#### Deliverables
- Complete RefundService implementation
- Webhook transformation logic
- Integration tests
- Updated refund business logic

#### Acceptance Criteria
- RefundService endpoints work correctly
- Webhooks are processed correctly
- Unified RefundResponse is properly populated
- All tests pass

---

### Task 4C: DisputeService Handler Implementation
**Assigned to**: Sub-agent Gamma  
**Dependencies**: Phase 3 completion

#### Objectives
- Implement DisputeService gRPC handlers
- Handle new dispute operations (Defend, Accept)
- Implement evidence submission functionality

#### Steps
1. **Implement DisputeService Trait**
   ```rust
   #[tonic::async_trait]
   impl grpc_api_types::dispute_service_server::DisputeService for DisputeServiceImpl {
       async fn submit_evidence(
           &self,
           request: Request<grpc_api_types::DisputeServiceSubmitEvidenceRequest>,
       ) -> Result<Response<grpc_api_types::DisputeServiceSubmitEvidenceResponse>, Status> {
           // Handle evidence document submission
       }
       
       async fn get(
           &self,
           request: Request<grpc_api_types::DisputeServiceGetRequest>,
       ) -> Result<Response<grpc_api_types::DisputeResponse>, Status> {
           // Return unified DisputeResponse
       }
       
       async fn defend(
           &self,
           request: Request<grpc_api_types::DisputeServiceDefendRequest>,
       ) -> Result<Response<grpc_api_types::DisputeServiceDefendResponse>, Status> {
           // New: Handle dispute defense
       }
       
       async fn accept(
           &self,
           request: Request<grpc_api_types::DisputeServiceAcceptRequest>,
       ) -> Result<Response<grpc_api_types::DisputeServiceAcceptResponse>, Status> {
           // New: Handle dispute acceptance
       }
       
       async fn transform(
           &self,
           request: Request<grpc_api_types::DisputeServiceTransformRequest>,
       ) -> Result<Response<grpc_api_types::DisputeServiceTransformResponse>, Status> {
           // Handle dispute webhook transformations
       }
   }
   ```

2. **Implement Evidence Document Handling**
   ```rust
   async fn process_evidence_documents(
       &self,
       evidence_docs: Vec<grpc_api_types::EvidenceDocument>,
   ) -> Result<Vec<String>, ProcessingError> {
       let mut submitted_ids = Vec::new();
       
       for doc in evidence_docs {
           let domain_doc = domain_types::DomainEvidenceDocument::try_from(doc)?;
           let submitted_id = self.evidence_processor.submit(domain_doc).await?;
           submitted_ids.push(submitted_id);
       }
       
       Ok(submitted_ids)
   }
   ```

3. **Update Dispute Business Logic**
   - Implement dispute defense logic
   - Implement dispute acceptance logic
   - Handle dispute status transitions
   - Process evidence documents (file uploads, text content)

4. **Create Comprehensive Tests**
   ```rust
   #[cfg(test)]
   mod dispute_integration_tests {
       #[tokio::test]
       async fn test_evidence_submission_flow() {
           // Test complete evidence submission
       }
       
       #[tokio::test]
       async fn test_dispute_defense_flow() {
           // Test dispute defense operation
       }
       
       #[tokio::test]
       async fn test_dispute_acceptance_flow() {
           // Test dispute acceptance operation
       }
   }
   ```

#### Deliverables
- Complete DisputeService implementation
- Evidence document processing logic
- New dispute operations (Defend, Accept)
- Comprehensive integration tests

#### Acceptance Criteria
- All DisputeService endpoints work correctly
- Evidence documents are processed properly
- New dispute operations function correctly
- Webhook transformations work

---

### Task 4D: Server Configuration and Error Handling Updates
**Assigned to**: Sub-agent Delta  
**Dependencies**: Tasks 4A, 4B, 4C completion

#### Objectives
- Update server configuration for new services
- Implement consistent error handling patterns
- Update middleware and interceptors

#### Steps
1. **Update Service Registration**
   ```rust
   // In main.rs or app.rs
   pub async fn create_server() -> Result<(), Box<dyn std::error::Error>> {
       let payment_service = PaymentServiceImpl::new(payment_core);
       let refund_service = RefundServiceImpl::new(refund_core);
       let dispute_service = DisputeServiceImpl::new(dispute_core);
       
       let server = Server::builder()
           .add_service(grpc_api_types::payment_service_server::PaymentServiceServer::new(payment_service))
           .add_service(grpc_api_types::refund_service_server::RefundServiceServer::new(refund_service))
           .add_service(grpc_api_types::dispute_service_server::DisputeServiceServer::new(dispute_service))
           .serve(addr)
           .await?;
       
       Ok(())
   }
   ```

2. **Implement Consistent Error Handling**
   ```rust
   pub fn convert_domain_error_to_status(error: domain_types::DomainError) -> Status {
       match error {
           domain_types::DomainError::ValidationError(msg) => Status::invalid_argument(msg),
           domain_types::DomainError::NotFound(msg) => Status::not_found(msg),
           domain_types::DomainError::Unauthorized(msg) => Status::unauthenticated(msg),
           domain_types::DomainError::InternalError(msg) => Status::internal(msg),
           // ... handle all error types
       }
   }
   ```

3. **Update HTTP Gateway Configuration**
   ```rust
   // Ensure HTTP endpoints are properly configured
   let gateway_config = GatewayConfig {
       endpoints: vec![
           "/v1/payment/authorize",
           "/v1/payment/get",
           "/v1/payment/void",
           "/v1/payment/capture",
           "/v1/payment/refund",
           "/v1/payment/register",
           "/v1/payment/dispute",
           "/v1/payment/transform",
           "/v1/refund/get",
           "/v1/refund/transform",
           "/v1/dispute/submit_evidence",
           "/v1/dispute/get",
           "/v1/dispute/defend",
           "/v1/dispute/accept",
           "/v1/dispute/transform",
       ],
   };
   ```

4. **Update Middleware and Interceptors**
   ```rust
   // Update any middleware to handle new message structures
   pub struct RequestLoggingInterceptor;
   
   impl Interceptor for RequestLoggingInterceptor {
       fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
           // Log requests with new field names
           tracing::info!("Request: {:?}", request.metadata());
           Ok(request)
       }
   }
   ```

5. **Create Server Integration Tests**
   ```rust
   #[cfg(test)]
   mod server_integration_tests {
       #[tokio::test]
       async fn test_server_startup() {
           // Test server starts successfully
       }
       
       #[tokio::test]
       async fn test_all_endpoints_respond() {
           // Test all endpoints are accessible
       }
   }
   ```

#### Deliverables
- Updated server configuration
- Consistent error handling patterns
- Updated middleware and interceptors
- Server integration tests

#### Acceptance Criteria
- Server starts successfully with all services
- All HTTP endpoints are accessible
- Error handling is consistent across services
- Middleware works with new message structures

---

## Phase 4 Completion Criteria

### Must Complete Before Phase 5
1. All gRPC service handlers are implemented and working
2. Server starts successfully and serves all endpoints
3. Error handling is consistent and comprehensive
4. Integration tests pass for all services

### Handoff to Phase 5
- **Fully functional gRPC server** with new proto interfaces
- **Working HTTP endpoints** for all operations
- **Consistent error handling** patterns
- **Integration test suite** for verification

### Risk Mitigation
- **Service failures**: Comprehensive error handling and logging
- **Performance issues**: Performance benchmarks and monitoring
- **Integration problems**: Extensive integration testing
- **HTTP gateway issues**: Test all HTTP endpoints

### Efficiency Focus
- **Stub first, implement later**: Get all handlers compiling with TODO implementations
- **Test endpoints immediately**: Verify each endpoint as soon as it's implemented
- **Parallel implementation**: Work on different services simultaneously
- **Early integration**: Test server startup as soon as basic handlers are ready

### Dependencies for Phase 5
- Connector teams need working server for testing
- Client SDK teams need accessible endpoints
- Testing teams need stable server environment
- All services must be functionally complete