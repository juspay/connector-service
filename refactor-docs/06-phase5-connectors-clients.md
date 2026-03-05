# Phase 5: Connector & Client Updates

## Overview
Update all connector implementations and client SDKs to work with the new proto interfaces. This phase ensures that all external integrations continue to work with the refactored system.

## Completion Target
All connectors work with new proto interfaces. All client SDKs are updated and functional.

## Tasks (Execute in parallel)

### Task 5A: Connector Implementation Updates
**Assigned to**: Sub-agent Alpha  
**Dependencies**: Phase 4 completion

#### Objectives
- Update all connector implementations for new proto message structures
- Update payment method handling for new PaymentMethod oneof structure
- Ensure all connectors work with field renames

#### Steps
1. **Update Adyen Connector**
   ```rust
   // In backend/connector-integration/src/connectors/adyen/transformers.rs
   impl PaymentAuthorizeV2 for Adyen {
       fn build_request(
           &self,
           req: &domain_types::PaymentAuthorizeRequest,
           connectors: &settings::Connectors,
       ) -> ConnectorResult<Option<services::Request>, types::ErrorResponse> {
           // Update for new PaymentMethod structure
           let payment_method_data = match &req.payment_method {
               domain_types::DomainPaymentMethod::Card(card_data) => {
                   self.build_card_payment_request(card_data)?
               }
               domain_types::DomainPaymentMethod::Token(token_data) => {
                   self.build_token_payment_request(token_data)?
               }
               // Handle future payment method types when implemented
           };
           
           // Update for renamed fields
           let adyen_request = AdyenPaymentRequest {
               merchant_account: req.merchant_account_id.clone(),
               amount: AdyenAmount {
                   value: req.minor_amount, // was amount_in_minor_units
                   currency: req.currency.to_string(),
               },
               reference: req.request_ref_id.get_id(), // was connector_request_reference_id
               payment_method: payment_method_data,
               // ... other fields
           };
           
           Ok(Some(services::Request::new(adyen_request, connectors.adyen.base_url.clone())))
       }
   }
   ```

2. **Update Razorpay Connector**
   ```rust
   // In backend/connector-integration/src/connectors/razorpay/transformers.rs
   impl PaymentAuthorizeV2 for Razorpay {
       fn build_request(
           &self,
           req: &domain_types::PaymentAuthorizeRequest,
           connectors: &settings::Connectors,
       ) -> ConnectorResult<Option<services::Request>, types::ErrorResponse> {
           // Similar updates for Razorpay-specific structure
           let payment_method = match &req.payment_method {
               domain_types::DomainPaymentMethod::Card(card) => {
                   RazorpayPaymentMethod::Card {
                       number: card.card_number.clone(),
                       exp_month: card.card_exp_month.clone(),
                       exp_year: card.card_exp_year.clone(),
                       cvv: card.card_cvc.clone(),
                       name: card.card_holder_name.clone(),
                   }
               }
               domain_types::DomainPaymentMethod::Token(token) => {
                   RazorpayPaymentMethod::Token {
                       token: token.token.clone(),
                   }
               }
           };
           
           // ... rest of implementation
       }
   }
   ```

3. **Update Fiserv Connector**
   ```rust
   // In backend/connector-integration/src/connectors/fiserv/transformers.rs
   impl PaymentAuthorizeV2 for Fiserv {
       // Similar pattern for Fiserv-specific requirements
   }
   ```

4. **Update Elavon Connector**
   ```rust
   // In backend/connector-integration/src/connectors/elavon/transformers.rs
   impl PaymentAuthorizeV2 for Elavon {
       // Similar pattern for Elavon-specific requirements
   }
   ```

5. **Update Response Processing**
   ```rust
   // Update all connectors to handle response_ref_id instead of connector_response_reference_id
   impl PaymentAuthorizeV2 for Adyen {
       fn handle_response(
           &self,
           data: &domain_types::PaymentAuthorizeRequest,
           res: types::Response,
       ) -> ConnectorResult<domain_types::PaymentAuthorizeResponse, types::ErrorResponse> {
           let response = AdyenPaymentResponse::from(res);
           
           Ok(domain_types::PaymentAuthorizeResponse {
               transaction_id: domain_types::DomainIdentifier::from_id(response.psp_reference),
               status: self.map_payment_status(response.result_code)?,
               response_ref_id: Some(domain_types::DomainIdentifier::from_id(response.psp_reference)), // was connector_response_reference_id
               // ... other fields
           })
       }
   }
   ```

6. **Update Webhook Handling**
   ```rust
   // Update webhook processors for all connectors
   impl WebhookProcessor for AdyenWebhookProcessor {
       fn process_webhook(
           &self,
           request: &grpc_api_types::RequestDetails,
       ) -> Result<grpc_api_types::WebhookResponseContent, WebhookError> {
           // Parse Adyen webhook
           let adyen_notification = self.parse_adyen_webhook(request)?;
           
           // Convert to unified response format
           match adyen_notification.event_code {
               "AUTHORISATION" => {
                   let payment_response = self.build_payment_response(adyen_notification)?;
                   Ok(grpc_api_types::WebhookResponseContent {
                       content: Some(grpc_api_types::webhook_response_content::Content::PaymentsResponse(payment_response)),
                   })
               }
               "REFUND" => {
                   let refund_response = self.build_refund_response(adyen_notification)?;
                   Ok(grpc_api_types::WebhookResponseContent {
                       content: Some(grpc_api_types::webhook_response_content::Content::RefundsResponse(refund_response)),
                   })
               }
               // ... handle other webhook types
           }
       }
   }
   ```

#### Deliverables
- Updated connector implementations for all supported connectors
- Updated webhook processing for new message structures
- Comprehensive connector tests
- Performance benchmarks for connector operations

#### Acceptance Criteria
- All connectors compile and work with new message structures
- Payment flows work end-to-end for all connectors
- Webhook processing works correctly
- No performance regression

---

### Task 5B: Node.js SDK Updates and Testing
**Assigned to**: Sub-agent Beta  
**Dependencies**: Phase 4 completion

#### Objectives
- Update Node.js SDK for new proto interfaces
- Create new TypeScript type definitions
- Update SDK examples and documentation

#### Steps
1. **Regenerate Proto Files**
   ```bash
   cd sdk/node-grpc-client
   # Update generate-proto.js for new proto structure
   npm run generate-proto
   ```

2. **Update TypeScript Interfaces**
   ```typescript
   // src/types.ts
   export interface PaymentMethod {
     paymentMethod?: {
       card?: CardPaymentMethodType;
       token?: TokenPaymentMethodType;
       // Add other payment method types as they become available
     };
   }
   
   export interface CardPaymentMethodType {
     cardType?: {
       credit?: CardDetails;
       debit?: CardDetails;
       cardRedirect?: CardRedirect;
     };
   }
   
   export interface PaymentAuthorizeRequest {
     requestRefId: Identifier; // was connectorRequestReferenceId
     amount: number;
     currency: Currency;
     minorAmount: number;
     paymentMethod: PaymentMethod;
     // ... other fields with updated names
   }
   ```

3. **Update SDK Client Implementation**
   ```typescript
   // src/payment.ts
   export class PaymentClient {
     async authorize(request: PaymentAuthorizeRequest): Promise<PaymentAuthorizeResponse> {
       // Convert TypeScript types to proto types
       const protoRequest = this.convertToProtoRequest(request);
       
       // Make gRPC call
       const response = await this.grpcClient.authorize(protoRequest);
       
       // Convert proto response to TypeScript types
       return this.convertFromProtoResponse(response);
     }
     
     // Update all other payment methods similarly
     async get(request: PaymentGetRequest): Promise<PaymentGetResponse> { }
     async void(request: PaymentVoidRequest): Promise<PaymentVoidResponse> { }
     async capture(request: PaymentCaptureRequest): Promise<PaymentCaptureResponse> { }
     async refund(request: PaymentRefundRequest): Promise<RefundResponse> { }
     async register(request: PaymentRegisterRequest): Promise<PaymentRegisterResponse> { }
     async dispute(request: PaymentDisputeRequest): Promise<DisputeResponse> { }
   }
   
   export class RefundClient {
     async get(request: RefundGetRequest): Promise<RefundResponse> { }
   }
   
   export class DisputeClient {
     async submitEvidence(request: DisputeSubmitEvidenceRequest): Promise<DisputeSubmitEvidenceResponse> { }
     async get(request: DisputeGetRequest): Promise<DisputeResponse> { }
     async defend(request: DisputeServiceDefendRequest): Promise<DisputeServiceDefendResponse> { }
     async accept(request: DisputeServiceAcceptRequest): Promise<DisputeServiceAcceptResponse> { }
   }
   ```

4. **Create Comprehensive Examples**
   ```typescript
   // examples/card-payment.ts
   import { PaymentClient, CardDetails, PaymentMethod } from '../src';
   
   async function makeCardPayment() {
     const client = new PaymentClient();
     
     const cardDetails: CardDetails = {
       cardNumber: "4111111111111111",
       cardExpMonth: "12",
       cardExpYear: "2025",
       cardCvc: "123",
       cardHolderName: "John Doe"
     };
     
     const paymentMethod: PaymentMethod = {
       paymentMethod: {
         card: {
           cardType: {
             credit: cardDetails
           }
         }
       }
     };
     
     const response = await client.authorize({
       requestRefId: { id: "req_123" },
       amount: 1000,
       currency: Currency.USD,
       minorAmount: 100000,
       paymentMethod: paymentMethod,
       // ... other required fields
     });
     
     console.log('Payment authorized:', response);
   }
   ```

5. **Update Tests**
   ```typescript
   // tests/payment.test.ts
   describe('PaymentClient', () => {
     test('authorize with card payment', async () => {
       const client = new PaymentClient();
       
       const response = await client.authorize({
         // Test with new message structure
       });
       
       expect(response.status).toBeDefined();
       expect(response.transactionId).toBeDefined();
     });
     
     // Add tests for all payment methods and new fields
   });
   ```

#### Deliverables
- Updated Node.js SDK with new proto interfaces
- Complete TypeScript type definitions
- Updated examples and documentation
- Comprehensive test suite

#### Acceptance Criteria
- SDK compiles without TypeScript errors
- All examples work correctly
- Test suite passes completely
- Documentation is up to date

---

### Task 5C: Python SDK Updates and Testing
**Assigned to**: Sub-agent Gamma  
**Dependencies**: Phase 4 completion

#### Objectives
- Update Python SDK for new proto interfaces
- Create new Python type hints and classes
- Update SDK examples and documentation

#### Steps
1. **Regenerate Proto Files**
   ```bash
   cd sdk/python-grpc-client
   make generate
   python -m pip install -e .
   ```

2. **Update Python Client Classes**
   ```python
   # src/python_grpc_client/payment_client.py
   from typing import Optional, Union
   from .generated import payment_pb2, payment_pb2_grpc
   
   class PaymentMethod:
       def __init__(self):
           self.card: Optional[CardPaymentMethodType] = None
           self.token: Optional[TokenPaymentMethodType] = None
   
   class CardPaymentMethodType:
       def __init__(self):
           self.credit: Optional[CardDetails] = None
           self.debit: Optional[CardDetails] = None
           self.card_redirect: Optional[CardRedirect] = None
   
   class PaymentClient:
       def __init__(self, channel):
           self.stub = payment_pb2_grpc.PaymentServiceStub(channel)
       
       async def authorize(self, request: PaymentAuthorizeRequest) -> PaymentAuthorizeResponse:
           # Convert Python types to proto
           proto_request = self._convert_to_proto_authorize_request(request)
           
           # Make gRPC call
           response = await self.stub.Authorize(proto_request)
           
           # Convert proto to Python types
           return self._convert_from_proto_authorize_response(response)
   ```

3. **Create Helper Functions**
   ```python
   # src/python_grpc_client/helpers.py
   def create_card_payment_method(
       card_number: str,
       exp_month: str,
       exp_year: str,
       cvc: str,
       holder_name: Optional[str] = None,
       is_credit: bool = True
   ) -> PaymentMethod:
       card_details = CardDetails(
           card_number=card_number,
           card_exp_month=exp_month,
           card_exp_year=exp_year,
           card_cvc=cvc,
           card_holder_name=holder_name
       )
       
       card_type = CardPaymentMethodType()
       if is_credit:
           card_type.credit = card_details
       else:
           card_type.debit = card_details
       
       payment_method = PaymentMethod()
       payment_method.card = card_type
       
       return payment_method
   
   def create_token_payment_method(token: str) -> PaymentMethod:
       token_type = TokenPaymentMethodType(token=token)
       payment_method = PaymentMethod()
       payment_method.token = token_type
       return payment_method
   ```

4. **Create Comprehensive Examples**
   ```python
   # examples/card_payment_example.py
   import asyncio
   from python_grpc_client import PaymentClient, create_card_payment_method, Currency, Identifier
   
   async def main():
       # Create client
       channel = grpc.aio.insecure_channel('localhost:50051')
       client = PaymentClient(channel)
       
       # Create payment method
       payment_method = create_card_payment_method(
           card_number="4111111111111111",
           exp_month="12",
           exp_year="2025",
           cvc="123",
           holder_name="John Doe"
       )
       
       # Make payment
       response = await client.authorize(PaymentAuthorizeRequest(
           request_ref_id=Identifier(id="req_123"),  # was connector_request_reference_id
           amount=1000,
           currency=Currency.USD,
           minor_amount=100000,
           payment_method=payment_method
       ))
       
       print(f"Payment authorized: {response.transaction_id}")
   
   if __name__ == "__main__":
       asyncio.run(main())
   ```

5. **Update Tests**
   ```python
   # tests/test_payment_client.py
   import pytest
   from python_grpc_client import PaymentClient, create_card_payment_method
   
   @pytest.mark.asyncio
   async def test_card_payment_authorization():
       client = PaymentClient(test_channel)
       
       payment_method = create_card_payment_method(
           card_number="4111111111111111",
           exp_month="12",
           exp_year="2025",
           cvc="123"
       )
       
       response = await client.authorize(PaymentAuthorizeRequest(
           # Test with new message structure
       ))
       
       assert response.status is not None
       assert response.transaction_id is not None
   ```

#### Deliverables
- Updated Python SDK with new proto interfaces
- Complete Python type hints and classes
- Updated examples and documentation
- Comprehensive test suite

#### Acceptance Criteria
- SDK passes mypy type checking
- All examples work correctly
- Test suite passes completely
- Documentation is up to date

---

### Task 5D: Rust Client SDK and Example Updates
**Assigned to**: Sub-agent Delta  
**Dependencies**: Phase 4 completion

#### Objectives
- Update Rust client SDK for new proto interfaces
- Update all example projects
- Ensure examples work with new message structures

#### Steps
1. **Update Rust Client SDK**
   ```rust
   // sdk/rust-grpc-client/src/lib.rs
   use grpc_api_types::{
       payment_service_client::PaymentServiceClient,
       refund_service_client::RefundServiceClient,
       dispute_service_client::DisputeServiceClient,
       PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse,
       // ... other message types
   };
   
   pub struct ConnectorClient {
       payment_client: PaymentServiceClient<tonic::transport::Channel>,
       refund_client: RefundServiceClient<tonic::transport::Channel>,
       dispute_client: DisputeServiceClient<tonic::transport::Channel>,
   }
   
   impl ConnectorClient {
       pub async fn new(endpoint: String) -> Result<Self, Box<dyn std::error::Error>> {
           let channel = tonic::transport::Channel::from_shared(endpoint)?
               .connect()
               .await?;
           
           Ok(Self {
               payment_client: PaymentServiceClient::new(channel.clone()),
               refund_client: RefundServiceClient::new(channel.clone()),
               dispute_client: DisputeServiceClient::new(channel),
           })
       }
       
       pub async fn authorize_payment(
           &mut self,
           request: PaymentServiceAuthorizeRequest,
       ) -> Result<PaymentServiceAuthorizeResponse, tonic::Status> {
           let response = self.payment_client.authorize(request).await?;
           Ok(response.into_inner())
       }
       
       // Add all other payment operations
   }
   ```

2. **Update Rust Examples**
   ```rust
   // examples/example-rs/src/main.rs
   use grpc_api_types::{
       PaymentServiceAuthorizeRequest, PaymentMethod, CardPaymentMethodType, CardDetails,
       Currency, Identifier, payment_method,
   };
   use rust_grpc_client::ConnectorClient;
   
   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       let mut client = ConnectorClient::new("http://localhost:50051".to_string()).await?;
       
       // Create card payment method with new structure
       let card_details = CardDetails {
           card_number: "4111111111111111".to_string(),
           card_exp_month: "12".to_string(),
           card_exp_year: "2025".to_string(),
           card_cvc: "123".to_string(),
           card_holder_name: Some("John Doe".to_string()),
           ..Default::default()
       };
       
       let payment_method = PaymentMethod {
           payment_method: Some(payment_method::PaymentMethod::Card(CardPaymentMethodType {
               card_type: Some(grpc_api_types::card_payment_method_type::CardType::Credit(card_details)),
           })),
       };
       
       let request = PaymentServiceAuthorizeRequest {
           request_ref_id: Some(Identifier { 
               id_type: Some(grpc_api_types::identifier::IdType::Id("req_123".to_string()))
           }),
           amount: 1000,
           currency: Currency::Usd as i32,
           minor_amount: 100000,
           payment_method: Some(payment_method),
           // ... other required fields
           ..Default::default()
       };
       
       let response = client.authorize_payment(request).await?;
       println!("Payment authorized: {:?}", response);
       
       Ok(())
   }
   ```

3. **Update CLI Example**
   ```rust
   // examples/example-cli/src/main.rs
   // Update CLI to use new message structures and field names
   // Add support for new payment method types
   // Update command line argument parsing for new fields
   ```

4. **Update TUI Example**
   ```rust
   // examples/example-tui/src/main.rs
   // Update terminal UI to handle new message structures
   // Add UI elements for new payment method types
   // Update display logic for renamed fields
   ```

5. **Create Comprehensive Tests**
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       
       #[tokio::test]
       async fn test_payment_authorization() {
           let mut client = ConnectorClient::new("http://localhost:50051".to_string()).await.unwrap();
           
           // Test with new message structure
           let response = client.authorize_payment(create_test_request()).await.unwrap();
           
           assert!(response.transaction_id.is_some());
           assert!(response.status != 0);
       }
   }
   ```

#### Deliverables
- Updated Rust client SDK
- Updated all Rust examples (CLI, TUI, basic example)
- Comprehensive test suite
- Updated documentation

#### Acceptance Criteria
- Rust client SDK compiles without warnings
- All examples compile and run correctly
- Test suite passes completely
- Documentation reflects new API structure

---

## Phase 5 Completion Criteria

### Must Complete Before Phase 6
1. All connectors work with new proto interfaces
2. All client SDKs are updated and functional
3. All examples work correctly
4. No regression in connector or client functionality

### Handoff to Phase 6
- **Working connectors** with updated implementations
- **Functional client SDKs** for all supported languages
- **Updated examples** demonstrating new API usage
- **Comprehensive test coverage** for all components

### Risk Mitigation
- **Connector failures**: Extensive testing with real connector endpoints
- **SDK issues**: Cross-platform testing for all SDKs
- **Example problems**: Automated testing of all examples
- **Performance issues**: Performance benchmarking

### Efficiency Focus
- **One connector first**: Get one connector fully working before updating others
- **SDK regeneration first**: Regenerate all SDKs before updating examples
- **Test basic flows**: Focus on authorize/capture/refund flows initially
- **Parallel SDK work**: Update all language SDKs simultaneously

### Dependencies for Phase 6
- Testing team needs working connectors and SDKs
- All components must be functionally complete
- Performance benchmarks must be available
- Documentation must be complete and accurate