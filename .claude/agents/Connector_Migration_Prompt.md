
## **ENHANCED CONNECTOR IMPLEMENTATION PROMPT**

```
I want to implement a complete connector using the enhanced agentic workflow system. Please execute all 9 specialized agents in sequence to implement [CONNECTOR_NAME] connector with [FLOW_TYPES] support.

**Connector Details:**
- Connector Name: [CONNECTOR_NAME] (e.g., Forte, Stripe, Square)
- Payment Flows: [FLOW_TYPES] (e.g., Authorize, Capture, Refund, Void, Sync)
- Payment Methods: [PAYMENT_METHODS] (e.g., Credit Cards, Digital Wallets)
- Authentication Type: [AUTH_TYPE] (HeaderKey, BodyKey, SignatureKey, MultiAuthKey)
- Authentication Keys: [AUTH_KEYS] (JSON object with auth type and required keys)

**Hyperswitch Reference Files:**
- Connector Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/[CONNECTOR_NAME].rs
- Transformer Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/[CONNECTOR_NAME]/transformers.rs

**Execute the following enhanced agents in sequence:**

1. **workflow-logger**: 
   - CREATE workflow_event_log.txt file in project root for event tracking
   - Initialize workflow event logging for [CONNECTOR_NAME] connector implementation
   - Log WORKFLOW_STARTED event with connector details and timestamp
   - Set up event tracking for all subsequent agent activities
   - Provide workflow overview and progress visibility through actual log file

2. **task-analysis-agent**: 
   - CREATE shared_context/ directory structure with actual files
   - Analyze the task "Implement [CONNECTOR_NAME] payment processor connector with [FLOW_TYPES] support"
   - Gather ALL required context upfront (eliminate redundant reads by other agents)
   - Extract TryFrom patterns and macro framework usage from existing connectors
   - CREATE shared_context/project_analysis/existing_connectors_analysis.md
   - CREATE shared_context/connector_patterns/tryFrom_patterns.md
   - CREATE shared_context/connector_patterns/macro_framework_usage.md
   - CREATE shared_context/workflow_context/task_requirements.md
   - Provide comprehensive task breakdown with complexity analysis and implementation strategy
   - Log CONTEXT_GATHERING and SHARED_CONTEXT_CREATED events to workflow_event_log.txt

3. **prd-generation-agent**: 
   - READ shared context files from shared_context/ directory (no redundant file reads)
   - CREATE shared_context/implementation_guide/generated_implementation_guide.md
   - CREATE shared_context/implementation_guide/tryFrom_implementations.md
   - CREATE shared_context/implementation_guide/macro_framework_usage.md
   - Generate dynamic implementation guide based on extracted patterns
   - Create comprehensive Product Requirement Document with TryFrom pattern requirements
   - Include executive summary, technical requirements, and implementation phases
   - Define acceptance criteria, validation strategy, and agent coordination plan
   - Log GUIDE_GENERATION_START and GUIDE_GENERATION_COMPLETE events to workflow_event_log.txt

4. **project-structure-agent**: 
   - READ shared context files for structural change requirements
   - Set up project structure for [CONNECTOR_NAME] connector
   - Add connector to ConnectorEnum in backend/domain_types/src/connector_types.rs
   - Update ForeignTryFrom implementation and Connectors struct
   - Update backend/connector-integration/src/types.rs and connectors.rs
   - Ensure all naming follows established patterns and conventions
   - Log structural changes to workflow_event_log.txt

5. **connector-scaffolding-agent**: 
   - READ shared_context/implementation_guide/generated_implementation_guide.md
   - READ shared_context/connector_patterns/tryFrom_patterns.md
   - READ shared_context/connector_patterns/macro_framework_usage.md
   - Generate [CONNECTOR_NAME] connector boilerplate with proper file structure
   - Create main connector file: backend/connector-integration/src/connectors/[connector_name].rs
   - Create transformer file: backend/connector-integration/src/connectors/[connector_name]/transformers.rs
   - Apply patterns from dynamic implementation guide files
   - Execute scaffolding scripts with pattern integration
   - Log SCAFFOLDING_START and SCAFFOLDING_COMPLETE events to workflow_event_log.txt

6. **unified-transformation-agent**: 
   - READ shared_context/implementation_guide/generated_implementation_guide.md
   - READ shared_context/implementation_guide/tryFrom_implementations.md
   - READ shared_context/connector_patterns/macro_framework_usage.md
   - Apply unified Rust code transformations and TryFrom patterns (replaces rust-transformation-agent and data-transformation-agent)
   - Implement comprehensive data transformation logic for all [FLOW_TYPES]
   - Create request transformations: PaymentsAuthorizeData<T> → [CONNECTOR_NAME]PaymentsRequest<T>
   - Create response transformations: [CONNECTOR_NAME]Response → PaymentsResponseData
   - Handle card data with RawCardNumber<T> for security
   - Apply macro systems: create_all_prerequisites and macro_connector_implementation
   - Ensure proper generic constraints (PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize)
   - Transform function signatures for RouterDataV2 compatibility for all [FLOW_TYPES]
   - Log TRANSFORMATION_START, TRYFORM_IMPLEMENTATION, and TRANSFORMATION_COMPLETE events to workflow_event_log.txt

7. **build-validation-agent**: 
   - READ shared_context/implementation_guide/generated_implementation_guide.md
   - READ shared_context/connector_patterns/tryFrom_patterns.md
   - READ shared_context/workflow_context/task_requirements.md
   - Execute comprehensive validation of [CONNECTOR_NAME] connector implementation
   - Run compilation check: cargo check --package connector-integration
   - Execute build validation: cargo build --release
   - Run test execution: cargo test --package connector-integration
   - Perform code quality analysis: cargo clippy and cargo fmt --check
   - Validate TryFrom pattern compliance and macro framework usage against shared context
   - Provide detailed validation report with context-aware recommendations
   - Log BUILD_VALIDATION_START, BUILD_SUCCESS/BUILD_FAILURE, and VALIDATION_COMPLETE events to workflow_event_log.txt

8. **error-resolution-agent**: 
   - READ workflow_event_log.txt for error correlation
   - READ shared context files for pattern-aware debugging
   - Diagnose and fix any compilation errors or issues found during validation
   - Analyze error messages with pattern-specific knowledge from shared context
   - Identify root causes using context-aware debugging approaches
   - Implement targeted fixes based on extracted patterns from shared context files
   - Validate fixes against shared context requirements
   - Document solutions and provide prevention recommendations
   - Log ERROR_DETECTED, ERROR_RESOLVED, and PREVENTION_DOCUMENTED events to workflow_event_log.txt

9. **test-generation-agent**: 
   - READ shared_context/implementation_guide/generated_implementation_guide.md
   - READ shared_context/workflow_context/task_requirements.md
   - Generate comprehensive test file for [CONNECTOR_NAME] connector
   - Create backend/grpc-server/tests/[connector_name]_payment_flows_test.rs
   - Include tests for all implemented [FLOW_TYPES] (authorize, capture, refund, sync, etc.)
   - Handle authentication using [AUTH_KEYS] configuration
   - Generate proper metadata headers and request builders for connector-specific requirements
   - Include health check, payment flows, error handling, and sandbox environment tests
   - Follow existing test patterns from fiserv_payment_flows_test.rs and authorizedotnet_payment_flows_test.rs
   - Ensure proper async/await patterns and comprehensive error handling
   - Log TEST_GENERATION_START, TEST_CREATION_COMPLETE, and TEST_VALIDATION events to workflow_event_log.txt

**Enhanced Requirements for each agent:**
- Use shared context to eliminate redundant file reads
- Follow extracted patterns from dynamic implementation guide
- Ensure proper TryFrom pattern implementation with generic constraints
- Log key workflow events for visibility and debugging
- Provide detailed reports with context correlation
- Validate all changes against shared context requirements
- Handle errors gracefully with pattern-aware solutions

**Expected Deliverables:**
- Complete [CONNECTOR_NAME] connector implementation with proper TryFrom patterns
- All [FLOW_TYPES] properly implemented with RouterDataV2 compatibility
- Dynamic implementation guide generated at runtime
- Comprehensive workflow event log with progress visibility
- Error-free compilation and successful test execution
- Production-ready code following all extracted patterns
- Shared context repository for future connector implementations

**Workflow Event Log Example:**
```
[15:30:00] WORKFLOW_STARTED: "[CONNECTOR_NAME] connector implementation initiated"
[15:30:05] CONTEXT_GATHERING_START: "Analyzing existing connectors for patterns"
[15:30:15] SHARED_CONTEXT_CREATED: "Created shared context (45 files analyzed)"
[15:30:25] GUIDE_GENERATION_COMPLETE: "Generated [CONNECTOR_NAME]-specific implementation guide"
[15:30:45] SCAFFOLDING_COMPLETE: "Created [connector_name].rs and transformers.rs"
[15:31:40] TRANSFORMATION_COMPLETE: "Applied TryFrom patterns for [FLOW_COUNT] flows"
[15:32:15] BUILD_SUCCESS: "Build completed successfully"
[15:32:25] TEST_GENERATION_START: "Generating comprehensive test suite"
[15:32:45] TEST_CREATION_COMPLETE: "Created [connector_name]_payment_flows_test.rs with [FLOW_COUNT] flow tests"
[15:32:50] WORKFLOW_COMPLETE: "[CONNECTOR_NAME] connector implementation finished"
```

Please execute this enhanced workflow and provide detailed reports with event logging from each agent.
```

---

## **Usage Examples:**

### Example 1: Forte Connector with Multiple Flows
```
I want to implement a complete connector using the enhanced agentic workflow system. Please execute all 9 specialized agents in sequence to implement Forte connector with Authorize, Refund, Sync support.

**Connector Details:**
- Connector Name: Forte
- Payment Flows: Authorize, Refund, Sync
- Payment Methods: Credit Cards (Visa, MasterCard, American Express)
- Authentication Type: MultiAuthKey
- Authentication Keys: {
    "auth_type": "multi-auth-key",
    "api_key": "0ec774886e654a66c2e46854b0f4f002",
    "api_secret": "38ee65bc05ffb5b6bee7e70bf115a71c",
    "key1": "438530",
    "key2": "316671"
  }

**Hyperswitch Reference Files:**
- Connector Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/forte.rs
- Transformer Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/forte/transformers.rs

[Execute all 9 agents as specified in the main prompt...]
```

### Example 2: Stripe Connector with Multiple Flows
```
I want to implement a complete connector using the enhanced agentic workflow system. Please execute all 9 specialized agents in sequence to implement Stripe connector with Authorize, Capture, Refund, and Void support.

**Connector Details:**
- Connector Name: Stripe
- Payment Flows: Authorize, Capture, Refund, Void
- Payment Methods: Credit Cards, Digital Wallets (Apple Pay, Google Pay)
- Authentication Type: HeaderKey
- Authentication Keys: {
    "auth_type": "header-key",
    "api_key": "sk_test_xxxxxxxxxxxxxxxxxxxx"
  }

**Hyperswitch Reference Files:**
- Connector Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/stripe.rs
- Transformer Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/stripe/transformers.rs

[Execute all 9 agents as specified in the main prompt...]
```

### Example 3: PayPal Connector
```
I want to implement a complete connector using the enhanced agentic workflow system. Please execute all 9 specialized agents in sequence to implement PayPal connector with Authorize, Capture, and Refund support.

**Connector Details:**
- Connector Name: PayPal
- Payment Flows: Authorize, Capture, Refund
- Payment Methods: PayPal Wallet, Credit Cards
- Authentication Type: BodyKey
- Authentication Keys: {
    "auth_type": "body-key",
    "api_key": "client_id_xxxxxxxxxxxx",
    "key1": "client_secret_xxxxxxxxxxxx"
  }

**Hyperswitch Reference Files:**
- Connector Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/paypal.rs
- Transformer Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/paypal/transformers.rs

[Execute all 9 agents as specified in the main prompt...]
```

## **Customization Instructions:**

1. **Replace placeholders** with your specific connector details:
   - `[CONNECTOR_NAME]` → Your connector name (e.g., Forte, Stripe, Square) - this will auto-populate Hyperswitch reference URLs
   - `[FLOW_TYPES]` → Required flows (e.g., Authorize, Capture, Refund, Sync)
   - `[PAYMENT_METHODS]` → Supported payment methods
   - `[AUTH_TYPE]` → Authentication type (HeaderKey, BodyKey, SignatureKey, MultiAuthKey)
   - `[AUTH_KEYS]` → Authentication keys JSON object with connector-specific credentials

2. **Authentication Keys Format Examples:**
   - **HeaderKey**: `{"auth_type": "header-key", "api_key": "sk_test_xxxxxxxxxxxx"}`
   - **BodyKey**: `{"auth_type": "body-key", "api_key": "client_id", "key1": "client_secret"}`
   - **SignatureKey**: `{"auth_type": "signature-key", "api_key": "xxx", "key1": "yyy", "api_secret": "zzz"}`
   - **MultiAuthKey**: `{"auth_type": "multi-auth-key", "api_key": "xxx", "api_secret": "yyy", "key1": "zzz", "key2": "aaa"}`

3. **Hyperswitch Reference URLs** are automatically generated using the connector name:
   - Connector file: `https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/[CONNECTOR_NAME].rs`
   - Transformer file: `https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/[CONNECTOR_NAME]/transformers.rs`

4. **Copy the complete prompt** and paste it into your Claude Code chat

5. **Wait for each agent** to complete before the next one starts

6. **Review reports** from each agent to ensure quality

7. **Address any issues** identified by the error-resolution-agent

## **Quick Start Template:**

For immediate use, copy and customize this template:

```
I want to implement a complete connector using the enhanced agentic workflow system. Please execute all 9 specialized agents in sequence to implement [CONNECTOR_NAME] connector with [FLOW_TYPES] support.

**Connector Details:**
- Connector Name: [CONNECTOR_NAME]
- Payment Flows: [FLOW_TYPES]
- Payment Methods: [PAYMENT_METHODS]
- Authentication Type: [AUTH_TYPE]
- Authentication Keys: [AUTH_KEYS]

**Hyperswitch Reference Files:**
- Connector Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/[CONNECTOR_NAME].rs
- Transformer Implementation: https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/[CONNECTOR_NAME]/transformers.rs

[Execute all 9 agents as specified in the main prompt above...]
```
