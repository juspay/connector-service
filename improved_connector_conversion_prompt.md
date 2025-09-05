# Improved Connector Conversion Prompt

## Enhanced Prompt for Converting Hyperswitch Connectors to Connector Service

Use this improved prompt for converting connectors like Forte and others:

---

**CONTEXT**: You are converting the {CONNECTOR_NAME} connector from Hyperswitch to the connector service architecture. Use the comprehensive gap analysis from `forte_connector_comparison_analysis.md` as your reference guide for understanding the key differences and requirements.

**PRIMARY OBJECTIVE**: Convert the {CONNECTOR_NAME} connector following the step-by-step instructions in `connectorImplementationGuide.md`, but with enhanced focus on bridging the gaps identified in the analysis.

**EXECUTION STRATEGY**:

1. **Pre-Implementation Analysis** (Steps 1-7):
   - Follow `connectorImplementationGuide.md` steps 1-7 for basic setup
   - Reference the gap analysis to understand what specific enums, types, and structures need to be implemented
   - Pay special attention to authentication mechanisms (organization_id, location_id vs simple API key)

2. **Core Implementation** (Steps 8-60):
   - Execute `connectorImplementationGuide.md` steps 8-60 for the core flows: Authorize, PSync, Capture, Void, Refund, RSync
   - **CRITICAL**: After every 5-10 steps, pause and compare your implementation with the Hyperswitch version at: https://github.com/juspay/hyperswitch/blob/f57468d9389111d6eba666b0acd529c87a85e2c7/crates/hyperswitch_connectors/src/connectors/{connector_name}.rs
   - Use the Gap Detection Agent to identify specific differences in:
     - Authentication patterns (simple API key vs org/location IDs)
     - Request/response structures (missing fields, different field names)
     - Status mapping logic (granular vs basic status codes)
     - Error handling approaches (comprehensive vs simple error responses)
     - API endpoint patterns (simple vs complex URL structures)

3. **Gap-Specific Enhancements**:
   Based on the analysis, ensure you implement:
   - **Enhanced Authentication**: If Hyperswitch uses org/location IDs, implement the complex auth pattern
   - **Missing Enums**: Add connector-specific enums like `{Connector}PaymentStatus`, `{Connector}TransactionType`, etc.
   - **Comprehensive Request Structures**: Include billing information, customer data, transaction metadata
   - **Enhanced Error Handling**: Implement detailed error response parsing and categorization
   - **Status Mapping**: Add granular status differentiation beyond basic succeeded/pending/failed
   - **Payment Method Support**: Ensure support for all card networks and payment methods from Hyperswitch

4. **Transformers Enhancement** (Steps 61-119):
   - Follow transformers conversion steps but enhance based on gap analysis
   - Ensure request/response structures match Hyperswitch complexity
   - Implement proper generic type handling for payment methods
   - Add missing fields identified in the gap analysis

5. **Error Resolution** (Step 122):
   - When encountering build errors, reference `connectorErrorFixGuide.md`
   - Use the Gap Fixing Agent to resolve implementation gaps
   - Focus on errors related to missing types, authentication patterns, and API structure differences

6. **Testing** (Step 123):
   - Follow `ai_generate_test.md` for test generation
   - Ensure tests cover the enhanced functionality identified in gap analysis
   - Test complex authentication scenarios if applicable

**GAP DETECTION AGENT USAGE**:
After every 5-10 implementation steps, run gap detection with these specific focus areas:
- Authentication mechanism differences
- Request/response structure completeness
- Status mapping comprehensiveness
- Error handling sophistication
- API endpoint pattern complexity
- Payment method support coverage

**GAP FIXING AGENT USAGE**:
When gaps are identified, prioritize fixes in this order:
1. Authentication and security-related gaps
2. Core payment flow functionality gaps
3. Error handling and status mapping gaps
4. Enhanced features and metadata gaps

**CHANGELOG MAINTENANCE**:
Document every step in `Changelog.md` with:
- What was implemented/modified
- Which gaps were addressed
- Files changed
- Issues encountered and resolutions
- Comparison notes with Hyperswitch implementation

**SUCCESS CRITERIA**:
- All 6 flows (Authorize, PSync, Capture, Void, Refund, RSync) implemented
- Authentication mechanism matches Hyperswitch complexity
- Request/response structures include all fields from Hyperswitch
- Status mapping covers all Hyperswitch status codes
- Error handling matches Hyperswitch sophistication
- Build completes successfully
- Tests pass for all implemented flows

**CONNECTOR-SPECIFIC CUSTOMIZATION**:
Replace {CONNECTOR_NAME} with the actual connector name (e.g., "forte", "adyen", "stripe") and adjust the Hyperswitch URL accordingly.

---

## Key Improvements in This Prompt:

1. **Gap-Aware Approach**: Leverages the specific gap analysis for targeted implementation
2. **Structured Comparison**: Regular comparison checkpoints with Hyperswitch implementation
3. **Prioritized Gap Fixing**: Clear priority order for addressing identified gaps
4. **Enhanced Focus Areas**: Specific attention to authentication, error handling, and API complexity
5. **Agent Integration**: Clear instructions for when and how to use Gap Detection and Gap Fixing agents
6. **Success Metrics**: Concrete criteria for successful conversion
7. **Reusable Template**: Easy to customize for different connectors

This approach should significantly improve your conversion success rate by being more targeted and gap-aware.