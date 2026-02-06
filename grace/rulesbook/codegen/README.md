# Global Rapid Agentic Connector Exchange for UCS (GRACE-UCS)

GRACE-UCS is a specialized AI-assisted system for UCS (Universal Connector Service) connector development that supports **complete connector lifecycle management** - from initial implementation to continuation of partially completed work.

## 🎯 Core Purpose

GRACE-UCS enables:
- **Full connector implementation** from scratch
- **Resuming partial implementations** where developers left off
- **All payment method support** (cards, wallets, bank transfers, BNPL, etc.)
- **Complete flow coverage** (authorize, capture, void, refund, sync, webhooks, etc.)
- **UCS-specific patterns** tailored for gRPC-based stateless architecture

## 🏗️ UCS Architecture Overview

The UCS connector-service uses a modern, stateless architecture:

```
backend/
├── connector-integration/     # Connector-specific logic
│   ├── src/connectors/       # Individual connector implementations
│   └── src/types.rs          # Common types and utilities
├── domain-types/             # Domain models and data structures
├── grpc-server/             # gRPC service implementation
└── grpc-api-types/          # Protocol buffer definitions
```

### Key UCS Characteristics:
- **gRPC-first**: All communication via Protocol Buffers
- **Stateless**: No database dependencies in connector logic
- **RouterDataV2**: Enhanced type-safe data flow
- **ConnectorIntegrationV2**: Modern trait-based integration
- **Domain-driven**: Clear separation of concerns

## 🚀 Usage Scenarios

### 1. **New Connector Implementation**
```
integrate [ConnectorName] using grace-ucs/.gracerules
```

### 2. **Resume Partial Implementation**
```
continue implementing [ConnectorName] connector in UCS - I have partially implemented [specific_flows] and need to complete [remaining_flows]
```

### 3. **Add Missing Flows**
```
add [flow_names] flows to existing [ConnectorName] connector in UCS
```

### 4. **Debug/Fix Issues**
```
fix [ConnectorName] connector issues in UCS - having problems with [specific_issue_description]
```

### 5. **Add Payment Methods**
```
add support for [payment_method_types] to [ConnectorName] connector in UCS
```

## 📋 Comprehensive Flow Support

### Core Payment Flows
- **Authorization** - Initial payment authorization
- **Capture** - Capture authorized payments
- **Void/Cancel** - Cancel authorized payments
- **Refund** - Full and partial refunds
- **Sync** - Payment status synchronization
- **Refund Sync** - Refund status synchronization

### Advanced Flows
- **Create Order** - Multi-step payment initiation
- **Session Token** - Secure payment session management
- **Setup Mandate** - Recurring payment setup
- **Webhook Handling** - Real-time payment notifications
- **Dispute Management** - Handle chargebacks and disputes

### Payment Method Coverage
- **Cards** - Credit/Debit (Visa, Mastercard, Amex, etc.)
- **Digital Wallets** - Apple Pay, Google Pay, PayPal, etc.
- **Bank Transfers** - ACH, SEPA, Open Banking
- **Buy Now Pay Later** - Klarna, Afterpay, Affirm
- **Cryptocurrencies** - Bitcoin, Ethereum, stablecoins
- **Regional Methods** - UPI, Alipay, WeChat Pay, etc.
- **Cash/Vouchers** - Boleto, OXXO, convenience store payments

## 🛠️ Implementation States

GRACE-UCS tracks and can resume from any implementation state:

### State 1: **Initial Setup**
- Basic connector structure created
- Auth configuration defined
- Base trait implementations stubbed

### State 2: **Core Flows Implemented**
- Authorization flow working
- Basic error handling in place
- Request/response transformations for primary flow

### State 3: **Extended Flows**
- Capture, void, refund flows implemented
- Sync operations working
- Status mapping complete

### State 4: **Payment Methods**
- Multiple payment method support
- Proper validation and transformation
- Payment method specific handling

### State 5: **Advanced Features**
- Webhook implementation
- 3DS handling
- Mandate/recurring support
- Comprehensive error handling

### State 6: **Production Ready**
- Full test coverage
- All edge cases handled
- Performance optimized
- Documentation complete

## 📖 How to Use GRACE

### For New Implementation:
1. Place connector API documentation in `grace/rulesbook/codegen/references/{{connector_name}}/`
2. Run: `integrate [ConnectorName] using .gracerules`
3. AI will create complete implementation plan and code

### For Resuming Work:
1. Describe current state: "I have [existing_functionality] implemented"
2. Specify what you need: "Need to add [missing_functionality]"
3. AI will analyze existing code and continue from there

### For Debugging:
1. Describe the issue: "Getting [error_description] when [specific_scenario]"
2. AI will analyze code, identify issue, and provide fix

## 🔧 UCS-Specific Patterns

GRACE-UCS provides dedicated pattern files for each payment flow:

### Available Flow Patterns
- **📖 `guides/patterns/README.md`** - Pattern directory index and usage guide
- **✅ `guides/patterns/pattern_authorize.md`** - Complete authorization flow patterns and implementations
- **✅ `guides/patterns/pattern_capture.md`** - Comprehensive capture flow patterns and examples
- **🚧 Future patterns**: void, refund, sync, webhook, dispute flows

### Pattern Usage
Each pattern file provides:
- **🎯 Quick Start Guide** with placeholder replacement examples
- **📊 Real-world Analysis** from existing connector implementations
- **🏗️ Modern Macro-Based Templates** for consistent implementations
- **🔧 Legacy Manual Patterns** for special cases
- **🧪 Testing Strategies** and integration checklists
- **✅ Validation Steps** and quality checks

### Using Patterns with AI
```bash
# Use specific patterns for targeted implementation
implement authorization flow for NewPayment using pattern_authorize.md
add capture flow to ExistingConnector using pattern_capture.md
implement complete connector flows using guides/patterns/ directory
```

### Connector Structure
```rust
// Main connector file: backend/connector-integration/src/connectors/connector_name.rs
impl ConnectorIntegrationV2<Flow, Request, Response> for ConnectorName {
    // UCS-specific implementations using patterns from guides/patterns/
}

// Transformers: backend/connector-integration/src/connectors/connector_name/transformers.rs
// Request/response transformations for all payment methods and flows
```

### Data Flow
```
gRPC Request → RouterDataV2 → Connector Transform → HTTP Request → External API
External Response → Connector Transform → RouterDataV2 → gRPC Response
```

## 📁 Directory Structure

```
grace/rulbook/codegen/
├── .gracerules                          # Main AI instructions
├── README.md                            # This file
├── guides/
│   ├── feedback.md                      # Quality feedback database with review template
│   ├── quality/                         # Quality system documentation
│   │   ├── README.md                    # Quality system overview
│   │   ├── quality_review_template.md   # Standalone review template
│   │   └── CONTRIBUTING_FEEDBACK.md     # Guide for adding feedback entries
│   ├── connector_integration_guide.md   # Step-by-step UCS integration
│   ├── patterns/                        # Flow-specific UCS patterns
│   │   ├── README.md                    # Pattern directory index and usage guide
│   │   ├── pattern_authorize.md         # Authorization flow patterns
│   │   └── pattern_capture.md           # Capture flow patterns
│   ├── learnings/learnings.md           # Lessons from UCS implementations
│   ├── types/types.md                   # UCS type system guide
│   └── integrations/integrations.md     # Previous UCS integrations
├── connector_integration/
│   └── template/
│       ├── tech_spec.md                 # UCS technical specification template
│       └── planner_steps.md             # UCS implementation planning template
└── references/
    └── {{connector_name}}/               # Connector-specific documentation
        ├── api_docs.md
        ├── payment_flows.yaml
        └── webhook_spec.json
```

## 🎯 Key Benefits

1. **Resumable Development**: Pick up exactly where you left off
2. **Complete Coverage**: All payment methods and flows supported
3. **UCS-Optimized**: Patterns specific to UCS architecture
4. **AI-Assisted**: Intelligent code generation and problem solving
5. **Quality Assured**: Automated quality reviews ensure high code standards
6. **Production-Ready**: Follows UCS best practices and patterns
7. **Extensible**: Easy to add new flows and payment methods
8. **Continuous Learning**: Feedback system captures and applies lessons learned

## 🚀 Getting Started

### Prerequisites

**Configure Cypress Credentials (One-Time Setup)**:
1. Create `grace/.env` from the template:
   ```bash
   cp grace/.env.example grace/.env
   ```
2. Edit `grace/.env` and fill in your credentials:
   - `CYPRESS_ADMINAPIKEY`: Admin API key for https://integ.hyperswitch.io
   - `CYPRESS_CONNECTOR_AUTH_FILE_PATH`: Path to your connector credentials JSON file
   - `CYPRESS_BASEURL`: API base URL (default: https://integ.hyperswitch.io/api)

### For New Implementation:
1. **Pre-Flight Check (Phase 0)**: The workflow automatically validates the connector's no_three_ds support
   - Runs `grace/rulesbook/codegen/validate_connector_cypress.sh {connector_name}`
   - Uses credentials from `grace/.env` (prompts if missing)
   - Tests validate that the source connector works correctly in Hyperswitch
   - **Critical Decision Gate**: Workflow only continues if tests pass
   - **Time Saver**: Catches issues early before code generation begins
2. Place connector API documentation in `grace/rulebook/codegen/references/{{connector_name}}/`
3. Run: `integrate [ConnectorName] using .gracerules`
4. AI will validate connector, create implementation plan, and generate code

### For Resuming Work:
1. Describe current state: "I have [existing_functionality] implemented"
2. Specify what you need: "Need to add [missing_functionality]"
3. AI will analyze existing code and continue from there

### For Debugging:
1. Describe the issue: "Getting [error_description] when [specific_scenario]"
2. AI will analyze code, identify issue, and provide fix

GRACE-UCS makes UCS connector development efficient, comprehensive, and resumable at any stage.

---

## 🛡️ Quality Enforcement System

GRACE-UCS includes an automated **Quality Guardian Subagent** (8th subagent) that ensures every connector meets high quality standards.

### Quality Review Process

```
Phase 0: Pre-Flight Validation (Cypress Tests) → Continue/Abort Decision
   ↓ (If Continue)
Foundation → Flow Implementation → All Flows Complete → Cargo Build ✅
                                                              ↓
                                                    Quality Guardian Review
                                                              ↓
                                        Quality Score ≥ 60? ──┬── Yes → ✅ Approved
                                                              │
                                                              └── No → ❌ Blocked (Fix Required)
```

### When Quality Review Runs

The Quality Guardian activates **ONCE** after all flows are implemented and code compiles successfully:
- ✅ All 6 flows completed (Authorize, PSync, Capture, Refund, RSync, Void)
- ✅ Cargo build passes without errors
- 🛡️ Quality Guardian performs comprehensive review
- ⚖️ Quality score calculated based on UCS compliance

### Quality Scoring System

```
Quality Score = 100 - (Critical Issues × 20) - (Warnings × 5) - (Suggestions × 1)

Thresholds:
95-100: Excellent ✨ - Auto-approve, document success patterns
80-94:  Good ✅ - Approve with minor notes
60-79:  Fair ⚠️ - Approve with warnings, recommend fixes
40-59:  Poor ❌ - Block until critical issues fixed
0-39:   Critical 🚨 - Block immediately, requires rework
```

### What Gets Reviewed

**UCS Pattern Compliance:**
- RouterDataV2 usage (not RouterData)
- ConnectorIntegrationV2 usage (not ConnectorIntegration)
- domain_types imports (not hyperswitch_*)
- Generic connector struct pattern

**Code Quality:**
- No code duplication across flows
- Consistent error handling
- Proper status mapping
- Payment method support
- Cross-flow consistency

**Security & Performance:**
- No exposed credentials
- Efficient resource usage
- Proper input validation
- Security best practices

### Feedback Database

All quality issues and success patterns are captured in `guides/feedback.md`:

```
guides/feedback.md
├── Quality Review Template (for generating reports)
├── Section 1: Critical Patterns (Must Follow)
├── Section 2: UCS-Specific Guidelines
├── Section 3: Flow-Specific Best Practices
├── Section 4: Payment Method Patterns
├── Section 5: Common Anti-Patterns
├── Section 6: Success Patterns
└── Section 7: Historical Feedback Archive
```

**Benefits of the Feedback System:**
- 📚 Learn from past issues before implementing
- 🎯 Targeted guidance for common problems
- 📈 Continuous improvement over time
- ✨ Success pattern library for best practices

### Quality Documentation

For detailed information about the quality system:

- **[guides/quality/README.md](guides/quality/README.md)** - Complete quality system overview
- **[guides/quality/quality_review_template.md](guides/quality/quality_review_template.md)** - Standalone review template
- **[guides/quality/CONTRIBUTING_FEEDBACK.md](guides/quality/CONTRIBUTING_FEEDBACK.md)** - How to add feedback entries
- **[guides/feedback.md](guides/feedback.md)** - Main feedback database

---

# grace-ucs
