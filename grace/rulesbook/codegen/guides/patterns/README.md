# UCS Connector Implementation Patterns

This directory contains comprehensive implementation patterns for each payment flow in the UCS (Universal Connector Service) system. Each pattern file provides complete, reusable templates that can be consumed by AI to generate consistent, production-ready connector code.

## 📚 Available Patterns

### Core Payment Flows

| Pattern File | Flow Type | Status | Description |
|-------------|-----------|---------|-------------|
| [`pattern_authorize.md`](./pattern_authorize.md) | **Authorization** | ✅ Complete | Complete authorization flow patterns for any payment connector |
| [`pattern_capture.md`](./pattern_capture.md) | **Capture** | ✅ Complete | Comprehensive capture flow patterns and implementations |
| [`pattern_psync.md`](./pattern_psync.md) | **Payment Sync** | ✅ Complete | Payment status synchronization (Psync) flow patterns across 22 connectors |
| `pattern_void.md` | **Void/Cancel** | ✅ Complete | Void payment authorization patterns |
| `pattern_refund.md` | **Refund** | ✅ Complete | Full and partial refund flow patterns |
| `pattern_rsync.md` | **Refund Sync** | ✅ Complete | Refund status synchronization patterns |

### Advanced Flows

| Pattern File | Flow Type | Status | Description |
|-------------|-----------|---------|-------------|
| `pattern_webhook.md` | **Webhooks** | 🚧 Planned | Webhook handling and signature verification patterns |
| [`pattern_setup_mandate.md`](./pattern_setup_mandate.md) | **SetupMandate** | ✅ Complete | Comprehensive SetupMandate flow patterns for recurring payments across 8 connectors |
| [`repeat_payment_flow_patterns.md`](./repeat_payment_flow_patterns.md) | **RepeatPayment** | ✅ Complete | Comprehensive RepeatPayment flow patterns for processing recurring payments using stored mandates across 7 connectors |
| `pattern_dispute.md` | **Disputes** | 🚧 Planned | Dispute handling and evidence submission patterns |
| `pattern_session.md` | **Session Token** | 🚧 Planned | Secure session management patterns |
| `pattern_order.md` | **Create Order** | 🚧 Planned | Multi-step payment initiation patterns |

## 🎯 Pattern Usage

### For New Implementations
1. **Choose the appropriate pattern file** for your flow
2. **Replace placeholders** with connector-specific values
3. **Follow the integration checklist** in each pattern
4. **Test using provided test patterns**

### For Resuming Partial Work
1. **Reference existing implementation** against pattern
2. **Identify missing components** using the checklists
3. **Apply pattern templates** for missing flows
4. **Ensure consistency** with existing code style

### AI Integration Commands
```bash
# Use specific patterns for implementation
implement authorization flow for [ConnectorName] using pattern_authorize.md
add capture flow to [ConnectorName] using pattern_capture.md
implement setup mandate flow for [ConnectorName] using pattern_setup_mandate.md
add repeat payment flow to [ConnectorName] using repeat_payment_flow_patterns.md
implement webhooks for [ConnectorName] using pattern_webhook.md
```

## 📖 Pattern Structure

Each pattern file follows a consistent structure:

### 1. **Quick Start Guide**
- Placeholder replacement guide
- Example implementations
- Time-to-completion estimates

### 2. **Implementation Analysis**
- Real-world connector analysis
- Implementation statistics
- Common patterns identified

### 3. **Modern Macro-Based Pattern**
- Recommended implementation approach
- Complete code templates
- Type-safe implementations

### 4. **Legacy Manual Pattern**
- Alternative implementation style
- Reference for special cases
- Backward compatibility

### 5. **Specific Patterns**
- Request/response structures
- URL endpoint patterns
- Authentication methods
- Error handling strategies

### 6. **Testing & Validation**
- Unit test templates
- Integration test patterns
- Validation checklists

### 7. **Integration Checklist**
- Pre-implementation requirements
- Step-by-step implementation guide
- Quality validation steps

## 🔄 Pattern Evolution

### Current Focus (Phase 1)
- ✅ **Authorization patterns** - Complete and battle-tested
- ✅ **Capture patterns** - Comprehensive coverage of 8+ connectors
- 🚧 **Void patterns** - Next priority
- 🚧 **Refund patterns** - Following void

### Future Expansion (Phase 2)
- Webhook and event handling patterns
- Advanced payment method patterns
- Regional payment method patterns
- Performance optimization patterns

### Continuous Improvement
- Patterns are updated based on new connector implementations
- Real-world usage feedback incorporated
- Best practices evolved from production experience
- New connector API patterns integrated

## 💡 Contributing to Patterns

When implementing new connectors or flows:

1. **Document new patterns** discovered during implementation
2. **Update existing patterns** with improvements or edge cases
3. **Add real-world examples** to pattern files
4. **Enhance checklists** based on implementation experience

## 🎨 Pattern Quality Standards

All pattern files maintain:

- **🎯 Completeness**: Cover all aspects of flow implementation
- **📖 Clarity**: Clear explanations and examples
- **🔄 Reusability**: Templates work for any connector
- **✅ Validation**: Comprehensive testing and quality checks
- **🏗️ UCS-specific**: Tailored for UCS architecture and patterns
- **🚀 Production-ready**: Battle-tested in real implementations

## 🔗 Related Documentation

### Integration & Implementation
- [`../connector_integration_guide.md`](../connector_integration_guide.md) - Complete UCS integration process
- [`../types/types.md`](../types/types.md) - UCS type system reference
- [`../learnings/learnings.md`](../learnings/learnings.md) - Implementation lessons learned
- [`../../README.md`](../../README.md) - GRACE-UCS overview and usage

### Quality & Standards
- [`../feedback.md`](../feedback.md) - Quality feedback database and review template
- [`../quality/README.md`](../quality/README.md) - Quality system overview
- [`../quality/CONTRIBUTING_FEEDBACK.md`](../quality/CONTRIBUTING_FEEDBACK.md) - Guide for adding quality feedback

**🛡️ Quality Note**: All implementations using these patterns are reviewed by the Quality Guardian Subagent to ensure UCS compliance and code quality. Review common issues in `feedback.md` before implementing to avoid known anti-patterns.

---

**💡 Pro Tip**: Always start with the pattern file that matches your target flow. The patterns are designed to be self-contained and provide everything needed for implementation.