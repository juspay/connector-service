# Refactor Quick Reference Guide

## Goal
Implement new proto interface definitions efficiently with maximum parallel execution.

## Strategy
**Get it working first, optimize later**. Focus on rapid iteration and immediate testing.

## Phases Overview

```
Phase 1: Infrastructure ──→ Phase 2: Proto Integration ──→ Phase 3: Domain Types
    ↓                           ↓                             ↓
  Setup                     Generate Code                 Conversions
  Validate                  Compile                       Test
  
Phase 4: Server Implementation ──→ Phase 5: Connectors & Clients ──→ Phase 6: Testing
    ↓                                ↓                                ↓
  Handlers                         Update All                       Validate
  Endpoints                        Integrations                     Go-Live
```

## Execution Rules

### ✅ DO
- **Work in parallel** within each phase
- **Test immediately** when dependencies are ready
- **Get basic functionality** working before optimizing
- **Communicate blockers** as soon as they occur
- **Move fast** through phases sequentially

### ❌ DON'T
- Wait for perfect implementations
- Work on phases out of order
- Optimize before functionality works
- Let blockers persist without escalation
- Work in isolation without communication

## Phase Completion Targets

| Phase | Target | Key Deliverable |
|-------|--------|----------------|
| **1** | Proto files validate and build system ready | Working proto compilation |
| **2** | All generated code compiles | Functional gRPC server startup |
| **3** | All conversions implemented | No compilation errors in domain types |
| **4** | All handlers working | Server serves all endpoints |
| **5** | All integrations updated | Connectors and SDKs functional |
| **6** | All tests pass | System ready for production |

## Sub-Agent Assignments

| Agent | Specialization | Primary Focus |
|-------|---------------|---------------|
| **Alpha** | Core Implementation | Complex business logic, integration |
| **Beta** | Infrastructure | Build systems, server implementation |
| **Gamma** | Multi-Service | Cross-service integration, multi-language |
| **Delta** | Examples & Docs | Examples, documentation, validation |

## Critical Dependencies

```
Phase 1 → Phase 2: Proto validation complete
Phase 2 → Phase 3: Generated code compiles
Phase 3 → Phase 4: Domain conversions working
Phase 4 → Phase 5: Server endpoints functional
Phase 5 → Phase 6: All components integrated
```

## Communication Protocol

### Rapid Check-ins (Every few hours)
- What's working?
- What's blocked?
- What do you need?

### Immediate Escalation
- Build failures
- Blocking dependencies
- Integration failures
- Performance regressions

## Success Criteria

### Phase Gates
1. **Compilation**: All code compiles without errors
2. **Functionality**: Basic operations work end-to-end
3. **Integration**: Components work together
4. **Testing**: Critical paths are validated
5. **Performance**: No significant regression

### Final Success
- All tests pass ✅
- All connectors work ✅
- All SDKs functional ✅
- Performance baseline met ✅
- Documentation complete ✅

## Efficiency Tips

### Phase 1
- Validate proto syntax first
- Test compilation immediately
- Setup tooling in parallel

### Phase 2
- Get compilation working before optimization
- Test server startup ASAP
- Generate all SDKs simultaneously

### Phase 3
- Implement core conversions first
- Test each conversion immediately
- Reuse patterns across types

### Phase 4
- Stub all handlers first
- Test endpoints as implemented
- Work on services in parallel

### Phase 5
- Get one connector working first
- Regenerate all SDKs before examples
- Test basic flows immediately

### Phase 6
- Test critical paths first
- Run tests in parallel
- Document as you validate

## Emergency Contacts

| Issue Type | Response Time | Action |
|------------|---------------|---------|
| Build Failures | Immediate | Stop work, fix build |
| Blocking Dependencies | 1 hour | Escalate, find workaround |
| Integration Failures | 2 hours | All-hands debugging |
| Performance Issues | 4 hours | Baseline and optimize |

---

**Remember**: Speed over perfection. Get it working, then make it better.