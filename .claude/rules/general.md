# General Project Rules

## Connector Service Overview

Universal Connector Service (UCS) for payment connector integrations using macro-based Rust architecture.

## Quick Start

```bash
# Integrate a connector (complete end-to-end)
/connector-integrate stripe https://stripe.com/docs/api

# Or let it auto-discover the docs
/connector-integrate adyen
```

## System Agents

1. **Research Agent** - Scrapes API documentation, creates technical spec
2. **Planning Agent** - Interactive validation, maps to UCS patterns
3. **Implementation Agent** - Generates Rust code, handles build errors
4. **Reviewer Agent** - Scores code quality, creates feedback loops

## Key Directories

| Directory | Purpose |
|-----------|---------|
| `.claude/rules/` | Modular project rules (this directory) |
| `.claude/skills/` | Auto-activating skill definitions |
| `.claude/commands/` | Slash command definitions |
| `.claude/context/` | Runtime connector specs and metrics |
| `.claude/memory/` | Cross-session learnings (deprecated → use rules/) |

## External References

- **Grace Rulesbook**: `/Users/uzair.khan/grace/rulesbook/codegen/`
- **Hyperswitch**: `/Users/uzair.khan/hyperswitch/crates/router/src/connector/`
- **Existing Connectors**: `backend/connector-integration/src/connectors/`

## Code Standards

- Use Rust 2021 edition
- Follow macro-based implementation patterns
- Run `cargo build` and `cargo clippy` before submission
- All connector code in `backend/connector-integration/src/connectors/`

## Documentation Patterns

### Connectors Overview

The connectors overview documentation (`docs/connectors/README.md`) maintains a matrix of all connectors and their integration status across different services:

**Status Definitions:**
- ![Integrated](https://img.shields.io/badge/-integrated-blue) - Code and transformers are available in `/connectors` folder
- ![Tested](https://img.shields.io/badge/-tested-green) - Code is integrated AND tests are available in `/tests` folder
- ![Not Integrated](https://img.shields.io/badge/-not%20integrated-lightgrey) - No code or mapping available

**Matrix Structure:**
- **PaymentService**: Core payment operations (Authorize, Capture, Void, PSync, SetupMandate, CreateOrder, CreateCustomer, PaymentToken, IncrementalAuth)
- **RefundService**: Refund operations (Refund, RSync)
- **DisputeService**: Dispute management (AcceptDispute, DefendDispute, SubmitEvidence)

**When adding a new connector:**
1. Add the connector row to each relevant service table
2. Mark operations as integrated using: `![Integrated](https://img.shields.io/badge/-integrated-blue)`
3. When tests are added, update to: `![Tested](https://img.shields.io/badge/-tested-green)`
4. Add connector details section at the bottom

**When adding a new operation:**
1. Add the operation column to the relevant service table
2. Mark the status for each connector that implements it
