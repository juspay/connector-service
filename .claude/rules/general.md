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
