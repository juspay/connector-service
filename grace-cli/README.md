# Grace CLI

Interactive CLI for creating Hyperswitch payment connectors.

## Overview

Grace CLI simplifies the process of integrating new payment processors into Hyperswitch by:
1. Collecting connector requirements through an interactive wizard
2. Automatically invoking AI agents (Claude Code/OpenCode) to generate technical specifications
3. Providing clear next steps for full connector implementation

## Installation

```bash
cd grace-cli
pip install -e .
```

Or using pipx for isolation:

```bash
pipx install -e .
```

## Prerequisites

### Claude Code (Recommended)

Claude Code is the primary AI agent used for connector generation. Install it:

```bash
curl -fsSL https://claude.ai/install.sh | bash
```

Or visit [claude.ai/code](https://claude.ai/code) for other installation methods.

## Usage

### Create a New Connector

```bash
grace create
```

This launches an interactive wizard that will:
1. Ask for connector details (name, API URL, auth type)
2. Collect documentation source (folder, URLs, or manual)
3. Select supported payment flows and methods
4. Configure webhook support
5. Invoke Claude Code to generate the tech spec

### Check Agent Status

```bash
grace status
```

Verifies which AI agents are available on your system.

## Workflow

```
grace create
  ↓
[Interactive Wizard]
  - Connector name, API URL, auth type
  - Documentation source
  - Payment flows & methods
  - Webhook configuration
  ↓
[Auto-invoke AI Agent]
  - Detects Claude Code
  - Runs Grace workflow
  - Generates tech spec
  ↓
[Output]
  - Technical specification saved
  - Instructions for next steps
```

## Example

```bash
$ grace create

╔═══════════════════════════════════════════════════════════╗
║  Grace - Hyperswitch Connector Generator                  ║
╚═══════════════════════════════════════════════════════════╝

Step 1/6: Connector Information
────────────────────────────────
? Connector name: StripeClone
? Base API URL: https://api.stripeclone.com
? Authentication type: OAuth 2.0

Step 2/6: Documentation
───────────────────────
? How to provide API docs? Local folder
? Path to documentation folder: ./stripe-docs/

...

✓ Tech spec generated successfully!

Connector: stripeclone
Output: grace/rulesbook/codegen/references/stripeclone/technical_specification.md

Next Steps:
  1. Review the generated tech spec
  2. Generate full connector code:
     $ claude -p "integrate StripeClone using grace/rulesbook/codegen/.gracerules"
```

## Without Claude Code

If Claude Code is not installed, Grace CLI will display manual instructions:

```
⚠ No AI agent detected

Please run the command below manually:

integrate StripeClone using grace/rulesbook/codegen/.gracerules
```

## Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Format code
black src/

# Type checking
mypy src/
```

## Project Structure

```
grace-cli/
├── src/grace_cli/
│   ├── cli.py              # Main entry point
│   ├── wizard/
│   │   ├── prompts.py      # Interactive questions
│   │   └── runner.py       # Wizard flow
│   └── agent/
│       ├── detector.py     # Detect available AI agents
│       ├── invoker.py      # Invoke agents
│       └── fallback.py     # Manual instructions
├── pyproject.toml
└── README.md
```

## License

Apache 2.0 - See [LICENSE](../LICENSE) for details.
