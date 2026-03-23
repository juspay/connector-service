---
name: generate-tech-spec
description: >
  Generates a technical specification for a payment connector in two phases: (1) discover
  and verify the connector's official API documentation links, (2) feed those links into
  the grace techspec CLI to produce a structured spec. Each phase can be delegated to a
  subagent. Use before implementing a new connector with the new-connector skill.
license: Apache-2.0
compatibility: Requires Python 3.10+ with uv, internet access for doc discovery, and grace CLI configured.
metadata:
  author: parallal
  version: "2.0"
  domain: payment-connectors
---

# Generate Tech Spec

Produces a structured technical specification for a payment connector through two
independent phases, each suitable for subagent delegation:

1. **Links Discovery** -- find, verify, and score the connector's backend API docs
2. **Tech Spec Generation** -- feed verified URLs into `grace techspec` to produce the spec

The generated tech spec is the required input for the `new-connector`, `add-connector-flow`,
and `add-payment-method` skills.

## Prerequisites

- Python 3.10+ and `uv` package manager
- Grace CLI configured: `cd grace && uv sync && source .venv/bin/activate`
- API key in `grace/.env` (copy from `grace/.env.example`)
- Internet access for web search and URL fetching

## Output

```
grace/rulesbook/codegen/references/specs/{connector_name}.md
```

---

## Phase 1: Links Discovery (Subagent)

**Purpose**: Find and verify official backend API documentation URLs for the connector.

**Can be delegated to a subagent.** The full subagent prompt is in
`references/links-discovery.md`. Give the subagent the connector name and payment method/flow.

### What the links subagent does

1. **Discovers documentation URLs** from scratch using web search:
   - Tries common developer portal patterns: `developer.{connector}.com`,
     `docs.{connector}.com`, `{connector}.readme.io`
   - Searches for payment-method-specific pages (e.g., `/payment-methods/apple-pay`)
   - Tries alternative naming (e.g., "ach" for bank debit, "digital-wallets" for Apple Pay)

2. **Categorizes each URL** as one of:
   - `api_reference` -- endpoint details, request/response schemas
   - `payment_method_guide` -- payment-method-specific integration guide
   - `authentication_guide` -- API key setup, headers, HMAC
   - `webhooks_guide` -- event types, payload format, signature verification
   - `testing_guide` -- sandbox credentials, test card numbers
   - `error_reference` -- error codes, decline codes

3. **Filters for backend only** -- excludes frontend SDKs, hosted pages, mobile docs.
   Includes only server-to-server / API-only / REST endpoint documentation.

4. **Verifies each URL** by fetching it and scoring against a 10-point checklist:

   | # | Element | What to look for |
   |---|---------|-----------------|
   | 1 | API Endpoint | POST URL for creating payments |
   | 2 | Authentication | Method + required headers |
   | 3 | Request Schema | JSON body with fields documented |
   | 4 | Response Schema (Success) | Success/pending/declined structure |
   | 5 | Response Schema (Error) | Error response structure |
   | 6 | Payment Method Params | Method-specific fields |
   | 7 | Idempotency | Idempotency-Key or unique reference |
   | 8 | Webhooks | Events, payload, signature verification |
   | 9 | Error Codes | Enumerated codes with meanings |
   | 10 | curl Example | Explicit curl or enough info to construct one |

   Score >= 7: **valid** -- sufficient docs. Score 4-6: **problematic** -- gaps exist.
   Score < 4: **insufficient** -- not enough for integration.

5. **Saves verified links** to `data/integration-source-links.json`:
   ```json
   {
     "ConnectorName": [
       "https://docs.connector.com/api/payments",
       "https://docs.connector.com/webhooks"
     ]
   }
   ```

### How to invoke the links subagent

```
Subagent prompt:
  "Read and follow the workflow in .skills/generate-tech-spec/references/links-discovery.md

  Variables:
    CONNECTOR_NAME: {ConnectorName}  (exact casing)
    PAYMENT_METHOD: {Flow}           (e.g., Card, Apple Pay, Bank Debit)"
```

### Manual alternative (no subagent)

If you already have the connector's API doc URLs, skip this phase. Write them directly:

```bash
# Create a URLs file (one URL per line)
cat > {connector_name}.txt << 'EOF'
https://docs.connector.com/api/payments
https://docs.connector.com/api/refunds
https://docs.connector.com/webhooks
EOF
```

Or save them to `data/integration-source-links.json` for the tech spec phase to pick up.

---

## Phase 2: Tech Spec Generation (Subagent)

**Purpose**: Feed the discovered URLs into `grace techspec` to produce a structured spec.

**Can be delegated to a subagent.** The full subagent prompt is in
`references/techspec-generation.md`. Give the subagent the connector name and flow.

### What the tech spec subagent does

1. **Extracts URLs** from `data/integration-source-links.json` for the connector
2. **Creates a URL file** (`{connector_name}.txt`) with one URL per line
3. **Runs `grace techspec`**:
   ```bash
   cd grace
   source .venv/bin/activate
   cat ../{connector_name}.txt | grace techspec {ConnectorName} -e
   ```
4. **Verifies** the spec was generated at `grace/rulesbook/codegen/references/specs/`

### How to invoke the tech spec subagent

```
Subagent prompt:
  "Read and follow the workflow in .skills/generate-tech-spec/references/techspec-generation.md

  Variables:
    CONNECTOR: {ConnectorName}  (exact casing for grace techspec command)
    FLOW: {Flow}                (e.g., Card, BankDebit)"
```

### Grace techspec CLI reference

```
grace techspec <ConnectorName> [options]

Options:
  -u <path>    Path to file containing URLs to scrape
  -f <path>    Path to folder with local docs (PDF, HTML)
  -e           Enable enhanced mode (Claude Agent SDK enhancement)
  -m           Enable mock server generation for testing
  -v           Verbose output
  -o <dir>     Output directory for generated specs

Input methods:
  Pipe URLs:     cat urls.txt | grace techspec ConnectorName -e
  Local folder:  grace techspec ConnectorName -f /path/to/docs -v
  URL file:      grace techspec ConnectorName -u urls.txt -e
```

**Critical rules:**
- Working directory MUST be `grace/` when running the command
- Virtual environment MUST be activated first (`source .venv/bin/activate`)
- The `-e` flag is recommended for enhanced extraction
- The command can take up to 20 minutes -- do not interrupt

### Manual alternative (no grace CLI)

If `grace techspec` is not available, create the spec manually by reading the connector's
API docs and writing it in this structure:

```markdown
# {ConnectorName} Technical Specification

## Overview
- Base URL: https://api.connector.com/v1
- Authentication: Bearer token via Authorization header
- Amount Format: Minor units (integer cents)
- Content Type: application/json

## Authentication
- Type: HeaderKey / SignatureKey / BodyKey
- Header: Authorization: Bearer {api_key}

## Endpoints

### Authorize (POST /payments)
- Request: { amount, currency, payment_method, ... }
- Response: { id, status, amount, ... }
- Statuses: succeeded, pending, failed, requires_action

### Capture (POST /payments/{id}/capture)
- Request: { amount }
- Response: { id, status }

### Refund (POST /refunds)
- Request: { payment_id, amount }
- Response: { id, status }

### Void (POST /payments/{id}/cancel)
- Request: {}
- Response: { id, status }

### Payment Sync (GET /payments/{id})
- Response: { id, status, amount, ... }

### Refund Sync (GET /refunds/{id})
- Response: { id, status, amount, ... }

## Status Mappings
| Connector Status | UCS AttemptStatus |
|-----------------|-------------------|
| succeeded       | Charged           |
| pending         | Pending           |
| failed          | Failure           |

## Error Format
{ "error": { "code": "...", "message": "..." } }

## Webhooks
- Signature: HMAC-SHA256 of payload
- Events: payment.succeeded, payment.failed, refund.succeeded

## Supported Payment Methods
- Card (Visa, Mastercard, Amex)
- Wallet (Apple Pay, Google Pay)
```

Save to: `grace/rulesbook/codegen/references/{connector_name}/technical_specification.md`

---

## Verification

After both phases complete, verify:

1. Tech spec file exists:
   ```bash
   find grace/rulesbook/codegen/references -iname "*{connector}*" | head -10
   ```

2. Tech spec contains all required sections (Overview, Auth, Endpoints, Status Mappings)

3. Each endpoint has: HTTP method, URL path, request schema, response schema, status values

---

## What to Do Next

After the tech spec is ready, use the appropriate skill:

- Full connector from scratch: use `new-connector` skill
- Add specific flows: use `add-connector-flow` skill
- Add payment methods: use `add-payment-method` skill

## Reference Files

| File | Purpose |
|------|---------|
| `references/links-discovery.md` | Full subagent prompt for Phase 1 (link finding + verification) |
| `references/techspec-generation.md` | Full subagent prompt for Phase 2 (grace techspec execution) |
