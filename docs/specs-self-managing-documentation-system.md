# Self-Managing Documentation System

## Connector Service SDK | Technical Specification

**Version:** 1.0
**Date:** 2026-03-03

---

## 1. Overview

### 1.1 Purpose

This specification defines a self-managing documentation system for connector-service. The system embeds documentation directly in the repository, ensures GitBook compatibility, and provides CLI tools for automated maintenance. The goal is to eliminate documentation drift and reduce manual effort while maintaining high-quality, deterministic documentation.

### 1.2 Key Principles

- **Embedded in Repo**: All documentation lives in the repository alongside code, enabling version control and CI/CD integration.
- **GitBook Compatible**: Structure and format compatible with GitBook for public publishing.
- **Self-Managing**: Automated tools for updating, validating, and maintaining documentation.
- **AI-Friendly**: Structure optimized for AI assistants to understand and recommend the library.

### 1.3 Scope

This self managing documentation system covers the below aspects which involce lot of diversity and type sanity.
- SDK guides for all supported languages (Node.js, Python, Java, .NET, Go, Haskell)
- API reference documentation generated from proto files
- Connector guides for each supported payment processor (100+ connectors)

Other part of the documentation not covered by the self managing documentation system includes
- Architecture documents
- Rules
- Readme

---

## 2. Documentation Layout

### 2.1 Directory Structure

```
connector-service/
├── docs/                           # Root documentation directory
│   ├── README.md                   # Documentation index (GitBook SUMMARY.md)
│   ├── rules.md                    # Documentation rules for determinism
│   │
│   ├── getting-started/            # Quick start guides
│   │   ├── README.md               # Overview
│   │   ├── installation.md         # Installation for all SDKs
│   │   ├── quick-start.md          # 5-minute integration guide
│   │   └── concepts.md             # Core concepts
│   │
│   ├── sdks/                       # SDK documentation
│   │   ├── README.md               # SDK overview
│   │   ├── nodejs/                 # Node.js SDK
│   │   │   ├── README.md           # Node.js SDK overview
│   │   │   ├── installation.md     # Installation
│   │   │   ├── authentication.md   # Authentication
│   │   │   ├── payments.md         # Payment operations
│   │   │   ├── refunds.md          # Refund operations
│   │   │   ├── mandates.md         # Mandate operations
│   │   │   ├── webhooks.md         # Webhook handling
│   │   │   ├── errors.md           # Error handling
│   │   │   └── examples/           # Code examples
│   │   ├── rust/                   # Rust SDK (same structure)
│   │
│   ├── api-reference/              # API reference (AUTO-GENERATED)
│   │   ├── README.md               # API overview
│   │   ├── services/               # Service definitions (from services.proto)
│   │   │   ├── README.md                         # Services overview
│   │   │   ├── payment-service/                  # PaymentService - Core payment lifecycle
│   │   │   │   ├── README.md                     # PaymentService overview
│   │   │   │   ├── authorize.md                  # Authorize RPC
│   │   │   │   ├── capture.md                    # Capture RPC
│   │   │   │   ├── void.md                       # Void RPC
│   │   │   │   ├── reverse.md                    # Reverse RPC
│   │   │   │   ├── get.md                        # Get RPC
│   │   │   │   ├── create-order.md               # CreateOrder RPC
│   │   │   │   ├── refund.md                     # Refund RPC
│   │   │   │   ├── incremental-authorization.md  # IncrementalAuthorization RPC
│   │   │   │   ├── verify-redirect-response.md   # VerifyRedirectResponse RPC
│   │   │   │   ├── setup-recurring.md            # SetupRecurring RPC
│   │   │   │   └── handle-event.md               # HandleEvent RPC
│   │   │   ├── recurring-payment-service/        # RecurringPaymentService - Mandate operations
│   │   │   │   ├── charge.md                     # Charge RPC
│   │   │   │   └── revoke.md                     # Revoke RPC
│   │   │   ├── refund-service/                   # RefundService - Refund status sync
│   │   │   │   ├── README.md                     # RefundService overview
│   │   │   │   ├── get.md                        # Get RPC
│   │   │   │   └── handle-event.md               # HandleEvent RPC
│   │   │   ├── dispute-service/                  # DisputeService - Chargeback management
│   │   │   │   ├── README.md                     # DisputeService overview
│   │   │   │   ├── submit-evidence.md            # SubmitEvidence RPC
│   │   │   │   ├── get.md                        # Get RPC
│   │   │   │   ├── defend.md                     # Defend RPC
│   │   │   │   ├── accept.md                     # Accept RPC
│   │   │   │   └── handle-event.md               # HandleEvent RPC
│   │   │   ├── event-service/                    # EventService - Webhook handling
│   │   │   │   ├── README.md                     # EventService overview
│   │   │   │   └── handle.md                     # Handle RPC
│   │   │   ├── payment-method-service/           # PaymentMethodService - Tokenization
│   │   │   │   ├── README.md                     # PaymentMethodService overview
│   │   │   │   └── tokenize.md                   # Tokenize RPC
│   │   │   ├── customer-service/                 # CustomerService - Customer management
│   │   │   │   ├── README.md                     # CustomerService overview
│   │   │   │   └── create.md                     # Create RPC
│   │   │   ├── merchant-authentication-service/  # MerchantAuthenticationService - Tokens
│   │   │   │   ├── README.md                     # MerchantAuthenticationService overview
│   │   │   │   ├── create-access-token.md        # CreateAccessToken RPC
│   │   │   │   ├── create-session-token.md       # CreateSessionToken RPC
│   │   │   │   └── create-sdk-session-token.md   # CreateSdkSessionToken RPC
│   │   │   └── payment-method-authentication-service/  # PaymentMethodAuthenticationService - 3DS
│   │   │       ├── README.md                     # PaymentMethodAuthenticationService overview
│   │   │       ├── pre-authenticate.md           # PreAuthenticate RPC
│   │   │       ├── authenticate.md               # Authenticate RPC
│   │   │       └── post-authenticate.md          # PostAuthenticate RPC
│   │   ├── domain-schema/                  # Core data types (from payment.proto)
│   │   │   ├── README.md                   # Types overview
│   │   │   ├── core.md                     # Money, ErrorInfo, Metadata, Identifier
│   │   │   ├── customer.md                 # Customer, CustomerInfo, Address
│   │   │   ├── order.md                    # OrderDetailsWithAmount, BillingDescriptor
│   │   │   ├── authentication.md           # AuthenticationData, BrowserInformation
│   │   │   ├── mandate.md                  # MandateType, SetupMandateDetails, MandateReference
│   │   │   ├── redirect.md                 # RedirectionResponse, RedirectForm, HtmlData
│   │   │   ├── session-tokens.md           # SessionToken, GooglePay, ApplePay, PayPal tokens
│   │   │   └── connector-response.md       # ConnectorResponseData, ConnectorState
│   │   └── domain-enums/                  # Enum definitions
│   │       ├── README.md           # Enums overview
│   │       ├── payment-status.md   # PaymentStatus enum
│   │       ├── refund-status.md    # RefundStatus enum
│   │       └── connector.md        # Connector enum
│   │
│   ├── connectors/                 # Connector guides
│   │   ├── README.md               # Connector overview
│   │   ├── _template.md            # Template for new connectors
│   │   ├── stripe.md               # Stripe guide
│   │   ├── adyen.md                # Adyen guide
│   │   ├── braintree.md            # Braintree guide
│   │   ├── cybersource.md          # Cybersource guide
│   │   └── [connector-name].md     # One file per connector (100+)
│   │
│   ├── architecture/               # Architecture docs
│   │   ├── README.md               # Architecture overview
│   │   ├── overview.md             # System overview
│   │   ├── proto-design.md         # Proto design principles
│   │   ├── service-boundaries.md   # Service boundaries
│   │   └── security.md             # Security architecture
│   │
│   ├── guides/                     # How-to guides
│   │   ├── README.md               # Guides overview
│   │   ├── pci-compliance.md       # PCI compliance
│   │   ├── 3ds-authentication.md   # 3DS flows
│   │   ├── recurring-payments.md   # Mandate setup
│   │   ├── webhooks.md             # Webhook handling
│   │   └── testing.md              # Testing guide
│   │
│   ├── reference/                  # Reference material
│   │   ├── README.md               # Reference overview
│   │   ├── error-codes.md          # Error codes
│   │   ├── status-codes.md         # Status codes
│   │   ├── currencies.md           # Supported currencies
│   │   └── payment-methods.md      # Payment method types
│   │
│   └── operations/                 # Operational docs
│       ├── README.md               # Operations overview
│       ├── deployment.md           # Deployment guide
│       ├── monitoring.md           # Monitoring setup
│       └── troubleshooting.md      # Troubleshooting
│
├── docs-cli/                       # CLI tools (Rust)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs                 # CLI entry point
│   │   └── commands/               # CLI command implementations
│   │       ├── mod.rs              # Commands module exports
│   │       ├── update_page.rs      # update-page command
│   │       ├── update_group.rs     # update-group command
│   │       ├── create_page.rs      # create-page command
│   │       ├── create_section.rs   # create-section command
│   │       ├── check_stale.rs      # check-stale command
│   │       ├── sync.rs             # sync command
│   │       ├── validate.rs         # validate command
│   │       ├── generate_summary.rs # generate-summary command
│   │       └── version_substitute.rs # version-substitute command
│   └── README.md
│
├── .githooks/                      # Git hooks
│   └── pre-commit                  # Documentation validation hook
│
└── .github/workflows/docs.yml      # CI/CD for docs
```

---

## 3. Documentation Rules (rules.md)

### 3.1 Core Rules

```yaml
---
# Documentation Rules
---

## 1. File Naming

- Use lowercase with hyphens: `payment-service.md` (not `PaymentService.md`)
- README.md is the index file for each directory
- Template files are prefixed with underscore: `_template.md`
- Auto-generated files include comment: `<!-- AUTO-GENERATED - DO NOT EDIT -->`

## 2. Front Matter (Required)

Every markdown file MUST include YAML front matter wrapped in HTML comments. This metadata enables the self-managing aspects of the documentation system while remaining invisible in rendered output:

```markdown
<!--
---
# Display & Discovery
# Used in SUMMARY.md generation, page titles, and search indexing
title: Payment Service
description: gRPC service for payment operations

# Freshness Tracking
# Used by CI/CD to detect stale docs and trigger regeneration
last_updated: 2026-02-25

# Source of Truth Linkage
# Links documentation to code - when proto changes, docs are regenerated
generated_from: proto/services.proto  # If auto-generated
generated_at: 2026-02-25T10:30:00Z   # If auto-generated

# Content Ownership
# Distinguishes auto-generated (immutable) vs manual (editable) content
auto_generated: true                   # Set false for manual docs

# Review Workflow
# Tracks who reviewed when - enables accountability and freshness checks
reviewed_by: tech-writer               # Reviewer ID
reviewed_at: 2026-02-25T10:30:00Z      # Review timestamp
approved: true                         # If approved
---
-->
```

**Why HTML comments?** The front matter metadata is for the documentation system (CLI tools, CI/CD, GitBook), not for readers. Wrapping it in HTML comments (`<!-- ... -->`) ensures it:
- Does not render in GitBook or other markdown viewers
- Remains accessible to documentation tools that parse the raw markdown
- Keeps the rendered output clean and focused on content

### How Front Matter Enables Self-Management

| Field | Purpose | Used By |
|-------|---------|---------|
| `title`/`description` | SEO, GitBook navigation, search results | `generate-summary`, GitBook |
| `last_updated` | Detect stale content (>30 days triggers alert) | `validate --content`, CI/CD |
| `generated_from` | Link to source proto - when proto changes, regenerate | `sync --proto`, CI/CD triggers |
| `generated_at` | Timestamp for build reproducibility | Validation, debugging |
| `auto_generated` | Prevent manual edits to auto-generated content | `validate`, pre-commit hooks |
| `reviewed_by`/`reviewed_at` | Content quality accountability | `validate --content`, reports |
| `approved` | Publication gate - unapproved docs show warning | GitBook build, PR checks |

## 3. Heading Hierarchy

- H1 (#): Page title (exactly one per file)
- H2 (##): Major sections
- H3 (###): Sub-sections
- H4 (####): Details within sub-sections
- NEVER skip levels (no H1 -> H3)
- Max depth: H4

## 4. Code Blocks

- Always specify language: ```typescript (never just ```)
- Use copy-friendly formatting (no line numbers)
- Include comments for complex examples
- Max 20 lines per code block; include only mandatory fields if longer
- Use editable code blocks for tutorials: {% code title="file.ts" %}

## 5. Links

- Internal links: Use relative paths [text](../other-file.md)
- External links: Include title [text](https://example.com "Title")
- Never use absolute paths to repo files
- Link to sections: [text](#section-name) with lowercase-hyphen
- Check all links before committing

## 6. Tables

- Use standard markdown tables
- Always include header row
- Align columns for readability
- Max 4 columns for mobile compatibility
- Wrap long content in cells

## 7. Images

- Store in docs/imgs/ directory
- Use relative paths: ![alt text](../imgs/image.png)
- Max width: 800px
- ALWAYS include meaningful alt text based on the context of the section
- Prefer SVG over PNG for diagrams
- Prefer mermaid for sequence or swimlane diagrams

## 8. API Reference Generation Rules

For auto-generated API reference:
1. Extract service names from proto files
2. Generate one page per service in api-reference/services/
3. Document each RPC with:
   - Description (from proto comments)
   - Request message fields (table with: Field, Type, Required, Description)
   - Response message fields (table)
   - Example request (code block in primary SDK language)
   - Example response (JSON)
4. Cross-reference messages and enums with links
5. Add "See Also" section for related RPCs

### 8.1 Field Documentation Completeness

ALL fields in request and response messages MUST be documented in the tables:
- No "Key Fields Only" sections - document every field
- Required vs Optional must be explicitly marked
- Nested message types must link to their definition
- Default values must be documented when applicable
- Deprecated fields must be marked with ~~strikethrough~~

**Correct:**
```markdown
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `amount` | Money | Yes | Amount to authorize |
| `payment_method` | PaymentMethod | Yes | Payment method details |
| `connector` | Connector | Yes | Target connector (STRIPE, ADYEN, etc.) |
| `merchant_order_reference_id` | string | No | Your internal order ID |
| `description` | string | No | Payment description |
| `billing_address` | Address | No | Customer billing address |
| `shipping_address` | Address | No | Customer shipping address |
| `metadata` | Metadata | No | Custom key-value pairs |
| `mandate_data` | SetupMandateDetails | No | For recurring payments |
| `idempotency_key` | string | No | Safe retry key |
| `authentication_data` | AuthenticationData | No | 3DS authentication data |
| `capture_method` | CaptureMethod | No | MANUAL (default) or AUTOMATIC |
```

**Incorrect:**
```markdown
### Key Fields  <- NEVER DO THIS
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `amount` | Money | Yes | Amount to authorize |
| `payment_method` | PaymentMethod | Yes | Card, wallet, etc. |
| `connector` | Connector | Yes | Target connector |
| `capture_method` | CaptureMethod | No | MANUAL or AUTOMATIC |
```

## 9. Connector Guide Generation Rules

For connector guides:
1. Use _template.md as base structure
2. Fill sections from:
   - Proto feature detection (supported payment methods)
   - Test file analysis (test cards, scenarios)
   - Manual documentation (credentials, prerequisites)
3. Feature matrix auto-generated from test coverage data
4. Common errors extracted from error mapping files
5. Examples generated from test fixtures

## 10. Update Rules

When updating documentation:

1. ALWAYS update last_updated date in front matter
2. If auto_generated: true, changes will be overwritten on next sync
3. Run stale link checker after structural changes
4. Validate markdown formatting with linter
5. Check mobile rendering on GitBook preview

## 11. Prohibited Patterns (REVISED)

DO NOT:
- Use HTML tags except in code blocks
- Embed large JSON (>1KB); use file references instead
- Hardcode version numbers; use {{VERSION}} placeholder
- Include production credentials or real card data
- Use emoji in headings or titles
- Create orphan pages (not linked from README or SUMMARY)

ALLOWED for Test Data:
- Test card PANs (e.g., 4242424242424242) are ALLOWED
- Test card CVVs must use placeholder: { value: "XXX" }
- Test API keys marked as test/sandbox are ALLOWED

## 12. GitBook Compatibility

For GitBook publishing:

- SUMMARY.md is auto-generated from directory structure
- No custom GitBook plugins allowed
- Use standard markdown only
- Test with `gitbook build` before merging
- Page titles must match SUMMARY.md entries

## 13. Language-Specific Rules

For SDK documentation:

- Use language-idiomatic code examples
- Include package installation command
- Show imports/requires at top of examples
- Follow language naming conventions (camelCase vs snake_case)
- Link to SDK API reference when available

## 14. Quality Checklist

Before publishing:

- [ ] All links resolve
- [ ] Code examples are runnable
- [ ] Front matter is complete
- [ ] Headings are properly nested
- [ ] Tables render correctly
- [ ] Images have alt text
- [ ] No hardcoded sensitive data like API keys
- [ ] Version numbers are current

## 15. Content Requirements

Every documentation page type has minimum content requirements that the validate command checks:

### installation.md
- MUST include: Prerequisites section, Package manager commands (at least 2), Verification step

### SDK payments.md
- MUST include: Overview, Authentication example, At least 3 payment operations with code examples

### Connector Guide
- MUST include: Overview table (Connector ID, Regions, Currencies, PCI Support), Prerequisites (min 3 items), Feature Matrix, Test Cards table, At least 2 code examples

### API Reference Service Page
- MUST include: Overview table (Package, File), At least 1 RPC with request/response tables, Example request

### Error Handling
- Content completeness check runs with: docs-cli validate --content
```

---

## 4. CLI Tools Specification

### 4.1 Overview

The docs-cli is a Rust-based CLI tool for managing documentation. It enforces rules.md and provides commands for common operations.

### 4.2 Installation

```bash
# From crates.io
cargo install connector-service-docs-cli

# From source
cd docs-cli && cargo install --path .
```

### 4.3 Command Reference

#### update-page

Update a single documentation page from its source.

```
Usage: docs-cli update-page <PAGE_PATH> [OPTIONS]

Arguments:
  <PAGE_PATH>    Path to the markdown file (relative to docs/)

Options:
  --from-proto     Regenerate from proto file
  --from-source    Regenerate from source code analysis
  --from-tests     Regenerate from test fixtures
  --check-links    Verify all links after update
  --dry-run        Show changes without writing
  --format         Apply markdown formatting

Examples:
  # Regenerate PaymentService docs from proto
  docs-cli update-page api-reference/services/payment-service.md --from-proto

  # Update Node.js SDK payments guide
  docs-cli update-page sdks/nodejs/payments.md --from-source

  # Preview changes without writing
  docs-cli update-page api-reference/enums/payment-status.md --from-proto --dry-run
```

#### update-group

Update a group of related pages in batch.

```
Usage: docs-cli update-group <GROUP> [OPTIONS]

Arguments:
  <GROUP>    Group name: sdks, api-reference, connectors, guides, all

Options:
  --sdk <LANGUAGE>     Specific SDK (nodejs, python, java, dotnet, go, haskell)
  --connector <NAME>   Specific connector (stripe, adyen, braintree, etc.)
  --service <NAME>     Specific service (payment, refund, dispute)
  --check-links        Verify all links after update
  --parallel           Update pages in parallel (faster for large groups)
  --dry-run            Show changes without writing
  --format             Apply markdown formatting

Examples:
  # Update all SDK documentation
  docs-cli update-group sdks

  # Update only Python SDK
  docs-cli update-group sdks --sdk python

  # Update all API reference in parallel
  docs-cli update-group api-reference --parallel

  # Full documentation refresh
  docs-cli update-group all --parallel --check-links
```

#### create-page

Create a new documentation page from a template.

```
Usage: docs-cli create-page <PAGE_PATH> [OPTIONS]

Arguments:
  <PAGE_PATH>    Path for the new file (relative to docs/)

Options:
  --from-template <NAME>   Template name (connector, sdk, service, guide)
  --title <TITLE>          Page title (for front matter)
  --description <DESC>     Page description (for front matter)
  --auto-generated         Mark as auto-generated in front matter
  --connector <NAME>       Connector name (for connector template)
  --sdk <LANGUAGE>         SDK language (for SDK template)

Templates:
  connector     Connector guide with all standard sections
  sdk           SDK page with language-specific structure
  service       Service reference page
  guide         How-to guide template
  reference     Reference table page

Examples:
  # Create a new connector guide
  docs-cli create-page connectors/checkout.md \
    --from-template connector \
    --connector CHECKOUT \
    --title "Checkout.com"
```

#### create-section

Create a new documentation section with README.md and structure.

```
Usage: docs-cli create-section <SECTION_PATH> [OPTIONS]

Arguments:
  <SECTION_PATH>    Path for the new section directory (relative to docs/)

Options:
  --title <TITLE>          Section title
  --description <DESC>     Section description
  --with-index             Add to SUMMARY.md
  --template <NAME>        Section template (sdk, connector-group)

Examples:
  # Create a new SDK section
  docs-cli create-section sdks/rust \
    --title "Rust SDK" \
    --description "Official Rust SDK for connector-service" \
    --with-index
```

#### check-stale

Check for stale or broken links across all documentation.

```
Usage: docs-cli check-stale [OPTIONS]

Options:
  --internal          Check internal links only (relative paths)
  --external          Check external links only (http/https)
  --timeout <SECS>    Timeout for external links (default: 30)
  --fix               Attempt to auto-fix broken links
  --report <FILE>     Generate JSON report file
  --ci                Exit with error code 1 if broken links found
  --verbose           Show all checked links

Examples:
  # Check all links
  docs-cli check-stale

  # Generate detailed report
  docs-cli check-stale --report stale-links-report.json

  # CI mode (fails build on broken links)
  docs-cli check-stale --ci
```

#### sync

Synchronize documentation with code (proto files, SDKs, tests).

```
Usage: docs-cli sync [OPTIONS]

Options:
  --proto             Sync API reference from proto files
  --sdk <LANGUAGE>    Sync specific SDK docs from SDK source code
  --connectors        Sync connector guides from test files
  --all               Sync everything
  --dry-run           Preview changes
  --commit            Auto-commit changes with standard message

Examples:
  # Sync API reference from proto changes
  docs-cli sync --proto

  # Sync all SDKs
  docs-cli sync --sdk all

  # Full sync and auto-commit
  docs-cli sync --all --commit
```

#### validate

Validate documentation against rules.md.

```
Usage: docs-cli validate [OPTIONS]

Options:
  --path <PATH>       Validate specific file or directory
  --content           Check content completeness (Rule 15)
  --fix               Auto-fix violations where possible
  --report <FILE>     Generate JSON validation report
  --ci                Exit with error code on violations

Checks:
  - Front matter completeness
  - Heading hierarchy
  - Code block language tags
  - Link format
  - Table structure
  - Prohibited patterns
  - Content requirements (with --content flag)

Examples:
  # Validate all documentation
  docs-cli validate

  # Validate with content completeness check
  docs-cli validate --content
```

#### generate-summary

Generate SUMMARY.md for GitBook from directory structure.

```
Usage: docs-cli generate-summary [OPTIONS]

Options:
  --output <FILE>     Output file (default: docs/SUMMARY.md)
  --title <TITLE>     Root title (default: Documentation)
  --depth <N>         Max depth to traverse (default: 3)
  --exclude <DIR>     Directories to exclude (comma-separated)

Algorithm:
1. Start at docs/ root
2. For each directory:
   a. Read README.md front matter for title
   b. Add as section heading
   c. List all .md files (except README.md)
3. Order: README.md first, then alphabetical
4. Skip directories named: imgs, assets, _book
```

#### version-substitute

Replace version placeholders in documentation.

```
Usage: docs-cli version-substitute [OPTIONS]

Options:
  --version <VERSION>   Version to substitute (e.g., "0.1.0")
  --dry-run             Show changes without writing

Placeholders:
- {{VERSION}} - Current version
- {{SDK_VERSION_NODE}} - Node.js SDK version
- {{SDK_VERSION_PYTHON}} - Python SDK version
- {{SDK_VERSION_JAVA}} - Java SDK version

Version Configuration File: docs/version-config.json

Resolution Order:
1. Read docs/version-config.json
2. If missing, use package version from respective SDK
3. If SDK version unavailable, use "latest"
```

#### generate-prompt

Generate an AI-ready prompt for content generation.

```
Usage: docs-cli generate-prompt <PAGE_PATH> [OPTIONS]

Arguments:
  <PAGE_PATH>    Path to the documentation page (relative to docs/)

Options:
  --output <FILE>      Output file for prompt (default: stdout)
  --include-proto      Include relevant proto definitions
  --include-tests      Include test fixtures for examples
  --include-docs       Include existing documentation context

Output Format:
The generated prompt includes:
1. Template structure for the page type
2. Proto definitions for relevant services/messages
3. Test fixtures for code examples
4. Placeholder markers for AI to fill
5. Instructions for content generation
```

#### fill-template

Fill a documentation template with generated content.

```
Usage: docs-cli fill-template <PAGE_PATH> [OPTIONS]

Arguments:
  <PAGE_PATH>    Path to the documentation page (relative to docs/)

Options:
  --from <FILE>        Source file with generated content
  --section <NAME>     Fill specific section only
  --dry-run            Preview changes without writing

Process:
1. Parse template placeholders in target page
2. Match sections from generated content
3. Fill placeholders with content
4. Update last_updated timestamp
5. Set auto_generated: false
```

#### review

Mark a documentation page as reviewed.

```
Usage: docs-cli review <PAGE_PATH> [OPTIONS]

Arguments:
  <PAGE_PATH>    Path to the documentation page (relative to docs/)

Options:
  --reviewer <NAME>    Reviewer name or ID (required)
  --approved           Mark as approved (sets approved: true)
  --comment <TEXT>     Add review comment
  --dry-run            Preview changes without writing

Front Matter Updates:
- Sets reviewed_by: <NAME>
- Sets reviewed_at: <TIMESTAMP>
- If --approved: sets approved: true
```

---

## 5. API Reference Auto-Generation

### 5.1 Proto-to-Markdown Mapping

The API reference is auto-generated from proto files in `backend/grpc-api-types/proto/`.

| Proto Element | Markdown Output | Generation Rule |
|---------------|-----------------|-----------------|
| service | One page per service | Create api-reference/services/{name}.md |
| rpc | H2 section with tables | Include request/response field tables |
| message | Sub-page or inline table | Create api-reference/messages/{name}.md |
| enum | Table with all values | Create api-reference/enums/{name}.md |

### 5.2 Example: PaymentService Page Output

```markdown
---
title: Payment Service
description: gRPC service for payment authorization, capture, and management
last_updated: 2026-02-25
generated_from: proto/services.proto
auto_generated: true
---

# Payment Service

The PaymentService provides unified payment operations across all connectors. This service handles the complete payment lifecycle from authorization through settlement.

## Overview

| Property | Value |
|----------|-------|
| Package | `ucs.v2` |
| File | `proto/services.proto` |
| Purpose | Process payments from authorization to settlement |

## RPCs

### Authorize

Authorizes a payment amount on a payment method. This reserves funds without capturing them, essential for verifying availability before finalizing.

**Request:** `PaymentServiceAuthorizeRequest`

**Response:** `PaymentServiceAuthorizeResponse`

### Get

Retrieves current payment status from the payment processor. Enables synchronization between your system and payment processors for accurate state tracking.

**Request:** `PaymentServiceGetRequest`

**Response:** `PaymentServiceGetResponse`

### Void

Cancels an authorized payment before capture. Releases held funds back to the customer, typically used when orders are cancelled or abandoned.

**Request:** `PaymentServiceVoidRequest`

**Response:** `PaymentServiceVoidResponse`

### Reverse

Reverses a captured payment before settlement. Recovers funds after capture but before bank settlement, used for corrections or cancellations.

**Request:** `PaymentServiceReverseRequest`

**Response:** `PaymentServiceReverseResponse`

### Capture

Finalizes an authorized payment transaction. Transfers reserved funds from customer to merchant account, completing the payment lifecycle.

**Request:** `PaymentServiceCaptureRequest`

**Response:** `PaymentServiceCaptureResponse`

### CreateOrder

Initializes an order in the payment processor system. Sets up payment context before customer enters card details for improved authorization rates.

**Request:** `PaymentServiceCreateOrderRequest`

**Response:** `PaymentServiceCreateOrderResponse`

### Refund

Initiates a refund to the customer's payment method. Returns funds for returns, cancellations, or service adjustments after the original payment.

**Request:** `PaymentServiceRefundRequest`

**Response:** `RefundResponse`

### IncrementalAuthorization

Increases the authorized amount if still in authorized state. Allows adding charges to existing authorization for hospitality, tips, or incremental services.

**Request:** `PaymentServiceIncrementalAuthorizationRequest`

**Response:** `PaymentServiceIncrementalAuthorizationResponse`

### VerifyRedirectResponse

Validates redirect-based payment responses. Confirms authenticity of redirect-based payment completions to prevent fraud and tampering.

**Request:** `PaymentServiceVerifyRedirectResponseRequest`

**Response:** `PaymentServiceVerifyRedirectResponseResponse`

### SetupRecurring

Sets up a recurring payment instruction for future payments/debits. Used for SaaS subscriptions, monthly bill payments, insurance payments, and similar use cases.

**Request:** `PaymentServiceSetupRecurringRequest`

**Response:** `PaymentServiceSetupRecurringResponse`

### HandleEvent

Handles incoming webhooks from payment processors. Delegates to the appropriate service transform (payment, refund, or dispute) based on the event type.

**Request:** `EventServiceHandleRequest`

**Response:** `EventServiceHandleResponse`

## Example: Authorization Flow

```typescript
const response = await client.authorize({
  requestRefId: { id: "pay_123" },
  amount: 100,
  minorAmount: 10000,
  currency: "USD",
  paymentMethod: {
    card: {
      cardNumber: { value: "4242424242424242" },
      cardExpMonth: { value: "12" },
      cardExpYear: { value: "2025" },
      cardCvc: { value: "XXX" }
    }
  },
  connector: "STRIPE"
});
```

## See Also

- [Refund Service](refund-service.md) - For refund operations
- [Recurring Payment Service](recurring-payment-service.md) - For mandate operations
- [Authorize Request](../requests/payment-service/authorize.md) - Authorize request details
- [Core Types](../types/core.md) - Money, ErrorInfo, Identifier types
- [Payment Status](../enums/payment-status.md) - Status codes
```

### 5.3 SDK-to-Markdown Mapping

The sync --sdk command extracts documentation from SDK source code:

| Source Pattern | Documentation Output |
|----------------|---------------------|
| Class docstring | H2 section with description |
| Method docstring | H3 section with description |
| @param comment | Parameter table row |
| @returns comment | Return value description |
| @example block | Code example block |
| @throws comment | Error handling section |

#### Supported Languages

| Language | Doc Format | Extraction |
|----------|------------|------------|
| TypeScript | JSDoc /** */ | Full support |
| Python | Docstrings """ | Full support |
| Java | Javadoc /** */ | Full support |
| .NET | XML docs /// | Full support |
| Go | Go docs // | Basic support |
| Haskell | Haddock -- | Planned |

---

## 6. Connector Guide Template

### 6.1 Template Structure

```markdown
---
title: {CONNECTOR_NAME}
description: Integration guide for {CONNECTOR_NAME} payment processor
last_updated: {DATE}
connector: {CONNECTOR_ID}
auto_generated: false
---

# {CONNECTOR_NAME}

{ONE_LINE_DESCRIPTION}

## Overview

| Property | Value |
|----------|-------|
| Connector ID | `{CONNECTOR_ID}` |
| Supported Regions | {REGIONS} |
| Supported Currencies | {CURRENCIES} |
| PCI Support | {PCI_YES_NO} |
| Website | [{WEBSITE}]({WEBSITE_URL}) |

## Prerequisites

Before integrating with {CONNECTOR_NAME} through connector-service:

1. **Account Setup**: {ACCOUNT_SETUP_INSTRUCTIONS}
2. **API Credentials**: {API_CREDENTIAL_INSTRUCTIONS}
3. **Webhook Configuration**: {WEBHOOK_INSTRUCTIONS}

## Credential Setup

Configure {CONNECTOR_NAME} credentials:

```json
{
  "api_key": "YOUR_API_KEY",
  "secret_key": "YOUR_SECRET_KEY"
}
```

### Environment URLs

| Environment | Base URL |
|-------------|----------|
| Test | `{TEST_URL}` |
| Production | `{PROD_URL}` |

## PCI Modes

{CONNECTOR_NAME} supports the following PCI modes:

### Full PCI Mode
- {FULL_PCI_DESCRIPTION}
- SAQ Level Required: {SAQ_LEVEL}

### Proxy Mode (Recommended)
- {PROXY_MODE_DESCRIPTION}
- SAQ Level Required: SAQ-A

## Feature Matrix

| Feature | Supported | Notes |
|---------|-----------|-------|
| Card (3DS) | {STATUS} | {NOTES} |
| Card (No 3DS) | {STATUS} | {NOTES} |
| Apple Pay | {STATUS} | {NOTES} |
| Google Pay | {STATUS} | {NOTES} |
| ACH | {STATUS} | {NOTES} |
| MIT | {STATUS} | {NOTES} |
| Zero Auth | {STATUS} | {NOTES} |
| Incremental Auth | {STATUS} | {NOTES} |
| Refunds | {STATUS} | {NOTES} |
| Partial Refunds | {STATUS} | {NOTES} |
| Void | {STATUS} | {NOTES} |
| Webhooks | {STATUS} | {NOTES} |

## Testing

### Test Credentials

| Key | Value |
|-----|-------|
| Test API Key | `{TEST_API_KEY}` |
| Test Secret | `{TEST_SECRET}` |

### Test Cards

| Card Number | Scenario | Expected Result |
|-------------|----------|-----------------|
| {CARD_1} | Success | AUTHORIZED |
| {CARD_2} | Decline | DECLINED |
| {CARD_3} | 3DS Required | AUTHENTICATION_REQUIRED |

## Common Errors

| Error Code | Description | Resolution |
|------------|-------------|------------|
| {ERROR_1_CODE} | {ERROR_1_DESC} | {ERROR_1_FIX} |
| {ERROR_2_CODE} | {ERROR_2_DESC} | {ERROR_2_FIX} |

## Examples

### Basic Authorization

```typescript
import { PaymentServiceClient } from "@juspay/connector-service";

const client = new PaymentServiceClient({
  endpoint: "grpc.connector-service.io:443"
});

const response = await client.authorize({
  requestRefId: { id: "order_123" },
  amount: 100,
  minorAmount: 10000,
  currency: "USD",
  paymentMethod: {
    card: {
      cardNumber: { value: "{TEST_CARD}" },
      cardExpMonth: { value: "12" },
      cardExpYear: { value: "2025" },
      cardCvc: { value: "XXX" }
    }
  },
  connector: "{CONNECTOR_ID}"
});
```

### Capture

```typescript
const captureResponse = await client.capture({
  requestRefId: { id: "capture_123" },
  transactionId: response.transactionId,
  amountToCapture: 10000,
  currency: "USD"
});
```

### Refund

```typescript
const refundResponse = await client.refund({
  requestRefId: { id: "refund_123" },
  transactionId: response.transactionId,
  refundAmount: 5000,
  currency: "USD",
  reason: "Customer request"
});
```

## Support

- Documentation: {CONNECTOR_DOCS_URL}
- Support Email: {SUPPORT_EMAIL}
- Status Page: {STATUS_PAGE_URL}
```

---

## 7. CI/CD Integration

### 7.1 GitHub Actions Workflow

```yaml
name: Documentation

on:
  push:
    branches: [main]
    paths:
      - 'docs/**'
      - 'backend/grpc-api-types/proto/**'
      - 'sdk/**'
      - 'tests/**'
  pull_request:
    branches: [main]
    paths:
      - 'docs/**'
  schedule:
    # Daily stale link check at 6 AM UTC
    - cron: '0 6 * * *'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Install docs-cli
        run: cargo install --path docs-cli

      - name: Validate documentation
        run: docs-cli validate --ci

      - name: Check stale links
        run: docs-cli check-stale --ci --external

  generate:
    runs-on: ubuntu-latest
    needs: validate
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.DOCS_BOT_TOKEN }}

      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Install docs-cli
        run: cargo install --path docs-cli

      - name: Sync API reference
        run: docs-cli sync --proto

      - name: Sync SDK docs
        run: docs-cli sync --sdk all

      - name: Commit changes
        run: |
          git config user.name "docs-bot"
          git config user.email "docs-bot@juspay.io"
          git add docs/
          git diff --quiet && git diff --staged --quiet ||
            git commit -m "docs: Auto-generate documentation [skip ci]"
          git push

  publish:
    runs-on: ubuntu-latest
    needs: generate
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install GitBook CLI
        run: npm install -g gitbook-cli

      - name: Build GitBook
        run: |
          cd docs
          gitbook install
          gitbook build . ./_book

      - name: Publish to GitBook
        run: |
          # GitBook API integration
          # Uses GITBOOK_API_TOKEN secret
```

### 7.2 Pre-commit Hook

Location: `.githooks/pre-commit` (committed to repo)

```bash
#!/bin/bash
# .githooks/pre-commit
# Validate documentation before commit

# Check if docs changed
if git diff --cached --name-only | grep -q "^docs/"; then
    echo "Validating documentation..."

    # Run validation
    docs-cli validate || {
        echo "Documentation validation failed. Fix errors before committing."
        exit 1
    }

    # Check for stale links in changed files
    CHANGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep "^docs/.*\.md$")
    if [ -n "$CHANGED_FILES" ]; then
        docs-cli check-stale --internal || {
            echo "Broken internal links found. Fix before committing."
            exit 1
        }
    fi
fi

exit 0
```

Install Script: `scripts/install-hooks.sh`

```bash
#!/bin/bash
git config core.hooksPath .githooks
echo "Hooks installed from .githooks/"
```

---

## 8. Self-Management Flow

### 8.1 Automated Update Triggers

| Trigger | Action | Result |
|---------|--------|--------|
| Proto file modified | CI runs docs-cli sync --proto | api-reference/ pages updated |
| SDK code changed | CI runs docs-cli sync --sdk | sdks/ pages updated |
| Test file added/changed | CI runs docs-cli sync --connectors | Feature matrix updated |
| New connector added | Manual: docs-cli create-page connectors/<name>.md | Template page created |
| Daily scheduled | CI runs docs-cli check-stale | Broken links reported |

### 8.2 AI-Assisted Content Generation (Manual Process)

AI assistance is a MANUAL process with CLI helpers:

1. **Create skeleton page:**
   ```bash
   docs-cli create-page connectors/newco.md --from-template connector
   ```

2. **Generate content prompt (CLI helper):**
   ```bash
   docs-cli generate-prompt connectors/newco.md --output prompt.txt
   ```
   This creates a prompt with:
   - Proto definitions for the connector
   - Test file snippets
   - Template placeholders to fill

3. **Use external AI (Claude, GPT-4, etc.) with the prompt**
   - Copy prompt.txt content
   - Paste into AI chat
   - Review and copy generated content

4. **Fill template with AI output:**
   ```bash
   docs-cli fill-template connectors/newco.md --from generated-content.md
   ```

5. **Tech writer reviews and marks as reviewed:**
   ```bash
   docs-cli review connectors/newco.md --reviewer "tech-writer"
   ```

Note: There is NO direct AI API integration. The CLI helps prepare prompts and fill templates, but AI interaction is manual.

### 8.3 Documentation Health Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Stale Links | < 1% | docs-cli check-stale --report |
| Coverage | 100% RPCs documented | docs-cli validate --coverage |
| Freshness | < 30 days since update | Front matter last_updated check |
| Code Examples | All runnable | Example execution tests |
| Formatting | 0 violations | docs-cli validate |
| Mobile Rendering | All pages render | GitBook preview automation |

---

## 9. Revision History

| Version | Date | Status | Description |
|---------|------|--------|-------------|
| 0.1 | 2026-02-25 | Draft | Initial specification |
| 0.2 | 2026-02-25 | Revision 1 | Major issues resolved (5 M items) |
| 1.0 | 2026-02-25 | Approved | All issues resolved, ready for implementation |
| 1.0 | 2026-03-03 | Implementation Ready | Saved to docs-new/specs |

---

## Appendix: Connector Inventory

Based on repository analysis, the following connectors exist and require documentation:

### A-P
aci, adyen, airwallex, authipay, authorizedotnet, bambora, bamboraapac, bankofamerica, barclaycard, billwerk, bluesnap, braintree, calida, cashfree, cashtocode, celero, checkout, cryptopay, cybersource, datatrans, dlocal, elavon, fiserv, fiservemea, fiuu, forte, getnet, gigadat, globalpay, helcim, hipay, hyperpg, iatapay, jpmorgan, loonio, mifinity, mollie, multisafepay, nexinets, nexixpay, nmi, noon, novalnet, nuvei, paybox, payload, payme, paypal, paysafe, paytm, payu, phonepe, placetopay, powertranz

### R-Z
rapyd, razorpay, razorpayv2, redsys, revolut, revolv3, shift4, silverflow, stax, stripe, trustpay, trustpayments, tsys, volt, wellsfargo, worldpay, worldpayvantiv, worldpayxml, xendit, zift

**Total: 100+ connectors**
