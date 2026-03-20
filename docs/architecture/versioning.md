<!--
@doc-guidance
────────────────────────────────────────────────────
PAGE INTENT: The connector service follow semantic versioning. new integrations, features on the .X. and bug fixes/ security fixes on the . .X and major uppgrade on the major version. How developers are supposed to integrated the library with 1.2.* to ensure that the bug fixes are auaomatically pulled.

AUDIENCE: Payment developers and architects
TONE: Direct, conversational, opinionated. Write like explaining to a colleague over coffee.
PRIOR READING: [What pages should the reader have seen before this one? Link them.]
LEADS INTO: [What page comes next?]
────────────────────────────────────────────────────
LENGTH: 1.5–2 pages max (~600–800 words prose, tables and code blocks don't count toward this).
         If you need more space, the page is doing too much — split it.

WRITING RULES:
1. FIRST SENTENCE RULE — Open with what the reader gains, not what the thing is.
   Bad:  "The Prism SDK provides a unified interface..."
   Good: "You call one method. It works with Stripe, Adyen, or any of 50+ processors."

2. NO HEDGING — Delete: "can be", "may", "it is possible to", "in some cases", "typically".
   Say what IS. If something is conditional, state the condition.

3. VERB OVER NOUN — "lets you configure" not "provides configuration capabilities".
   "transforms the request" not "performs request transformation".

4. ONE IDEA PER SECTION — If a section has more than one takeaway, split it.

5. SHOW THEN TELL — Code example or diagram first, explanation after.
   The reader should see what it looks like before reading why.

6. EARN EVERY SENTENCE — If removing a sentence doesn't lose information, remove it.
   No "In this section, we will discuss..." No "As mentioned earlier..."
   No "It is important to note that..."

7. SPECIFICS OVER CLAIMS — Never say "supports many payment methods".
   Say "supports cards, wallets (Apple Pay, Google Pay), bank transfers, BNPL, and UPI".

8. ERRORS ARE FEATURES — When documenting a flow, show what goes wrong too.
   Include at least one error scenario with the actual error message.

9. NAME THE PRODUCT "Prism" — Not "UCS", not "the service", not "our platform".

10. TABLES FOR COMPARISON, PROSE FOR NARRATIVE — Don't put a story in a table.
     Don't write paragraphs when a 3-row table would be clearer.

CODE EXAMPLE RULES:
- Every code block must be runnable or clearly marked as pseudocode
- Use test credentials: Stripe key as $STRIPE_API_KEY, card 4242424242424242
- Show the output, not just the input
- If the example needs setup, show the setup

ANTI-PATTERNS TO REJECT:
- "Comprehensive", "robust", "seamless", "leverage", "utilize", "facilitate"
- Starting paragraphs with "Additionally", "Furthermore", "Moreover"
- Any sentence that describes the documentation itself ("This guide covers...")
- Repeating the heading as the first sentence of a section
────────────────────────────────────────────────────
-->

# Versioning

You update your dependency and critical payment flows break. Or worse: you miss a security patch because you pinned too conservatively. Prism uses semantic versioning to give you control over what changes land in your codebase.

```
MAJOR.MINOR.PATCH
  1    .2    .3
```

## Version Number Meanings

| Position | When It Changes | What It Means for You |
|----------|-----------------|----------------------|
| **MAJOR** (1.x.x → 2.x.x) | Breaking API changes | You must update your code. Migration guide provided. |
| **MINOR** (1.2.x → 1.3.x) | New features, new connectors | Add capabilities without touching existing code. |
| **PATCH** (1.2.3 → 1.2.4) | Bug fixes, security patches | Update automatically. Zero code changes required. |

Prism follows [Semantic Versioning 2.0.0](https://semver.org/). A minor version never breaks your existing integration. A patch version only fixes things.

## Pinning for Automatic Bug Fixes

You want security patches and critical fixes without manual updates. Pin your dependency to accept patch increments automatically.

<!-- tabs:start -->

#### **Node.js (package.json)**

```json
{
  "dependencies": {
    "@juspay/connector-service-node": "1.2.*"
  }
}
```

This accepts: `1.2.0`, `1.2.1`, `1.2.4`, `1.2.15`  
This rejects: `1.3.0`, `2.0.0`

#### **Python (requirements.txt)**

```
juspay-connector-service==1.2.*
```

Or in `pyproject.toml`:

```toml
[tool.poetry.dependencies]
juspay-connector-service = "1.2.*"
```

#### **Java (Maven)**

```xml
<dependency>
    <groupId>com.juspay</groupId>
    <artifactId>connector-service</artifactId>
    <version>[1.2.0,1.3.0)</version>
</dependency>
```

The `[1.2.0,1.3.0)` syntax means: 1.2.0 inclusive, 1.3.0 exclusive.

#### **Rust (Cargo.toml)**

```toml
[dependencies]
connector-service = "1.2"
```

Cargo treats `1.2` as `^1.2.0`, which accepts `1.2.0` through `1.2.999` but not `1.3.0`.

<!-- tabs:end -->

## What You Get Automatically

When you pin to `1.2.*`, your build system pulls these automatically:

**Patch releases (automatic):**
- Security fixes for connector authentication
- Bug fixes for specific PSP error parsing
- Performance improvements
- Documentation corrections

**Minor releases (manual opt-in):**
- New connector support (e.g., "Added Peach Payments")
- New payment methods (e.g., "Added UPI")
- New SDK features (e.g., "Added async streaming")
- Deprecation warnings for old APIs

**Major releases (manual migration):**
- Breaking changes to core types
- Removal of deprecated methods
- Fundamental architecture changes

## The Risk of Pinning Too Tightly

```json
{
  "dependencies": {
    "@juspay/connector-service-node": "1.2.3"
  }
}
```

This pins exactly to `1.2.3`. You miss:
- `1.2.4` — Fix for Stripe webhook signature verification
- `1.2.5` — Security patch for Adyen credential handling
- `1.2.6` — Critical fix for refund idempotency keys

Your code works today. It breaks tomorrow when Stripe rotates certificates and you lack the fix.

## The Risk of Pinning Too Loosely

```json
{
  "dependencies": {
    "@juspay/connector-service-node": "*"
  }
}
```

This accepts any version, including `2.0.0` with breaking changes. Your CI passes today. Production fails tomorrow when a new major version introduces API changes.

## Recommended Strategy

Pin to minor version for active development:

```
1.2.*
```

This gives you:
- Automatic security patches
- Automatic bug fixes
- No surprise breaking changes
- Control over when new features arrive

Update minor versions intentionally when you need new connectors or features. Read the changelog. Run your integration tests. Then bump the pin.

## Version Compatibility Matrix

Prism maintains compatibility across SDK languages for the same minor version:

| Prism Version | Node.js SDK | Python SDK | Java SDK | Rust SDK |
|---------------------------|-------------|------------|----------|----------|
| 1.2.x | 1.2.x | 1.2.x | 1.2.x | 1.2.x |
| 1.3.x | 1.3.x | 1.3.x | 1.3.x | 1.3.x |

All SDKs for version `1.2.x` speak the same protocol, support the same connectors, and handle the same error codes. Mixing SDK versions (Node.js at `1.2.5`, Python at `1.3.0`) works but may produce different behaviors for newer features.

## Checking Your Current Version

```bash
# Node.js
npm list @juspay/connector-service-node

# Python
pip show juspay-connector-service

# Java
mvn dependency:tree | grep connector-service

# Rust
cargo tree | grep connector-service
```

## Deprecation Policy

Prism maintains deprecated APIs for one full major version. When `2.0.0` releases:
- APIs deprecated in `1.x` are removed
- Migration guides are published
- Automated codemods are provided where possible

You have the entire `1.x` lifecycle to update your code before breaking changes arrive.

---

**Pin to `MAJOR.MINOR.*`. Get fixes automatically. Control features manually. Sleep soundly.**
