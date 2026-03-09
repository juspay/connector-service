# Installation

---
title: Installation
description: SDK installation, API configuration, and environment setup for Connector Service
last_updated: 2026-03-03
generated_from: N/A
auto_generated: false
reviewed_by: tech-writer
reviewed_at: 2026-03-03
approved: true
---

## Overview

This guide walks you through installing Connector Service SDKs and configuring your environment for development and production use.

## SDK Installation

### Node.js

```bash
# Using npm
npm install @juspay/connector-service-sdk

# Using yarn
yarn add @juspay/connector-service-sdk

# Using pnpm
pnpm add @juspay/connector-service-sdk
```

### Python

```bash
# Using pip
pip install juspay-connector-service

# Using poetry
poetry add juspay-connector-service

# Using uv
uv pip install juspay-connector-service
```

### Java (Maven)

```xml
<dependency>
    <groupId>in.juspay</groupId>
    <artifactId>connector-service-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Java (Gradle)

```groovy
dependencies {
    implementation 'in.juspay:connector-service-sdk:1.0.0'
}
```

### .NET

```bash
# Using dotnet CLI
dotnet add package Juspay.ConnectorService

# Using NuGet Package Manager
Install-Package Juspay.ConnectorService
```

### Go

```bash
go get github.com/juspay/connector-service-sdk-go
```

### Haskell

```bash
# Add to your cabal file
build-depends: connector-service-sdk >= 1.0.0

# Or using stack
stack build connector-service-sdk
```

## API Credentials Setup

### 1. Obtain Credentials

1. Log in to the [Juspay Dashboard](https://dashboard.juspay.in)
2. Navigate to **Settings > API Keys**
3. Generate a new API key (save it securely - it won't be shown again)
4. Note your **Merchant ID** from the dashboard header

### 2. Environment Variables

Create a `.env` file in your project root:

```bash
# Required
UCS_API_KEY="your-api-key-here"
UCS_MERCHANT_ID="your-merchant-id"

# Optional - defaults shown
UCS_API_ENDPOINT="https://api.juspay.in"  # Production
# UCS_API_ENDPOINT="https://sandbox.juspay.in"  # Sandbox
UCS_TIMEOUT_MS="30000"
UCS_MAX_RETRIES="3"
```

### 3. Load Environment Variables

**Node.js:**
```javascript
require('dotenv').config();
const apiKey = process.env.UCS_API_KEY;
const merchantId = process.env.UCS_MERCHANT_ID;
```

**Python:**
```python
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv('UCS_API_KEY')
merchant_id = os.getenv('UCS_MERCHANT_ID')
```

## Verify Installation

### Health Check

```bash
# Using curl (language-agnostic)
curl -X POST https://api.juspay.in/v2/health \
  -H "Authorization: Bearer $UCS_API_KEY" \
  -H "Content-Type: application/json"
```

### SDK Health Check

**Node.js:**
```javascript
const { ConnectorClient } = require('@juspay/connector-service-sdk');

const client = new ConnectorClient({
  apiKey: process.env.UCS_API_KEY,
  merchantId: process.env.UCS_MERCHANT_ID
});

async function verify() {
  try {
    const health = await client.health.check();
    console.log('✅ Connected to Connector Service');
    console.log('Status:', health.status);
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
  }
}

verify();
```

## Environment-Specific Configuration

| Environment | Endpoint | Use Case |
|-------------|----------|----------|
| Sandbox | `https://sandbox.juspay.in` | Development, testing |
| Production | `https://api.juspay.in` | Live transactions |

### Switching Environments

```javascript
// Node.js example
const client = new ConnectorClient({
  apiKey: process.env.UCS_API_KEY,
  merchantId: process.env.UCS_MERCHANT_ID,
  environment: process.env.NODE_ENV === 'production' ? 'production' : 'sandbox'
});
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Authentication failed" | Verify API key is correct and not expired |
| "Merchant not found" | Check MERCHANT_ID format (should be alphanumeric) |
| "Connection timeout" | Check firewall settings and UCS_TIMEOUT_MS value |
| "SSL certificate error" | Update system CA certificates |

## Next Steps

- [Quick Start Guide](./quick-start.md) - Process your first payment
- [Concepts](./concepts.md) - Understand core abstractions
- [SDK Documentation](../sdks/) - Language-specific guides
