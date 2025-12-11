---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Quality Scoring System

## Score Calculation

```
Score = 100 - (Critical × 20) - (Warning × 5) - (Suggestion × 1)
```

## Thresholds

| Score | Rating | Action |
|-------|--------|--------|
| 95-100 | Excellent ✨ | Auto-pass |
| 90-94 | Good ✅ | Pass |
| 80-89 | Fair ⚠️ | Blocked - requires feedback |
| 60-79 | Poor ❌ | Blocked |
| 0-59 | Critical 🚨 | Blocked |

## Critical Violations (Auto-block)

Each violation deducts **20 points**:

1. Using `RouterData` instead of `RouterDataV2`
2. Using `ConnectorIntegration` instead of `ConnectorIntegrationV2`
3. Hardcoded reference IDs
4. Mutated reference IDs (`.to_uppercase()`, `.replace()`, etc.)
5. Primitive amount types (`i64`, `f64` instead of `MinorUnit`)
6. Missing or empty amount converters
7. Using `.unwrap()` instead of `?`
8. Unknown status → `Failure` (should be `Pending`)
9. Changing parent payment status on refund
10. Unsafe code blocks
11. Hardcoded credentials or API keys

## Pre-Submission Checklist

- [ ] `RouterDataV2` used (not `RouterData`)
- [ ] `ConnectorIntegrationV2` used (not `ConnectorIntegration`)
- [ ] All amounts use `MinorUnit` type
- [ ] Amount converters declared in `create_all_prerequisites!`
- [ ] Reference IDs from `router_data.connector_request_reference_id.clone()`
- [ ] No hardcoded reference IDs (search: `"test-`, `uuid::`, `format!`)
- [ ] No `.unwrap()` calls
- [ ] PII fields wrapped in `Secret<>`
- [ ] Unknown statuses map to `Pending`
- [ ] Refund responses keep parent status as `Charged`
