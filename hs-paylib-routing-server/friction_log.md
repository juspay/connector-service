# Friction Log

## Executive Summary

### Pattern: Package discoverability friction

- The PyPI page could not be read cleanly through a simple fetch because it served a JavaScript challenge page.
- The installed package name is `hs-paylib`, but the import surface is exposed as `payments`, not `hs_paylib`.

### Pattern: Connector-specific behavior hidden behind a unified SDK

- The SDK offers a common `refund` interface, but Adyen required a connector-specific refund reason format that differs from Stripe.
- Adyen refund creation is asynchronous in sandbox and returns `REFUND_PENDING`, while Stripe returned immediate `REFUND_SUCCESS`.

### Pattern: Fast path to working examples exists, but is scattered

- The most reliable integration guidance came from generated connector examples already present in the repository, not from the package landing page.
- The examples showed that Adyen requests need browser information for card flows, which was not obvious from the generic client signature alone.

## Recommendations By Criticality

### Critical

- Publish a clear import example on PyPI showing that `hs-paylib` is consumed via `from payments import ...`.
- Document connector-specific field/value differences that break the otherwise unified contract, especially refund reason handling.

### High

- Add a minimal end-to-end example in the package docs for two connectors with different runtime behavior.
- Document expected sandbox outcomes per connector, including synchronous versus asynchronous refunds.

### Medium

- Provide a concise credential-loading example using `creds.json` style files.
- Add a table mapping package name, module name, and top-level clients.

## Detailed Log

| Step | Friction Point | Pattern | Time Wasted | How It Was Overcome |
| --- | --- | --- | --- | --- |
| 1 | PyPI page fetch returned a JavaScript challenge instead of usable docs. | Discoverability | 8 minutes | Installed the package in the repo virtualenv and inspected the installed files directly. |
| 2 | `import hs_paylib` failed even after installation. | Naming mismatch | 10 minutes | Inspected `site-packages` and found the real import namespace was `payments`. |
| 3 | The package API shape was not obvious from the package name alone. | Discoverability | 7 minutes | Read `payments/__init__.py`, generated service clients, and connector examples in `examples/stripe` and `examples/adyen`. |
| 4 | First Adyen refund attempt failed with `Invalid merchant refund reason`. | Connector-specific contract leak | 15 minutes | Re-ran the flow with alternate reason values until the accepted Adyen sandbox format, `CUSTOMER REQUEST`, was confirmed. |
| 5 | It was unclear whether Adyen refund pending meant failure. | Async behavior variance | 6 minutes | Confirmed that Adyen refund creation returned `REFUND_PENDING` with a created refund reference, which is the expected asynchronous behavior for that sandbox flow. |
| 6 | Connector request requirements differed although both used the same client. | Unified interface mismatch | 5 minutes | Kept `browser_info` in the shared authorize builder because Adyen's generated example included it and Stripe tolerated it. |

Total estimated time wasted due to friction: 51 minutes.

## Assumptions And How They Were Resolved

| Assumption | Why It Was Needed | Resolution |
| --- | --- | --- |
| The deliverable should be a Python server app, not a Node app. | The request said both `node server app` and `python server app`. | Clarified and proceeded with a Python server app. |
| Stripe should handle USD and Adyen should handle EUR only. | Routing rules needed to be explicit for the server API. | Encoded the rule directly in `app/config.py` and exposed it through `/routing-rules`. |
| Demo storage could be in-memory. | Refund requests need a way to look up the original connector transaction. | Stored `payment_id -> connector transaction` in memory and documented that this is a demo assumption. |
| Adyen pending refund is acceptable expected behavior. | User asked for tested behavior, not necessarily final settlement. | Validated that the sandbox accepted the refund and returned a refund reference with `REFUND_PENDING`. |
| The provided creds file should remain external and not be copied into the repo. | Avoid duplicating secrets into new files. | Loaded credentials from the provided path at runtime via CLI or environment variable. |

## Deliverable Paths

- Server app: `/Users/amitsingh.tanwar/Documents/connector-service/connector-service/hs-paylib-routing-server`
- Friction log: `/Users/amitsingh.tanwar/Documents/connector-service/connector-service/hs-paylib-routing-server/friction_log.md`
