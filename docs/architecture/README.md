## The Problem

If you've integrated multiple payment providers, you know the pain:
- Stripe uses PaymentIntents
- Adyen uses payments
- PayPal uses orders

All of them do the same job, but each has different field names, different status enums, different error formats.

This problem exists in other domains too, but solved with well maintained developer centric libraries, open source and free from vendor lock-in.

| Domain | Unified Interface | What It Solves |
|--------|-------------------|----------------|
| **LLMs** | [LiteLLM](https://github.com/BerriAI/litellm) | One interface for OpenAI, Anthropic, Google, etc. |
| **Databases** | [Prisma](https://www.prisma.io/) | One ORM for PostgreSQL, MySQL, MongoDB, etc. |
| **Cloud Storage** | [Rclone](https://rclone.org/) | One CLI for S3, GCS, Azure Blob, etc. |

**But for payments, no such equivalent exists for developers.**

Connector Service is the unified abstraction layer for payment processors—giving you one API, one set of types, and one mental model for 100+ payment connectors.