# Project Brief: Open-Source Payments Connector Service

## Mission Statement

The "Connector Service" is an open-source, stateless merchant payments abstraction service built using gRPC that enables developers to integrate with a wide variety of payment processors using a unified contract. It represents the "Linux moment" for payments, liberating merchants and fintechs from being locked-in to the contract of a single payment processor and making switching payment processors a breeze.

## Core Requirements

1. **Unified Contract**: Provide a consistent API across multiple payment processors, abstracting away the differences in their implementations.

2. **Connector Integration**: Establish and accept connections to numerous remote endpoints of payment processors like Stripe, Adyen, Razorpay, etc.

3. **Payment Lifecycle Management**: Support all payment lifecycle operations including:
   - Authorization
   - Capture
   - Refunds
   - Status checks
   - Chargebacks
   - Dispute handling
   - Webhook normalization

4. **Multi-language Support**: Provide client SDKs in multiple programming languages (Java, Python, Go, Rust, PHP) for rapid integration.

5. **Stateless Architecture**: Maintain a stateless design to ensure scalability and reliability.

6. **Extensibility**: Allow for easy addition of new payment processors through a well-defined connector interface.

## Goals

1. **Processor Independence**: Liberate merchants from being locked into a single payment processor's contract.

2. **Simplified Integration**: Reduce the complexity of integrating with multiple payment processors.

3. **Seamless Switching**: Enable businesses to switch processors without disrupting their internal business logic.

4. **Global Coverage**: Eventually encompass the widest variety of processor support across the globe through community contributions.

5. **Production Readiness**: Provide a robust, production-ready service that can handle real-world payment processing needs.

6. **Community Driven**: Foster an open-source community around the project to drive adoption and contribution.

## Project Context

The Connector Service has been in production since January 2023 and is a part of Hyperswitch - a Composable & Open Source Payment Orchestration platform, built by the team from Juspay. It is designed for scalability and portability, allowing businesses to seamlessly switch processors without disrupting their internal business logic.

## Related Projects

- **Hyperswitch**: Built on top of Connector Service, Hyperswitch offers a complete payments orchestration layer with routing, retries, and full lifecycle management.
