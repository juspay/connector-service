# Dapr Kafka Integration Example

This example demonstrates how to use Dapr to publish messages to Kafka topics.

## Overview

The example consists of:

1. A Kafka broker running in a container
2. A Rust publisher application that sends messages to a Kafka topic via Dapr
3. A direct verification mechanism to confirm messages are delivered to Kafka

## Prerequisites

- [Dapr CLI](https://docs.dapr.io/getting-started/install-dapr-cli/)
- [Podman](https://podman.io/getting-started/installation) (or Docker)
- [podman-compose](https://github.com/containers/podman-compose) (or docker-compose)
- [Rust](https://www.rust-lang.org/tools/install) (to build and run the example)
- [jq](https://stedolan.github.io/jq/download/) (for JSON formatting in verification)

## Running the Example

There are two ways to run this example:

### Option 1: Automated Demo Script

For a quick demonstration of the full system, use the demo script:

```bash
./demo_rust.sh
```

This script will:
1. Start Kafka and Zookeeper
2. Send a test message using the Rust publisher
3. Verify the message was delivered to Kafka
4. Clean up all resources when done

This is the easiest way to see the entire system in action.

### Option 2: Interactive Manual Demo

For a more interactive experience with manual control of each step, use:

```bash
./demo_manual.sh help
```

The manual demo script provides several commands:

```bash
./demo_manual.sh start         # Start Kafka and Zookeeper
./demo_manual.sh publish       # Publish a message (with optional parameters)
./demo_manual.sh verify <id>   # Verify a specific message by ID
./demo_manual.sh view          # View all messages in Kafka
./demo_manual.sh stop          # Stop Kafka and Zookeeper
./demo_manual.sh demo          # Run a full automated demo
```

This interactive approach gives you fine-grained control over each step in the demo.

## Sending Messages Manually

If you want to test publishing a message directly (without using any script), you can use curl:

```bash
curl -X POST http://localhost:<DAPR_HTTP_PORT>/v1.0/publish/kafka-pubsub/payment-events \
  -H "Content-Type: application/json" \
  -d '{"payment_id":"test_payment_123", "amount":100.0, "currency":"USD", "status":"completed"}'
```

Replace `<DAPR_HTTP_PORT>` with the HTTP port of the Dapr sidecar (from the output of `dapr list`).

## Component Configuration

The Dapr component configuration is in `components/kafka-pubsub.yaml`. This defines the Kafka pubsub component that Dapr will use to communicate with Kafka.

## Architecture

```
┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│   Publisher   │         │     Dapr      │         │     Kafka     │
│  Application  │ ──────► │   Sidecar     │ ──────► │     Broker    │
└───────────────┘         └───────────────┘         └───────────────┘
```

## Implementation Details

### Publisher

The publisher is implemented in Rust using the `reqwest` HTTP client to communicate with the Dapr API. It sends a JSON payload to the `payment-events` topic via Dapr's HTTP API.

### Verification

The verification is done by directly querying Kafka for messages. Both demo scripts include built-in verification that searches for a specific payment ID in the Kafka topic and formats the output using jq.

## Troubleshooting

- If you see errors connecting to Kafka, make sure Kafka is running and accessible.
- Check the Dapr logs for any component initialization errors.
- Verify that the component configuration in `components/kafka-pubsub.yaml` is correct.
- If the publisher fails to connect to the Dapr sidecar, make sure the port is correct.
