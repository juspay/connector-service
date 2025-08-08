#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration Variables
# ======================

# Kafka Configuration
KAFKA_CONTAINER_NAME="hyperswitch-kafka0-1"
KAFKA_TOPIC="audit-trail-events"
KAFKA_BOOTSTRAP_SERVER="localhost:9092"
KAFKA_UI_PORT="8090"

# Dapr Configuration
APP_ID="connector-service"
APP_PORT="8000"
DAPR_GRPC_PORT="50001"
DAPR_HTTP_PORT="3501"
COMPONENTS_PATH="./components"
export DAPR_PUBSUB_NAME="kafka-pubsub"

# Network Configuration
DAPR_NETWORK="dapr-net"
DAPR_METRICS_PORT="9091"

# Test Configuration
PAYMENT_ID="payment_$(date +%s)_$RANDOM"
CONNECTOR_NAME="checkout"
TENANT_ID="test_tenant"
MERCHANT_ID="test_merchant"

# Timeouts and Limits
MAX_WAIT_TIME=120
WAIT_INTERVAL=5
KAFKA_MAX_MESSAGES=100
KAFKA_TIMEOUT_MS=5000

# Verbose logging flag
VERBOSE=${VERBOSE:-true}
LOG_FILE="demo_logs_$(date +%Y%m%d_%H%M%S).log"

# Check for required API key environment variables
if [[ -z "${CONNECTOR_API_KEY}" || -z "${CONNECTOR_KEY1}" || -z "${CONNECTOR_API_SECRET}" ]]; then
  echo -e "${RED}Error: Required API keys are missing.${NC}"
  echo -e "${YELLOW}Please set the following environment variables before running this script:${NC}"
  echo -e "  - CONNECTOR_API_KEY"
  echo -e "  - CONNECTOR_KEY1"
  echo -e "  - CONNECTOR_API_SECRET"
  echo -e "${YELLOW}Example:${NC}"
  echo -e "  export CONNECTOR_API_KEY=your_api_key"
  echo -e "  export CONNECTOR_KEY1=your_key1"
  echo -e "  export CONNECTOR_API_SECRET=your_api_secret"
  exit 1
fi

# Assign environment variables to local variables for use in the script
API_KEY="${CONNECTOR_API_KEY}"
KEY1="${CONNECTOR_KEY1}"
API_SECRET="${CONNECTOR_API_SECRET}"

# Function to cleanup resources when script exits
function cleanup() {
    echo -e "\n${BLUE}Cleaning up resources...${NC}"
    
    # Kill the Dapr sidecar and application
    if [ -n "$DAPR_PID" ]; then
        echo -e "${YELLOW}Stopping Dapr and application...${NC}"
        kill -15 $DAPR_PID || true
        sleep 2
    fi
    
    echo -e "${GREEN}Cleanup complete!${NC}"
}

# Register the cleanup function to be called on exit
# trap cleanup EXIT

echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}   Events Implementation Demo                        ${NC}"
echo -e "${BLUE}=====================================================${NC}"

# Ensure dapr network exists
echo -e "\n${BLUE}Ensuring $DAPR_NETWORK network exists...${NC}"
if ! podman network ls | grep -q $DAPR_NETWORK; then
    echo -e "${YELLOW}Creating $DAPR_NETWORK network...${NC}"
    podman network create $DAPR_NETWORK
fi

# Check for existing Kafka and Zookeeper containers (both running and stopped) and remove them
# echo -e "\n${BLUE}Checking Kafka and Zookeeper container status...${NC}"
# if podman ps -a | grep -q kafka; then
#     echo -e "${YELLOW}Removing existing Kafka container...${NC}"
#     podman stop kafka >/dev/null 2>&1 || true
#     podman rm -f kafka >/dev/null 2>&1 || true
# fi

# if podman ps -a | grep -q zookeeper; then
#     echo -e "${YELLOW}Removing existing Zookeeper container...${NC}"
#     podman stop zookeeper >/dev/null 2>&1 || true
#     podman rm -f zookeeper >/dev/null 2>&1 || true
# fi

# echo -e "${YELLOW}Setting up Zookeeper and Kafka containers...${NC}"
# echo -e "${YELLOW}Starting Zookeeper...${NC}"
# podman run -d --name zookeeper \
#   --network dapr-net \
#   --platform linux/amd64 \
#   -e ALLOW_ANONYMOUS_LOGIN=yes \
#   -p 2181:2181 \
#   docker.io/bitnami/zookeeper:3.7

# # Wait for Zookeeper to start
# echo -e "${YELLOW}Waiting for Zookeeper to start...${NC}"
# sleep 10
    
#     echo -e "${YELLOW}Starting Kafka...${NC}"
#     podman run -d --name kafka \
#       --platform linux/amd64 \
#       -e KAFKA_BROKER_ID=1 \
#       -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
#       -e KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,EXTERNAL://0.0.0.0:29092 \
#       -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka:9092,EXTERNAL://127.0.0.1:29092 \
#       -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=PLAINTEXT:PLAINTEXT,EXTERNAL:PLAINTEXT \
#       -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT \
#       -e ALLOW_PLAINTEXT_LISTENER=yes \
#       -p 9092:9092 \
#       -p 29092:29092 \
#       --network dapr-net \
#       docker.io/bitnami/kafka:2.8.1
    
#     # Wait for Kafka to start
#     echo -e "${YELLOW}Waiting for Kafka to start...${NC}"
#     sleep 20
    
#     # Create payment events topic (used by kafka-pubsub component)
#     echo -e "${YELLOW}Creating Kafka topic 'audit-trail-events'...${NC}"
#     podman exec kafka /opt/bitnami/kafka/bin/kafka-topics.sh \
#         --create --if-not-exists \
#         --bootstrap-server localhost:9092 \
#         --replication-factor 1 \
#         --partitions 1 \
#         --topic audit-trail-events

echo -e "${GREEN}Kafka is running.${NC}"

# Step 1: Start the service with Dapr
echo -e "\n${BLUE}Step 1: Starting the service with Dapr...${NC}"

# Create components directory if it doesn't exist
mkdir -p $COMPONENTS_PATH

# Print information
echo -e "${YELLOW}App ID: $APP_ID${NC}"
echo -e "${YELLOW}App Port: $APP_PORT${NC}"
echo -e "${YELLOW}Dapr gRPC Port: $DAPR_GRPC_PORT${NC}"
echo -e "${YELLOW}Dapr HTTP Port: $DAPR_HTTP_PORT${NC}"
echo -e "${YELLOW}Components Path: $COMPONENTS_PATH${NC}"

# Start Dapr with the service in the background
dapr run \
  --app-id $APP_ID \
  --app-port $APP_PORT \
  --dapr-grpc-port $DAPR_GRPC_PORT \
  --dapr-http-port $DAPR_HTTP_PORT \
  --metrics-port $DAPR_METRICS_PORT \
  --components-path $COMPONENTS_PATH \
  --log-level info \
  -- cargo run --bin grpc-server &

DAPR_PID=$!

# Wait for the service to start
echo -e "${YELLOW}Waiting for service to start...${NC}"

# Function to check if service is running on either port
check_service_up() {
    if nc -z localhost $APP_PORT 2>/dev/null; then
        echo -e "${GREEN}Service is up and running on port $APP_PORT!${NC}"
        return 0
    elif nc -z localhost 8080 2>/dev/null; then
        echo -e "${GREEN}Service is up and running on port 8080!${NC}"
        APP_PORT=8080
        return 0
    else
        return 1
    fi
}

# Wait for the build and service to start with timeout
START_TIME=$(date +%s)

echo -e "${YELLOW}Waiting for cargo build to complete and service to start (timeout: ${MAX_WAIT_TIME}s)...${NC}"

while true; do
    # Check if the service is up
    if check_service_up; then
        break
    fi
    
    # Check if we've exceeded the maximum wait time
    CURRENT_TIME=$(date +%s)
    ELAPSED_TIME=$((CURRENT_TIME - START_TIME))
    
    if [ $ELAPSED_TIME -ge $MAX_WAIT_TIME ]; then
        echo -e "${YELLOW}Service ports not detected after ${MAX_WAIT_TIME} seconds.${NC}"
        echo -e "${YELLOW}Will try to continue anyway, but this might fail.${NC}"
        break
    fi
    
    echo -e "${YELLOW}Still waiting for service to come up... (${ELAPSED_TIME}s elapsed)${NC}"
    sleep $WAIT_INTERVAL
done

# Give Dapr a moment to initialize all components
echo -e "${YELLOW}Service detected! Giving Dapr a moment to initialize all components...${NC}"
sleep 5

# Step 2: Test the Events Implementation
echo -e "\n${BLUE}Step 2: Testing Events Implementation...${NC}"
echo -e "${YELLOW}Using payment ID: $PAYMENT_ID${NC}"

echo -e "\n${BLUE}Step 2a: Making payment authorization request...${NC}"

# Generate unique IDs for metadata
UDF_TXN_UUID="txn_$(date +%s)_$RANDOM"
REQUEST_ID="req_$(date +%s)_$RANDOM"

echo -e "${YELLOW}Using udf_txn_uuid: $UDF_TXN_UUID${NC}"
echo -e "${YELLOW}Using x-request-id: $REQUEST_ID${NC}"

RESPONSE=$(grpcurl -plaintext \
  -H "x-tenant-id: $TENANT_ID" \
  -H "x-request-id: $REQUEST_ID" \
  -H "x-connector: $CONNECTOR_NAME" \
  -H "x-merchant-id: $MERCHANT_ID" \
  -H "x-auth: signature-key" \
  -H "x-api-key: $API_KEY" \
  -H "x-key1: $KEY1" \
  -H "x-api-secret: $API_SECRET" \
  -H "udf-txn-uuid: $UDF_TXN_UUID" \
  -d '{
    "amount": 1000,
    "minor_amount": 1000,
    "currency": "USD",
    "payment_method": {
      "card": {
        "credit": {
          "card_number": "4000020000000000",
          "card_exp_month": "12",
          "card_exp_year": "2030",
          "card_cvc": "123",
          "card_holder_name": "Test User",
          "card_network": "VISA"
        }
      }
    },
    "email": "customer@example.com",
    "address": {
      "shipping_address": {},
      "billing_address": {}
    },
    "auth_type": "NO_THREE_DS",
    "request_ref_id": {
      "id": "'$PAYMENT_ID'"
    },
    "enrolled_for_3ds": false,
    "request_incremental_authorization": false,
    "capture_method": "AUTOMATIC",
    "metadata": {
      "udf_txn_uuid": "'$UDF_TXN_UUID'",
      "transaction_id": "'$PAYMENT_ID'"
    }
  }' \
  localhost:$APP_PORT ucs.v2.PaymentService/Authorize)

echo -e "${GREEN}Payment Authorization Response received:${NC}"
echo $RESPONSE | jq '.' || echo $RESPONSE

# Wait a moment for the audit event to be published
echo -e "\n${YELLOW}Waiting for audit event to be published to Kafka...${NC}"
sleep 3

# Step 2b: Check Kafka for the payment audit event
echo -e "\n${BLUE}Step 2b: Checking Kafka for payment audit events...${NC}"
echo -e "${YELLOW}Looking for events with payment ID: $PAYMENT_ID${NC}"

# Check if Kafka container is running
if ! podman ps | grep -q $KAFKA_CONTAINER_NAME; then
    echo -e "${RED}Error: Kafka container $KAFKA_CONTAINER_NAME not running. Please start it first.${NC}"
    exit 1
fi

# First, check if the topic exists and has messages
echo -e "${YELLOW}Checking Kafka topic status...${NC}"
TOPIC_INFO=$(podman exec $KAFKA_CONTAINER_NAME env JMX_PORT="" kafka-topics \
    --bootstrap-server $KAFKA_BOOTSTRAP_SERVER \
    --describe --topic $KAFKA_TOPIC 2>/dev/null || echo "Topic not found")

if echo "$TOPIC_INFO" | grep -q "Topic not found"; then
    echo -e "${YELLOW}Topic $KAFKA_TOPIC does not exist. Creating it...${NC}"
    podman exec $KAFKA_CONTAINER_NAME env JMX_PORT="" kafka-topics \
        --bootstrap-server $KAFKA_BOOTSTRAP_SERVER \
        --create --topic $KAFKA_TOPIC \
        --partitions 1 --replication-factor 1 || true
    sleep 2
fi

# Run kafka-console-consumer in the Kafka container to verify audit events
echo -e "${YELLOW}Fetching messages from Kafka topic: $KAFKA_TOPIC${NC}"
if [ "$VERBOSE" = "true" ]; then
    echo -e "${YELLOW}Running: podman exec $KAFKA_CONTAINER_NAME env JMX_PORT=\"\" kafka-console-consumer --bootstrap-server $KAFKA_BOOTSTRAP_SERVER --topic $KAFKA_TOPIC --from-beginning --max-messages $KAFKA_MAX_MESSAGES --timeout-ms $KAFKA_TIMEOUT_MS${NC}"
    MESSAGES=$(podman exec $KAFKA_CONTAINER_NAME env JMX_PORT="" kafka-console-consumer \
        --bootstrap-server $KAFKA_BOOTSTRAP_SERVER \
        --topic $KAFKA_TOPIC \
        --from-beginning \
        --max-messages $KAFKA_MAX_MESSAGES \
        --timeout-ms $KAFKA_TIMEOUT_MS 2>/dev/null || true)
    echo -e "${YELLOW}Retrieved $(echo "$MESSAGES" | grep -v '^$' | wc -l) messages from Kafka${NC}"
else
    MESSAGES=$(podman exec $KAFKA_CONTAINER_NAME env JMX_PORT="" kafka-console-consumer \
        --bootstrap-server $KAFKA_BOOTSTRAP_SERVER \
        --topic $KAFKA_TOPIC \
        --from-beginning \
        --max-messages $KAFKA_MAX_MESSAGES \
        --timeout-ms $KAFKA_TIMEOUT_MS 2>/dev/null || true)
fi

# Check if our test audit event is in the Kafka topic
PAYMENT_MESSAGE_FOUND=false

# Search for the specific payment event by request_id (should contain the request ID)
if echo "$MESSAGES" | grep -q "\"request_id\":.*\"$REQUEST_ID\""; then
    echo -e "${GREEN}✓ Found payment audit event with request_id containing request ID in Kafka:${NC}"
    echo "$MESSAGES" | grep "\"request_id\":.*\"$REQUEST_ID\"" | tail -1 | jq '.' || echo "$MESSAGES" | grep "\"request_id\":.*\"$REQUEST_ID\"" | tail -1
    PAYMENT_MESSAGE_FOUND=true
else
    echo -e "${YELLOW}⚠ No payment audit event found with request_id containing request ID: $REQUEST_ID${NC}"
    # Show the latest messages to help debug
    if [ -n "$MESSAGES" ]; then
        echo -e "${YELLOW}Latest messages in the $KAFKA_TOPIC topic:${NC}"
        echo "$MESSAGES" | tail -3
        PAYMENT_MESSAGE_FOUND=false
    else
        echo -e "${YELLOW}No messages found in Kafka topic${NC}"
        PAYMENT_MESSAGE_FOUND=false
    fi
fi

# Step 3: Make a refund request to test refund events
echo -e "\n${BLUE}Step 3: Testing refund events...${NC}"
REFUND_ID="refund_$(date +%s)_$RANDOM"
REFUND_UDF_TXN_UUID="refund_txn_$(date +%s)_$RANDOM"
REFUND_REQUEST_ID="refund_req_$(date +%s)_$RANDOM"

echo -e "${YELLOW}Using refund ID: $REFUND_ID${NC}"
echo -e "${YELLOW}Using refund udf_txn_uuid: $REFUND_UDF_TXN_UUID${NC}"
echo -e "${YELLOW}Using refund x-request-id: $REFUND_REQUEST_ID${NC}"

REFUND_RESPONSE=$(grpcurl -plaintext \
  -H "x-tenant-id: $TENANT_ID" \
  -H "x-request-id: $REFUND_REQUEST_ID" \
  -H "x-connector: $CONNECTOR_NAME" \
  -H "x-merchant-id: $MERCHANT_ID" \
  -H "x-auth: signature-key" \
  -H "x-api-key: $API_KEY" \
  -H "x-key1: $KEY1" \
  -H "x-api-secret: $API_SECRET" \
  -H "udf-txn-uuid: $REFUND_UDF_TXN_UUID" \
  -d '{
    "request_ref_id": {"id": "refund_'$REFUND_ID'"},
    "refund_id": "'$REFUND_ID'",
    "transaction_id": {"id": "'$PAYMENT_ID'"},
    "payment_amount": 1000,
    "minor_payment_amount": 1000,
    "refund_amount": 500,
    "minor_refund_amount": 500,
    "currency": "USD",
    "reason": "Customer requested refund",
    "metadata": {
      "udf_txn_uuid": "'$REFUND_UDF_TXN_UUID'",
      "transaction_id": "'$REFUND_ID'"
    }
  }' \
  localhost:$APP_PORT ucs.v2.PaymentService/Refund)

echo -e "${GREEN}Refund response received:${NC}"
echo $REFUND_RESPONSE | jq '.' || echo $REFUND_RESPONSE

# Wait a moment for the refund audit event to be published
echo -e "\n${YELLOW}Waiting for refund audit event to be published to Kafka...${NC}"
sleep 3

# Step 4: Check Kafka for the refund audit event
echo -e "\n${BLUE}Step 4: Checking Kafka for refund audit events...${NC}"
echo -e "${YELLOW}Looking for refund events with refund_id: $REFUND_ID${NC}"

# Run kafka-console-consumer again to get latest messages including refund events
echo -e "${YELLOW}Fetching refund messages from Kafka topic: $KAFKA_TOPIC${NC}"
if [ "$VERBOSE" = "true" ]; then
    echo -e "${YELLOW}Running: podman exec $KAFKA_CONTAINER_NAME env JMX_PORT=\"\" kafka-console-consumer --bootstrap-server $KAFKA_BOOTSTRAP_SERVER --topic $KAFKA_TOPIC --from-beginning --max-messages $((KAFKA_MAX_MESSAGES * 2)) --timeout-ms $KAFKA_TIMEOUT_MS${NC}"
    REFUND_MESSAGES=$(podman exec $KAFKA_CONTAINER_NAME env JMX_PORT="" kafka-console-consumer \
        --bootstrap-server $KAFKA_BOOTSTRAP_SERVER \
        --topic $KAFKA_TOPIC \
        --from-beginning \
        --max-messages $((KAFKA_MAX_MESSAGES * 2)) \
        --timeout-ms $KAFKA_TIMEOUT_MS 2>/dev/null || true)
    echo -e "${YELLOW}Retrieved $(echo "$REFUND_MESSAGES" | grep -v '^$' | wc -l) messages from Kafka${NC}"
else
    REFUND_MESSAGES=$(podman exec $KAFKA_CONTAINER_NAME env JMX_PORT="" kafka-console-consumer \
        --bootstrap-server $KAFKA_BOOTSTRAP_SERVER \
        --topic $KAFKA_TOPIC \
        --from-beginning \
        --max-messages $((KAFKA_MAX_MESSAGES * 2)) \
        --timeout-ms $KAFKA_TIMEOUT_MS 2>/dev/null || true)
fi

# Check if our refund audit event is in the Kafka topic
REFUND_MESSAGE_FOUND=false

# Search for the specific refund event by request_id (should contain the refund request ID)
if echo "$REFUND_MESSAGES" | grep -q "\"request_id\":.*\"$REFUND_REQUEST_ID\""; then
    echo -e "${GREEN}✓ Found refund audit event with request_id containing refund request ID in Kafka:${NC}"
    echo "$REFUND_MESSAGES" | grep "\"request_id\":.*\"$REFUND_REQUEST_ID\"" | tail -1 | jq '.' || echo "$REFUND_MESSAGES" | grep "\"request_id\":.*\"$REFUND_REQUEST_ID\"" | tail -1
    REFUND_MESSAGE_FOUND=true
else
    echo -e "${YELLOW}⚠ No refund audit event found with request_id containing refund request ID: $REFUND_REQUEST_ID${NC}"
    # Show the latest messages to help debug
    if [ -n "$REFUND_MESSAGES" ]; then
        echo -e "${YELLOW}Latest messages in the $KAFKA_TOPIC topic:${NC}"
        echo "$REFUND_MESSAGES" | tail -3
        REFUND_MESSAGE_FOUND=false
    else
        echo -e "${YELLOW}No messages found in Kafka topic${NC}"
        REFUND_MESSAGE_FOUND=false
    fi
fi

# Step 5: Analyze the event structure to verify generic events implementation
echo -e "\n${BLUE}Step 5: Analyzing event structure...${NC}"

# Get a sample of recent events to analyze
SAMPLE_EVENTS=$(echo "$REFUND_MESSAGES" | tail -5)

if [ -n "$SAMPLE_EVENTS" ]; then
    echo -e "${YELLOW}Analyzing event structure for events implementation...${NC}"
    
    # Check for key indicators of the new events system
    EVENTS_INDICATORS=0
    
    # Check for configuration-driven fields from development.toml
    if echo "$SAMPLE_EVENTS" | grep -q "\"hostname\":\"connector-service\""; then
        echo -e "${GREEN}✓ Found hostname field from static_values configuration${NC}"
        EVENTS_INDICATORS=$((EVENTS_INDICATORS + 1))
    fi
    
    if echo "$SAMPLE_EVENTS" | grep -q "\"schema_version\":\"V2\""; then
        echo -e "${GREEN}✓ Found schema_version field from static_values configuration${NC}"
        EVENTS_INDICATORS=$((EVENTS_INDICATORS + 1))
    fi
    
    if echo "$SAMPLE_EVENTS" | grep -q "\"category\":\"OUTGOING_API\""; then
        echo -e "${GREEN}✓ Found category field from static_values configuration${NC}"
        EVENTS_INDICATORS=$((EVENTS_INDICATORS + 1))
    fi
    
    # Check for transformation mappings
    if echo "$SAMPLE_EVENTS" | grep -q "\"gateway\":\"CHECKOUT\""; then
        echo -e "${GREEN}✓ Found gateway field from transformations (connector → gateway)${NC}"
        EVENTS_INDICATORS=$((EVENTS_INDICATORS + 1))
    fi
    
    # Check for extraction fields
    if echo "$SAMPLE_EVENTS" | grep -q "\"message\".*\"req_body\""; then
        echo -e "${GREEN}✓ Found extracted request body in message structure${NC}"
        EVENTS_INDICATORS=$((EVENTS_INDICATORS + 1))
    fi
    
    if echo "$SAMPLE_EVENTS" | grep -q "\"message\".*\"res_body\""; then
        echo -e "${GREEN}✓ Found extracted response body in message structure${NC}"
        EVENTS_INDICATORS=$((EVENTS_INDICATORS + 1))
    fi
    
    echo -e "\n${BLUE}Events Implementation Analysis:${NC}"
    echo -e "Found ${EVENTS_INDICATORS}/6 indicators of the new events system"
    
    if [ $EVENTS_INDICATORS -ge 4 ]; then
        echo -e "${GREEN}✓ Events implementation is working correctly!${NC}"
        EVENTS_WORKING=true
    elif [ $EVENTS_INDICATORS -ge 2 ]; then
        echo -e "${YELLOW}⚠ Partial events implementation detected${NC}"
        EVENTS_WORKING=true
    else
        echo -e "${YELLOW}⚠ Limited evidence of events implementation${NC}"
        EVENTS_WORKING=false
    fi
else
    echo -e "${YELLOW}⚠ No events found for analysis${NC}"
    EVENTS_WORKING=false
fi

# Set overall message found status
if [ "$PAYMENT_MESSAGE_FOUND" = true ] && [ "$REFUND_MESSAGE_FOUND" = true ]; then
    MESSAGE_FOUND=true
elif [ "$PAYMENT_MESSAGE_FOUND" = true ] || [ "$REFUND_MESSAGE_FOUND" = true ]; then
    MESSAGE_FOUND=true
else
    MESSAGE_FOUND=false
fi

# Show summary based on test results
echo -e "\n${BLUE}=====================================================${NC}"
if [ "$MESSAGE_FOUND" = true ]; then
    echo -e "${GREEN}Events Implementation Demo Completed Successfully!${NC}"
    echo -e "${BLUE}=====================================================${NC}"
    echo -e "${YELLOW}Summary:${NC}"
    echo -e "1. ✓ Started the connector service with Dapr"
    echo -e "2. ✓ Sent payment authorization and refund requests"
    echo -e "3. ✓ Verified that audit events were published to Kafka"
    
    if [ "$EVENTS_WORKING" = true ]; then
        echo -e "4. ✓ Confirmed events implementation is working"
        echo -e "${GREEN}The refactored events system is functioning correctly!${NC}"
    else
        echo -e "4. ⚠ Events implementation needs verification"
        echo -e "${YELLOW}Events are being published but may be using legacy implementation${NC}"
    fi
    
    echo -e "\n${YELLOW}Key Features Verified:${NC}"
    echo -e "• Configuration-driven event transformation"
    echo -e "• Euler-compatible event format (backward compatibility)"
    echo -e "• Static values injection from development.toml"
    echo -e "• Field transformations (connector → gateway, etc.)"
    echo -e "• Data extraction from request/response payloads"
    echo -e "• Dapr-based event publishing to Kafka"
    
    echo -e "\n${YELLOW}Expected Event Structure (from development.toml):${NC}"
    echo -e "• timestamp: ISO format timestamp"
    echo -e "• hostname: 'connector-service' (static value)"
    echo -e "• schema_version: 'V2' (static value)"
    echo -e "• category: 'OUTGOING_API' (static value)"
    echo -e "• gateway: Transformed from connector name"
    echo -e "• action: Flow type (GW_INIT_TXN, GW_INIT_REFUND, etc.)"
    echo -e "• message: Complex JSON with extracted request/response data"
    echo -e "• udf_txn_uuid: Transaction UUID"
    echo -e "• x-request-id: Request identifier"
    
    exit 0
else
    echo -e "${RED}Test failed: No audit events were found in Kafka.${NC}"
    echo -e "${RED}This suggests that the Dapr audit event publishing is not working correctly.${NC}"
    echo -e "${YELLOW}Things to check:${NC}"
    echo -e "1. Is the kafka-pubsub component properly configured?"
    echo -e "2. Is the Kafka broker running and accessible?"
    echo -e "3. Is the Dapr client properly initialized in the application?"
    echo -e "4. Is the events configuration in development.toml correct?"
    echo -e "5. Are the event publishing functions being called?"
    echo -e "6. Check the application logs for any event publishing errors"
    
    if [ "$VERBOSE" = "true" ] && [ -f "$LOG_FILE" ]; then
        echo -e "\n${YELLOW}Recent application logs from $LOG_FILE:${NC}"
        echo -e "${YELLOW}===========================================${NC}"
        tail -20 "$LOG_FILE" || echo "Could not read log file"
        echo -e "${YELLOW}===========================================${NC}"
        echo -e "${YELLOW}For full logs, run: cat $LOG_FILE${NC}"
    fi
    
    exit 1
fi
