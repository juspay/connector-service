#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set script variables
PAYMENT_ID="payment_$(date +%s)_$RANDOM"
APP_ID="connector-service"
APP_PORT="8000"
DAPR_GRPC_PORT="50001"
DAPR_HTTP_PORT="3500"
COMPONENTS_PATH="./components"
export DAPR_PUBSUB_NAME="kafka-pubsub" 

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
trap cleanup EXIT

echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}   Dapr Kafka Integration Demo                        ${NC}"
echo -e "${BLUE}=====================================================${NC}"

# Ensure dapr-net network exists
echo -e "\n${BLUE}Ensuring dapr-net network exists...${NC}"
if ! podman network ls | grep -q dapr-net; then
    echo -e "${YELLOW}Creating dapr-net network...${NC}"
    podman network create dapr-net
fi

# Check for existing Kafka and Zookeeper containers (both running and stopped) and remove them
echo -e "\n${BLUE}Checking Kafka and Zookeeper container status...${NC}"
if podman ps -a | grep -q kafka; then
    echo -e "${YELLOW}Removing existing Kafka container...${NC}"
    podman stop kafka >/dev/null 2>&1 || true
    podman rm -f kafka >/dev/null 2>&1 || true
fi

if podman ps -a | grep -q zookeeper; then
    echo -e "${YELLOW}Removing existing Zookeeper container...${NC}"
    podman stop zookeeper >/dev/null 2>&1 || true
    podman rm -f zookeeper >/dev/null 2>&1 || true
fi

echo -e "${YELLOW}Setting up Zookeeper and Kafka containers...${NC}"
echo -e "${YELLOW}Starting Zookeeper...${NC}"
podman run -d --name zookeeper \
  --network dapr-net \
  --platform linux/amd64 \
  -e ALLOW_ANONYMOUS_LOGIN=yes \
  -p 2181:2181 \
  docker.io/bitnami/zookeeper:3.7

# Wait for Zookeeper to start
echo -e "${YELLOW}Waiting for Zookeeper to start...${NC}"
sleep 10
    
    echo -e "${YELLOW}Starting Kafka...${NC}"
    podman run -d --name kafka \
      --platform linux/amd64 \
      -e KAFKA_BROKER_ID=1 \
      -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
      -e KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,EXTERNAL://0.0.0.0:29092 \
      -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka:9092,EXTERNAL://127.0.0.1:29092 \
      -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=PLAINTEXT:PLAINTEXT,EXTERNAL:PLAINTEXT \
      -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT \
      -e ALLOW_PLAINTEXT_LISTENER=yes \
      -p 9092:9092 \
      -p 29092:29092 \
      --network dapr-net \
      docker.io/bitnami/kafka:2.8.1
    
    # Wait for Kafka to start
    echo -e "${YELLOW}Waiting for Kafka to start...${NC}"
    sleep 20
    
    # Create topic
    echo -e "${YELLOW}Creating Kafka topic 'payment-events'...${NC}"
    podman exec kafka /opt/bitnami/kafka/bin/kafka-topics.sh \
        --create --if-not-exists \
        --bootstrap-server localhost:9092 \
        --replication-factor 1 \
        --partitions 1 \
        --topic payment-events

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
  --components-path $COMPONENTS_PATH \
  --log-level info \
  -- cargo run --bin grpc-server &

DAPR_PID=$!

# Wait for the service to start
echo -e "${YELLOW}Waiting for service to start...${NC}"

# Function to check if service is running on either port
check_service_up() {
    if nc -z localhost 8000 2>/dev/null; then
        echo -e "${GREEN}Service is up and running on port 8000!${NC}"
        APP_PORT=8000
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
MAX_WAIT=120  # Maximum seconds to wait
START_TIME=$(date +%s)
WAIT_INTERVAL=5  # Check every 5 seconds

echo -e "${YELLOW}Waiting for cargo build to complete and service to start (timeout: ${MAX_WAIT}s)...${NC}"

while true; do
    # Check if the service is up
    if check_service_up; then
        break
    fi
    
    # Check if we've exceeded the maximum wait time
    CURRENT_TIME=$(date +%s)
    ELAPSED_TIME=$((CURRENT_TIME - START_TIME))
    
    if [ $ELAPSED_TIME -ge $MAX_WAIT ]; then
        echo -e "${YELLOW}Service ports not detected after ${MAX_WAIT} seconds.${NC}"
        echo -e "${YELLOW}Will try to continue anyway, but this might fail.${NC}"
        break
    fi
    
    echo -e "${YELLOW}Still waiting for service to come up... (${ELAPSED_TIME}s elapsed)${NC}"
    sleep $WAIT_INTERVAL
done

# Give Dapr a moment to initialize all components
echo -e "${YELLOW}Service detected! Giving Dapr a moment to initialize all components...${NC}"
sleep 5

# Step 2: Make a payment authorization request
echo -e "\n${BLUE}Step 2: Making payment authorization request...${NC}"
echo -e "${YELLOW}Using payment ID: $PAYMENT_ID${NC}"

RESPONSE=$(grpcurl -plaintext \
  -H "x-tenant-id: test_tenant" \
  -H "x-request-id: req_$(date +%s)" \
  -H "x-connector: checkout" \
  -H "x-merchant-id: test_merchant" \
  -H "x-auth: signature-key" \
  -H "x-api-key: $API_KEY" \
  -H "x-key1: $KEY1" \
  -H "x-api-secret: $API_SECRET" \
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
    "capture_method": "AUTOMATIC"
  }' \
  localhost:$APP_PORT ucs.v2.PaymentService/Authorize)

echo -e "${GREEN}Response received:${NC}"
echo $RESPONSE | jq '.' || echo $RESPONSE

# Wait a moment for the event to be published
echo -e "\n${YELLOW}Waiting for event to be published to Kafka...${NC}"
sleep 3

# Step 3: Check Kafka for the message
echo -e "\n${BLUE}Step 3: Checking Kafka for the payment event...${NC}"
echo -e "${YELLOW}Checking for messages with reference_id: $PAYMENT_ID${NC}"

# Check if Kafka container is running
if ! podman ps | grep -q kafka; then
    echo -e "${RED}Error: Kafka container not running. Please start it first with:${NC}"
    echo -e "${YELLOW}  podman-compose -f kafka-dapr.yaml up -d${NC}"
    exit 1
fi

# Run kafka-console-consumer in the Kafka container to verify messages
MESSAGES=$(podman exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server localhost:9092 \
    --topic payment-events \
    --from-beginning \
    --max-messages 100 \
    --timeout-ms 5000 2>/dev/null || true)

# Check if our test message is in the Kafka topic
if echo "$MESSAGES" | grep -q "\"reference_id\":\"$PAYMENT_ID\""; then
    echo -e "${GREEN}Success! Message with reference_id '$PAYMENT_ID' was found in Kafka:${NC}"
    echo "$MESSAGES" | grep "\"reference_id\":\"$PAYMENT_ID\"" | jq '.' || echo "$MESSAGES" | grep "\"reference_id\":\"$PAYMENT_ID\""
    MESSAGE_FOUND=true
else
    echo -e "${YELLOW}No messages found with reference_id: $PAYMENT_ID${NC}"
    echo -e "${YELLOW}Note: After processing, payment_id field may contain the connector transaction ID${NC}"
    MESSAGE_FOUND=false
fi

# Show summary based on test results
echo -e "\n${BLUE}=====================================================${NC}"
if [ "$MESSAGE_FOUND" = true ]; then
    echo -e "${GREEN}Dapr Kafka Integration Demo Completed Successfully!${NC}"
    echo -e "${BLUE}=====================================================${NC}"
    echo -e "${YELLOW}Summary:${NC}"
    echo -e "1. Started the connector service with Dapr"
    echo -e "2. Sent a payment authorization request"
    echo -e "3. Verified the payment event was published to Kafka"
    echo -e "${GREEN}The Dapr implementation is working correctly!${NC}"
    exit 0
else
    echo -e "${RED}Test failed: No message with reference_id '$PAYMENT_ID' was found in Kafka.${NC}"
    echo -e "${RED}This suggests that the Dapr event publishing is not working correctly.${NC}"
    echo -e "${YELLOW}Things to check:${NC}"
    echo -e "1. Is the kafka-pubsub component properly configured?"
    echo -e "2. Is the Kafka broker running and accessible?"
    echo -e "3. Is the Dapr client properly initialized in the application?"
    echo -e "4. Is the payment event being created and published in the code?"
    exit 1
fi
