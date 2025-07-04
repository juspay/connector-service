#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get full paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
KAFKA_YAML="$SCRIPT_DIR/kafka-dapr.yaml"
COMPONENTS_DIR="$SCRIPT_DIR/components"

# Display banner
function show_banner() {
    echo -e "${BLUE}=====================================================${NC}"
    echo -e "${BLUE}       Dapr Kafka Integration Manual Demo           ${NC}"
    echo -e "${BLUE}=====================================================${NC}"
}

# Check prerequisites
function check_prerequisites() {
    local missing_tools=()
    
    for cmd in dapr podman podman-compose cargo jq; do
        if ! command -v $cmd &> /dev/null; then
            missing_tools+=("$cmd")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}Error: The following required tools are missing:${NC}"
        for tool in "${missing_tools[@]}"; do
            echo -e "${RED}- $tool${NC}"
        done
        echo -e "${YELLOW}Please install these tools before running this script.${NC}"
        exit 1
    fi
}

# Function to start Kafka and Zookeeper
function start_kafka() {
    echo -e "${BLUE}Starting Kafka and Zookeeper...${NC}"
    cd "$ROOT_DIR" && podman-compose -f "$KAFKA_YAML" up -d
    
    echo -e "${GREEN}Waiting for Kafka to be ready...${NC}"
    sleep 10
    
    # Check if Kafka is running
    if podman ps | grep -q "kafka"; then
        echo -e "${GREEN}Kafka is running!${NC}"
    else
        echo -e "${RED}Error: Kafka failed to start.${NC}"
        exit 1
    fi
}

# Function to stop Kafka and Zookeeper
function stop_kafka() {
    echo -e "${BLUE}Stopping Kafka and Zookeeper...${NC}"
    cd "$ROOT_DIR" && podman-compose -f "$KAFKA_YAML" down
    echo -e "${GREEN}Kafka and Zookeeper stopped.${NC}"
}

# Function to clean up all resources
function cleanup() {
    echo -e "${BLUE}Cleaning up resources...${NC}"
    stop_kafka
    echo -e "${GREEN}Cleanup complete!${NC}"
}

# Function to run the publisher with optional custom parameters
function run_publisher() {
    local payment_id="${1:-demo_test_$(date +%s)}"
    local amount="${2:-123.45}"
    local currency="${3:-USD}"
    local status="${4:-demo_test}"
    
    echo -e "${BLUE}Running publisher with the following parameters:${NC}"
    echo -e "${YELLOW}- Payment ID: $payment_id${NC}"
    echo -e "${YELLOW}- Amount: $amount${NC}"
    echo -e "${YELLOW}- Currency: $currency${NC}"
    echo -e "${YELLOW}- Status: $status${NC}"
    
    echo -e "${YELLOW}Starting Rust publisher with dapr...${NC}"
    cd "$ROOT_DIR" && dapr run \
        --app-id publisher \
        --components-path "$COMPONENTS_DIR" \
        -- cargo run --bin publisher --manifest-path ./examples/example-dapr-kafka/Cargo.toml "$payment_id" "$amount" "$currency" "$status"
    
    echo -e "${GREEN}Publisher completed.${NC}"
}

# Function to view all messages in the Kafka topic
function view_all_messages() {
    echo -e "${BLUE}Viewing all messages in the payment-events topic...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop viewing messages${NC}"
    
    podman exec -it kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
        --bootstrap-server localhost:9092 \
        --topic payment-events \
        --from-beginning \
        --timeout-ms 30000
}

# Function to verify a specific message by payment_id
function verify_message() {
    local payment_id="$1"
    
    if [ -z "$payment_id" ]; then
        echo -e "${RED}Error: Payment ID not provided.${NC}"
        echo -e "${YELLOW}Usage: $0 verify <payment_id>${NC}"
        return 1
    fi
    
    echo -e "${BLUE}=== Direct Kafka Message Verification ===${NC}"
    echo -e "${YELLOW}Searching for message with payment_id: $payment_id${NC}"
    
    # Run kafka-console-consumer in the Kafka container to verify messages
    local MESSAGES=$(podman exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
        --bootstrap-server localhost:9092 \
        --topic payment-events \
        --from-beginning \
        --max-messages 100 \
        --timeout-ms 10000 2>/dev/null || true)
    
    # Check if our test message is in the Kafka topic
    if echo "$MESSAGES" | grep -q "$payment_id"; then
        echo -e "${GREEN}Success! Message with payment_id '$payment_id' was found in Kafka:${NC}"
        echo "$MESSAGES" | grep "$payment_id" | jq '.' || echo "$MESSAGES" | grep "$payment_id"
        return 0
    else
        echo -e "${RED}Error: Message with payment_id '$payment_id' was not found in Kafka.${NC}"
        echo -e "${YELLOW}Available messages in Kafka:${NC}"
        echo "$MESSAGES" | jq '.' || echo "$MESSAGES"
        return 1
    fi
}

# Function to run a full demo (start, publish, verify, cleanup)
function run_full_demo() {
    local payment_id="demo_test_$(date +%s)"
    
    show_banner
    check_prerequisites
    
    # Start Kafka
    echo -e "\n${BLUE}Step 1: Starting Kafka and Zookeeper...${NC}"
    start_kafka
    
    # Send a message
    echo -e "\n${BLUE}Step 2: Sending a test message using Rust publisher...${NC}"
    echo -e "${YELLOW}Message parameters:${NC}"
    echo -e "${YELLOW}- Payment ID: $payment_id${NC}"
    echo -e "${YELLOW}- Amount: 123.45${NC}"
    echo -e "${YELLOW}- Currency: USD${NC}"
    echo -e "${YELLOW}- Status: demo_test${NC}"
    
    # Run the publisher in the background and capture its output
    cd "$ROOT_DIR" && dapr run \
        --app-id publisher \
        --components-path "$COMPONENTS_DIR" \
        -- cargo run --bin publisher --manifest-path ./examples/example-dapr-kafka/Cargo.toml "$payment_id" "123.45" "USD" "demo_test" > publisher_output.log 2>&1
    
    echo -e "${GREEN}Publisher completed. Output:${NC}"
    cat publisher_output.log
    
    # Brief wait for Kafka to process the message
    echo -e "${YELLOW}Waiting for Kafka to process the message...${NC}"
    sleep 3
    
    # Verify the message
    echo -e "\n${BLUE}Step 3: Verifying the message was received in Kafka...${NC}"
    verify_message "$payment_id"
    
    # Summary
    echo -e "\n${BLUE}=====================================================${NC}"
    echo -e "${GREEN}Dapr Kafka Integration Demo Completed Successfully!${NC}"
    echo -e "${BLUE}=====================================================${NC}"
    echo -e "${YELLOW}Summary:${NC}"
    echo -e "1. Started Kafka and Zookeeper"
    echo -e "2. Sent a test message through Rust publisher with Dapr"
    echo -e "3. Verified the message was correctly stored in Kafka"
    echo -e "${BLUE}=====================================================${NC}"
    echo -e "${YELLOW}Automatically cleaning up resources in 5 seconds...${NC}"
    sleep 5
    
    # Cleanup
    cleanup
}

# Function to show help message
function show_help() {
    show_banner
    
    echo -e "${BLUE}Manual demo script for Dapr Kafka Integration${NC}"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start                         Start Kafka and Zookeeper"
    echo "  stop                          Stop Kafka and Zookeeper"
    echo "  publish [id] [amt] [cur] [st] Run the publisher with optional parameters"
    echo "                                (defaults: random ID, 123.45, USD, demo_test)"
    echo "  verify <payment_id>           Verify a specific message by payment_id"
    echo "  view                          View all messages in the Kafka topic"
    echo "  demo                          Run a full demo (start, publish, verify, cleanup)"
    echo "  help                          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start                      # Start Kafka and Zookeeper"
    echo "  $0 publish my_payment_123     # Publish a message with custom ID"
    echo "  $0 verify my_payment_123      # Verify a specific message"
    echo "  $0 demo                       # Run the full demo"
}

# Main script logic
case "$1" in
    start)
        show_banner
        check_prerequisites
        start_kafka
        ;;
    stop)
        show_banner
        stop_kafka
        ;;
    publish)
        show_banner
        check_prerequisites
        run_publisher "$2" "$3" "$4" "$5"
        ;;
    verify)
        show_banner
        check_prerequisites
        verify_message "$2"
        ;;
    view)
        show_banner
        check_prerequisites
        view_all_messages
        ;;
    demo)
        run_full_demo
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        show_help
        exit 1
        ;;
esac
