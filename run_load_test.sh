#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}   Connector Service Locust Load Test Runner        ${NC}"
echo -e "${BLUE}=====================================================${NC}"

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

# Check if grpcurl is installed
if ! command -v grpcurl &> /dev/null; then
    echo -e "${RED}Error: grpcurl is not installed.${NC}"
    echo -e "${YELLOW}Please install grpcurl:${NC}"
    echo -e "  macOS: brew install grpcurl"
    echo -e "  Linux: Download from https://github.com/fullstorydev/grpcurl/releases"
    exit 1
fi

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed.${NC}"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 is not installed.${NC}"
    exit 1
fi

echo -e "${YELLOW}Checking Python dependencies...${NC}"

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip install --upgrade pip

# Force reinstall to fix any threading issues
echo -e "${YELLOW}Reinstalling dependencies to fix gevent threading issues...${NC}"
pip uninstall -y locust gevent || true
pip install -r requirements.txt

# Check if the connector service is running
echo -e "${YELLOW}Checking if connector service is running on localhost:8000...${NC}"
if ! nc -z localhost 8000 2>/dev/null; then
    echo -e "${RED}Error: Connector service is not running on localhost:8000${NC}"
    echo -e "${YELLOW}Please start the connector service first using:${NC}"
    echo -e "  ./demo.sh"
    echo -e "${YELLOW}Or manually start it with:${NC}"
    echo -e "  dapr run --app-id connector-service --app-port 8000 --dapr-grpc-port 50001 --dapr-http-port 3501 --components-path ./components -- cargo run --bin grpc-server"
    exit 1
fi

echo -e "${GREEN}✓ Connector service is running${NC}"

# Configuration
TARGET_RPS=${TARGET_RPS:-200}
DURATION=${DURATION:-60}
USERS=${USERS:-200}
SPAWN_RATE=${SPAWN_RATE:-10}

echo -e "\n${BLUE}Load Test Configuration:${NC}"
echo -e "${YELLOW}Target RPS: ${TARGET_RPS}${NC}"
echo -e "${YELLOW}Duration: ${DURATION} seconds${NC}"
echo -e "${YELLOW}Users: ${USERS}${NC}"
echo -e "${YELLOW}Spawn Rate: ${SPAWN_RATE} users/second${NC}"
echo -e "${YELLOW}Mix: 100% payment authorizations only${NC}"

# Ask for confirmation
echo -e "\n${YELLOW}Press Enter to start the load test, or Ctrl+C to cancel...${NC}"
read -r

echo -e "\n${BLUE}Starting Locust load test...${NC}"

# Run the load test
if [ "$1" = "--web" ]; then
    echo -e "${YELLOW}Starting Locust with web UI on http://localhost:8089${NC}"
    locust -f locust_load_test.py --host=localhost:8000 --web-host=0.0.0.0 --web-port=8089
else
    echo -e "${YELLOW}Starting headless load test...${NC}"
    locust -f locust_load_test.py --host=localhost:8000 --headless -u $USERS -r $SPAWN_RATE -t ${DURATION}s
fi

echo -e "\n${GREEN}Load test completed!${NC}"
echo -e "${YELLOW}Check the following for results:${NC}"
echo -e "1. Dapr metrics at http://localhost:9091/metrics"
echo -e "2. Kafka messages using the demo.sh script"
echo -e "3. Prometheus metrics if configured"

# Deactivate virtual environment
deactivate
