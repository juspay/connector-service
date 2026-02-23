#!/usr/bin/env bash
set -e

echo "==================================="
echo "Testing all SDK clients"
echo "STRIPE_API_KEY is set: $([ -n "$STRIPE_API_KEY" ] && echo 'YES' || echo 'NO')"
echo "==================================="
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
OVERALL_SUCCESS=true

print_header() {
    echo ""
    echo "==================================="
    echo "$1"
    echo "==================================="
    echo ""
}

print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2 PASSED${NC}"
    else
        echo -e "${RED}✗ $2 FAILED${NC}"
        OVERALL_SUCCESS=false
    fi
}

print_header "Testing JavaScript SDK"
cd "$PWD"
if make -C sdk/javascript setup; then
    if node sdk/javascript/examples/example.js; then
        print_result 0 "JavaScript SDK"
    else
        print_result 1 "JavaScript SDK"
    fi
else
    print_result 1 "JavaScript SDK (setup)"
fi

print_header "Testing Python SDK"
cd "$PWD"
if make -C sdk/python setup; then
    if python3 sdk/python/examples/example.py; then
        print_result 0 "Python SDK"
    else
        print_result 1 "Python SDK"
    fi
else
    print_result 1 "Python SDK (setup)"
fi

print_header "Testing Java/Kotlin SDK"
cd "$PWD"
if make -C sdk/java setup; then
    if ./sdk/java/gradlew -p sdk/java run; then
        print_result 0 "Java/Kotlin SDK"
    else
        print_result 1 "Java/Kotlin SDK"
    fi
else
    print_result 1 "Java/Kotlin SDK (setup)"
fi

print_header "Testing Rust SDK"
cd "$PWD"
if cargo build -p hyperswitch-payments-client --release; then
    if cargo run -p hyperswitch-payments-client --example basic --release; then
        print_result 0 "Rust SDK"
    else
        print_result 1 "Rust SDK"
    fi
else
    print_result 1 "Rust SDK (build)"
fi

echo ""
echo "==================================="
echo "TEST SUMMARY"
echo "==================================="
if [ "$OVERALL_SUCCESS" = true ]; then
    echo -e "${GREEN}✓ All SDK tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some SDK tests failed${NC}"
    exit 1
fi
