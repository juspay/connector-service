# gRPC Connector Testing Workflow

This document describes the complete workflow for testing gRPC connectors using the Powertranz implementation.

## 📋 Prerequisites

1. **Server Running**: gRPC server must be running on `localhost:8000`
2. **Configuration**: `.env.grpc` must be properly configured with Powertranz credentials
3. **Dependencies**: Python 3.9+ with required packages installed

## 🔧 Step 1: Generate gRPC Commands

First, generate the gRPC cURL commands based on your configuration:

```bash
cd connector-service/grace
python3 grpc_generator.py
```

This will:
- Load configuration from `.env.grpc`
- Generate cURL commands for all operations (auth, capture, void, refund, sync, rsync)
- Save configuration to `grpc_configs/current_config.json`
- Display example commands for manual testing

## 🧪 Step 2: Execute Tests

Run the complete test suite:

```bash
python3 run_grpc_tests.py
```

### What Tests Run:

1. **Manual Capture Flow**
   - Authorize payment with manual capture
   - Capture the authorized amount
   - Sync to verify final status

2. **Void Flow**
   - Authorize payment
   - Void the authorization
   - Sync to verify void status

3. **Automatic Capture Flow**
   - Authorize with automatic capture (sale)
   - Refund the captured amount
   - rSync using RefundService/Get with refund ID

## 📊 Step 3: Analyze Results

After execution, results are saved in `grpc_test_results/`:

### Result Files:
- `grpc_test_log_TIMESTAMP.txt` - Detailed execution log
- `test_results_TIMESTAMP.json` - Structured JSON results
- `analysis_report_TIMESTAMP.md` - Automated analysis summary

### Manual Analysis Commands:
```bash
# View latest log
cat grpc_test_results/grpc_test_log_*.txt | tail -100

# View JSON results
python3 -c "import json; print(json.dumps(json.load(open('grpc_test_results/test_results_*.json')), indent=2))"

# Check success rate
grep -E "PASSED|FAILED" grpc_test_results/analysis_report_*.md
```

## 🚀 One-Liner Command for Claude

For quick testing with Claude:

```bash
claude --dangerously-skip-permutations "cd connector-service/grace && python3 run_grpc_tests.py && echo 'Check grpc_test_results/ for detailed results'"
```

## 🔍 Claude Analysis Request

For comprehensive analysis:

```
claude --dangerously-skip-permissions

Execute the complete gRPC testing workflow:
1. cd connector-service/grace
2. python3 grpc_generator.py  # Generate commands
3. python3 run_grpc_tests.py  # Execute tests
4. Analyze all files in grpc_test_results/
5. Report: success rate, issues, recommendations

Expected: 100% pass rate for Powertranz with proper auth/capture/void/refund flows.
```

## 📝 Common Troubleshooting

### Issues and Solutions:

1. **"Host format error" (ISO 97)**
   - Cause: Invalid CVC code
   - Fix: Use CVC 123 instead of 999

2. **"invalid character 't' after object"**
   - Cause: connector_meta_data not properly escaped
   - Fix: Ensure it's a JSON string in auth.json

3. **"has no known field named amount"**
   - Cause: Invalid fields in RefundService/Get
   - Fix: rsync.json should only contain transaction_id and refund_id

### Quick Fix Script:
```bash
# Fix common issues
sed -i '' 's/"999"/"123"/g' .env.grpc
python3 verify-setup.py  # Verify configuration
```

## ✅ Success Criteria

All tests should pass with:
- **Manual Capture**: AUTHORIZED → CHARGED → Sync confirmation
- **Void Flow**: AUTHORIZED → VOIDED → Sync confirmation
- **Auto Capture**: CHARGED → REFUND_SUCCESS → rSync confirmation

Each transaction should receive unique IDs and proper status transitions.