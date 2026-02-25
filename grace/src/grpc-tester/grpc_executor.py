#!/usr/bin/env python3
"""
gRPC Executor - Executes gRPC tests based on test sets configuration
Runs each set independently, stopping on auth failure
"""

import os
import json
import sys
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from grpc_generator import GrpcGenerator


class GrpcExecutor:
    def __init__(self, env_file: str = ".env.grpc"):
        """Initialize the executor"""
        self.env_file = env_file

        # Verify executor-specific requirements
        self._verify_executor_setup()

        self.generator = GrpcGenerator(env_file)
        self.output_dir = Path(os.getenv("GRPC_OUTPUT_DIR", "./grpc_test_results"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Store transaction IDs and results
        self.transactions = {}
        self.refunds = {}
        self.results = []

        # Load test sets
        self.test_sets_file = Path("test_sets.json")
        self.test_sets = self.load_test_sets()

        # Create output files with timestamps
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.output_dir / f"grpc_test_log_{timestamp}.txt"
        self.results_file = self.output_dir / f"test_results_{timestamp}.json"

    def load_test_sets(self) -> List[Dict[str, Any]]:
        """Load test sets from configuration file"""
        if not self.test_sets_file.exists():
            raise FileNotFoundError(f"Test sets file not found: {self.test_sets_file}")

        with open(self.test_sets_file, 'r') as f:
            data = json.load(f)

        return data.get("test_sets", [])

    def execute_grpc_command(self, command: str) -> Tuple[bool, str, Optional[str], Optional[str]]:
        """
        Execute a gRPC command and capture output

        Returns:
            Tuple of (success, output, transaction_id, refund_id)
        """
        try:
            # Execute the command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Parse the response to get transaction ID
                output = result.stdout

                # Try to parse JSON response
                try:
                    response = json.loads(output)
                    transaction_id = None
                    refund_id = None

                    # Extract transaction ID for successful auth
                    if "transactionId" in response and response["transactionId"]:
                        if isinstance(response["transactionId"], dict) and "id" in response["transactionId"]:
                            transaction_id = response["transactionId"]["id"]
                        else:
                            transaction_id = response["transactionId"]

                    # Extract refund ID for successful refund
                    if "refundId" in response and response["refundId"]:
                        if isinstance(response["refundId"], dict) and "id" in response["refundId"]:
                            refund_id = response["refundId"]["id"]
                        else:
                            refund_id = response["refundId"]

                    # Check for errors
                    if "errorCode" in response and response["errorCode"]:
                        return False, output, transaction_id, refund_id

                    # Check for noResponseIdMarker (indicating error)
                    if "transactionId" in response and response["transactionId"] == "noResponseIdMarker":
                        return False, output, transaction_id, refund_id

                    return True, output, transaction_id, refund_id

                except json.JSONDecodeError:
                    # If we can't parse JSON, still return with stdout
                    return not bool(result.stderr), output, None, None
            else:
                # Command failed
                return False, result.stderr, None, None

        except subprocess.TimeoutExpired:
            return False, "Command timed out", None, None
        except Exception as e:
            return False, f"Error executing command: {str(e)}", None, None

    def log_request_response(self, test_name: str, operation: str,
                           curl_command: str, response: str, success: bool):
        """Log the request and response to a file"""
        with open(self.log_file, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Test Set: {test_name}\n")
            f.write(f"Operation: {operation}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"\n--- gRPC Command ---\n")
            f.write(curl_command)
            f.write(f"\n\n--- Raw Connector Response ---\n")
            f.write(response)
            f.write(f"\n\n--- Status: {'SUCCESS' if success else 'FAILURE'} ---\n")
            f.flush()

    def execute_test_set(self, test_set: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single test set
        Each set is independent - starts fresh with auth
        """
        test_name = test_set["name"]
        steps = test_set["steps"]

        print(f"\n{'='*60}")
        print(f"Executing: {test_name}")
        print(f"Description: {test_set['description']}")
        print(f"{'='*60}")

        # Clear transactions and refunds for this test set
        self.transactions.clear()
        self.refunds.clear()

        test_result = {
            "test_set_name": test_name,
            "description": test_set["description"],
            "all_passed": True,
            "steps_executed": [],
            "stopped_at": None
        }

        for step in steps:
            operation = step["operation"]
            depends_on = step["depends_on"]
            capture_method = step["capture_method"]

            # Generate unique reference ID
            ref_id = f"{test_name.replace(' ', '_')}_{operation}_{int(time.time())}"

            # Get transaction ID if this step depends on a previous step
            transaction_id = None
            refund_id = None
            if depends_on:
                # For sync operations, use the most recent transaction (from capture/void/name changes if available)
                if operation == "sync":
                    transaction_id = self.transactions.get("last") or self.transactions.get("auth")
                elif operation == "rsync":
                    refund_id = self.refunds.get("refund")
                else:
                    # For other dependent operations, use the transaction from auth
                    transaction_id = self.transactions.get("auth")

            # Generate gRPC command
            try:
                curl_command = self.generator.generate_grpc_curl(
                    operation=operation,
                    ref_id=ref_id,
                    transaction_id=transaction_id,
                    refund_id=refund_id,
                    capture_method=capture_method
                )
            except Exception as e:
                error_msg = f"Failed to generate gRPC command: {str(e)}"
                print(f"  ✗ {operation.upper()}: {error_msg}")

                test_result["steps_executed"].append({
                    "operation": operation,
                    "success": False,
                    "error": error_msg,
                    "curl_command": None
                })
                test_result["all_passed"] = False
                test_result["stopped_at"] = operation
                break

            # Add delay before sync for server processing
            if operation == "sync":
                print(f"  ⏳ Waiting 10 seconds for server processing before sync...")
                for i in range(10, 0, -1):
                    time.sleep(1)
                    if i <= 3 or i % 2 == 0:  # Show countdown for last 3 seconds and even numbers
                        print(f"  ⏳ {i} second{'s' if i != 1 else ''} remaining...")
            elif operation != "auth":
                time.sleep(3)  # 3 seconds for other operations

            # Execute the command
            success, response, txn_id, rf_id = self.execute_grpc_command(curl_command)

            # Store transaction ID for successful operations
            if success and txn_id:
                if operation == "auth":
                    self.transactions["auth"] = txn_id
                    print(f"  ✓ {operation.upper()}: Transaction ID = {txn_id}")
                elif operation in ["capture", "void"]:
                    self.transactions["last"] = txn_id
                    print(f"  ✓ {operation.upper()}: Transaction ID = {txn_id}")
                else:
                    print(f"  ✓ {operation.upper()}")

            # Store refund ID for successful refund operations
            if success and rf_id and operation == "refund":
                self.refunds["refund"] = rf_id
                print(f"  ✓ {operation.upper()}: Refund ID = {rf_id}")
            elif success and operation == "refund":
                print(f"  ✓ {operation.upper()}")
            elif operation == "refund" and not success:
                print(f"  ✗ {operation.upper()}: Refund failed - cannot get refund ID for rsync")
            # For operations that are not auth/capture/void/refund, print status
            if operation not in ["auth", "capture", "void", "refund"]:
                status = "✓" if success else "✗"
                print(f"  {status} {operation.upper()}")

            # Log the request and response
            self.log_request_response(test_name, operation, curl_command, response, success)

            # Record step result
            step_result = {
                "operation": operation,
                "success": success,
                "curl_command": curl_command,
                "transaction_id": txn_id if operation == "auth" else transaction_id,
                "response": response[:500] + "..." if len(response) > 500 else response
            }

            if not success:
                step_result["error"] = response
                test_result["all_passed"] = False

                # Stop the test set if auth fails
                if operation == "auth":
                    test_result["stopped_at"] = operation
                    print(f"\n⚠️  Authentication failed - stopping test set")
                    break

            test_result["steps_executed"].append(step_result)

        # Report test set result
        status = "PASSED" if test_result["all_passed"] else "FAILED"
        print(f"\n{status}: {test_name}")

        return test_result

    def execute_all_tests(self) -> Dict[str, Any]:
        """Execute all test sets"""
        print(f"\n{'='*60}")
        print("Starting gRPC Test Execution")
        print(f"Connector: {self.generator.connector_name}")
        print(f"Server: {self.generator.server_url}")
        print(f"Output Directory: {self.output_dir}")
        print(f"{'='*60}")

        # Initialize log file
        with open(self.log_file, 'w') as f:
            f.write(f"gRPC Test Execution Log\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Connector: {self.generator.connector_name}\n")
            f.write(f"Auth Type: {self.generator.auth_type}\n")
            f.write(f"Server: {self.generator.server_url}\n")
            f.flush()

        # Execute each test set
        all_results = []
        passed_sets = 0

        for test_set in self.test_sets:
            result = self.execute_test_set(test_set)
            all_results.append(result)

            if result["all_passed"]:
                passed_sets += 1

            # Delay between test sets
            if test_set != self.test_sets[-1]:
                time.sleep(5)

        # Generate summary
        summary = {
            "total_sets": len(self.test_sets),
            "passed_sets": passed_sets,
            "failed_sets": len(self.test_sets) - passed_sets,
            "success_rate": (passed_sets / len(self.test_sets)) * 100 if self.test_sets else 0
        }

        # Compile final results
        final_results = {
            "connector_name": self.generator.connector_name,
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "test_sets": all_results,
            "log_file": str(self.log_file),
            "configuration": {
                "auth_type": self.generator.auth_type,
                "merchant_id": self.generator.merchant_id,
                "server_url": self.generator.server_url
            }
        }

        # Save results to JSON
        with open(self.results_file, 'w') as f:
            json.dump(final_results, f, indent=2)

        # Print final summary
        print(f"\n{'='*60}")
        print("FINAL RESULTS")
        print(f"{'='*60}")
        print(f"Total Test Sets: {summary['total_sets']}")
        print(f"Passed: {summary['passed_sets']}")
        print(f"Failed: {summary['failed_sets']}")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        print(f"\nLog file: {self.log_file}")
        print(f"Results file: {self.results_file}")
        print(f"{'='*60}")

        return final_results

    def _verify_executor_setup(self):
        """Verify executor-specific setup requirements"""
        # Check if GRPC_OUTPUT_DIR can be created
        output_dir = Path(os.getenv("GRPC_OUTPUT_DIR", "./grpc_test_results"))
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            print(f"✓ Output directory: {output_dir}")
        except Exception as e:
            print(f"✗ Cannot create output directory {output_dir}: {e}")
            sys.exit(1)

        # Check if test_sets.json has valid structure
        test_sets_file = Path("test_sets.json")
        if not test_sets_file.exists():
            print(f"✗ Test sets file not found: {test_sets_file}")
            sys.exit(1)

        try:
            with open(test_sets_file, 'r') as f:
                data = json.load(f)
                test_sets = data.get("test_sets", [])

                if not test_sets:
                    print("⚠️  No test sets defined in test_sets.json")
                else:
                    print(f"✓ Found {len(test_sets)} test sets")
                    for i, test_set in enumerate(test_sets, 1):
                        name = test_set.get("name", f"Unnamed_{i}")
                        print(f"  - {name}")
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON in test_sets.json: {e}")
            sys.exit(1)

        # Check output directory permissions
        try:
            test_file = output_dir / ".write_test"
            test_file.write_text("test")
            test_file.unlink()
            print("✓ Output directory is writable")
        except Exception as e:
            print(f"✗ Output directory is not writable: {e}")
            sys.exit(1)


if __name__ == "__main__":
    executor = GrpcExecutor()
    results = executor.execute_all_tests()

    # Exit with non-zero if any test failed
    if results["summary"]["passed_sets"] != results["summary"]["total_sets"]:
        exit(1)