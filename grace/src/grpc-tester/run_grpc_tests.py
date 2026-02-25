#!/usr/bin/env python3
"""
Main gRPC Test Runner
Runs the complete gRPC testing pipeline:
1. Generate cURL commands
2. Execute test sets
3. Check and analyze results
"""

import sys
import argparse
import time
from pathlib import Path
from grpc_generator import GrpcGenerator
from grpc_executor import GrpcExecutor
from grpc_checker import GrpcChecker


def verify_setup(env_file=".env.grpc"):
    """Verify the complete setup before running tests"""
    import subprocess
    import json

    print("=== gRPC Test Framework Verification ===\n")
    print("="*60)

    all_good = True

    # Check essential files
    essential_files = [
        (env_file, "Environment configuration"),
        ("test_sets.json", "Test sets configuration"),
        ("grpc_generator.py", "gRPC generator"),
        ("grpc_executor.py", "gRPC executor"),
        ("grpc_checker.py", "gRPC checker"),
        ("run_grpc_tests.py", "Test runner")
    ]

    for filepath, description in essential_files:
        if Path(filepath).exists():
            print(f"✓ {description}: {filepath}")
        else:
            print(f"✗ {description}: {filepath} (MISSING)")
            all_good = False

    # Check request templates
    print("\nChecking request templates:")
    request_files = [
        "grpc_requests/auth.json",
        "grpc_requests/capture.json",
        "grpc_requests/void.json",
        "grpc_requests/refund.json",
        "grpc_requests/sync.json",
        "grpc_requests/rsync.json"
    ]

    for req_file in request_files:
        if Path(req_file).exists():
            print(f"✓ Template: {req_file.split('/')[-1]}")
        else:
            print(f"✗ Template: {req_file.split('/')[-1]} (MISSING)")
            all_good = False

    # Check configuration values
    print("\nConfiguration verification:")
    if Path(env_file).exists():
        with open(env_file, 'r') as f:
            env_config = {}
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_config[key.strip()] = value.strip()

        required_keys = [
            'CONNECTOR_NAME',
            'CONNECTOR_AUTH_TYPE',
            'CONNECTOR_API_KEY',
            'CONNECTOR_KEY1',
            'CARD_NUMBER',
            'CARD_CVC'
        ]

        for key in required_keys:
            if key in env_config:
                # For CVC, just accept any value without special checks
                masked_value = '*' * len(env_config[key]) if 'KEY' in key else env_config[key]
                print(f"✓ {key}: {masked_value}")
            else:
                print(f"✗ {key}: NOT SET")
                all_good = False
    else:
        all_good = False

    # Check test sets content
    print("\nTest sets verification:")
    if Path("test_sets.json").exists():
        with open("test_sets.json", 'r') as f:
            test_sets = json.load(f)

        test_sets_list = test_sets.get('test_sets', [])
        if not test_sets_list:
            print("⚠️  No test sets defined")
            all_good = False
        else:
            print(f"✓ Found {len(test_sets_list)} test set(s)")
            for i, test_set in enumerate(test_sets_list, 1):
                name = test_set.get('name', f'Unnamed_{i}')
                description = test_set.get('description', 'No description')
                print(f"  - {name}: {description}")

                has_rsync = any(step.get('operation') == 'rsync'
                              for step in test_set.get('steps', []))
                if has_rsync:
                    print(f"    ✓ Includes rsync operation for refund sync")

    # Check server connectivity
    print("\nServer connectivity check:")
    try:
        result = subprocess.run(
            ["grpcurl", "-plaintext", "localhost:8000", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print("✓ gRPC server is running on localhost:8000")
        else:
            print("✗ gRPC server not responding on localhost:8000")
            all_good = False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("⚠️  Cannot verify gRPC server (grpcurl not installed or server not running)")

    print("\n" + "="*60)
    if all_good:
        print("✓ Setup verification: PASSED")
        print("\nYou can now run the tests with:")
        print("  python3 run_grpc_tests.py")
        print("  ./grace-test.sh")
    else:
        print("✗ Setup verification: FAILED")
        print("\nPlease fix the issues above before running tests.")
        sys.exit(1)

    return all_good


def main():
    parser = argparse.ArgumentParser(description="Run gRPC tests for payment connectors")
    parser.add_argument("--env", default=".env.grpc", help="Environment file (default: .env.grpc)")
    parser.add_argument("--generate-only", action="store_true", help="Only generate cURL commands, don't execute")
    parser.add_argument("--check-only", action="store_true", help="Analyze existing results without running tests")
    parser.add_argument("--test-set", help="Run specific test set by name")
    parser.add_argument("--skip-verify", action="store_true", help="Skip setup verification (not recommended)")

    args = parser.parse_args()

    # Main verification for all operations (unless skipped)
    if not args.skip_verify:
        verify_setup(args.env)
    else:
        print("⚠️  Skipping setup verification (not recommended)")
        print()

    try:
        if args.check_only:
            # For check-only, verify results directory exists
            results_dir = Path("grpc_test_results")
            if not results_dir.exists():
                print("✗ grpc_test_results directory not found")
                print("Run tests first to generate results")
                sys.exit(1)

            print(f"✓ Results directory: {results_dir}")

            # Find and verify latest results
            results_files = list(results_dir.glob("test_results_*.json"))
            if not results_files:
                print("✗ No test result files found")
                sys.exit(1)

            latest_file = max(results_files, key=lambda p: p.stat().st_mtime)
            print(f"✓ Latest results: {latest_file.name}\n")

            # Analyze existing results
            checker = GrpcChecker()

            print(f"\nAnalyzing results from: {latest_file}")

            analysis = checker.check_test_results(latest_file)
            report_file = results_dir / f"analysis_report_{latest_file.stem.replace('test_results_', '')}.md"

            checker.generate_report(analysis, report_file)
            return

        if args.generate_only:
            # Generate cURL commands only
            generator = GrpcGenerator(args.env)

            print(f"\n=== Generating gRPC Commands ===")
            print(f"Connector: {generator.connector_name}")
            print(f"Auth Type: {generator.auth_type}")
            print(f"Server: {generator.server_url}")

            operations = ["auth", "capture", "void", "refund", "sync"]
            for op in operations:
                try:
                    curl_cmd = generator.generate_grpc_curl(
                        op,
                        f"demo_{op}_{int(time.time())}",
                        transaction_id="txn_12345" if op != "auth" else None,
                        capture_method="MANUAL"
                    )
                    print(f"\n{op.upper()}:")
                    print(curl_cmd)
                except Exception as e:
                    print(f"Error generating {op}: {e}")

            generator.save_configuration()
            return

        # Run full test pipeline
        print(f"\n{'='*60}")
        print("gRPC Test Pipeline")
        print(f"Environment: {args.env}")
        print(f"{'='*60}")

        # Step 1: Generate and save configuration
        print("\nStep 1: Initializing...")
        generator = GrpcGenerator(args.env)
        generator.save_configuration()
        print(f"✓ Connector: {generator.connector_name}")
        print(f"✓ Auth Type: {generator.auth_type}")
        print(f"✓ Server: {generator.server_url}")

        # Step 2: Execute tests
        print("\nStep 2: Executing Tests...")
        executor = GrpcExecutor(args.env)

        # Filter test set if specified
        if args.test_set:
            test_sets = executor.test_sets
            filtered_sets = [ts for ts in test_sets if ts["name"].lower() == args.test_set.lower()]
            if not filtered_sets:
                print(f"Error: Test set '{args.test_set}' not found")
                sys.exit(1)
            executor.test_sets = filtered_sets
            print(f"Running only: {args.test_set}")

        results = executor.execute_all_tests()

        # Step 3: Analyze results
        print("\nStep 3: Analyzing Results...")
        checker = GrpcChecker()

        if "results_file" in results and results["results_file"]:
            results_file = Path(results["results_file"])
        else:
            # Find the latest results file
            results_dir = Path("grpc_test_results")
            if results_dir.exists():
                results_files = list(results_dir.glob("test_results_*.json"))
                if results_files:
                    results_file = max(results_files, key=lambda p: p.stat().st_mtime)
                else:
                    print("No results file found to analyze")
                    return
            else:
                print("No results directory found")
                return

        if results_file.exists():
            analysis = checker.check_test_results(results_file)

            # Print recommendations
            print("\nRecommendations:")
            for rec in analysis["recommendations"]:
                print(f"  {rec}")

            # Generate report
            report_file = results_file.parent / f"analysis_report_{results_file.stem.replace('test_results_', '')}.md"
            checker.generate_report(analysis, report_file)

        # Final status
        if results["summary"]["passed_sets"] == results["summary"]["total_sets"]:
            print(f"\n✅ All tests passed!")
            sys.exit(0)
        else:
            print(f"\n❌ Some tests failed")
            sys.exit(1)

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()