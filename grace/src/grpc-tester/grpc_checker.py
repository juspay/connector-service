#!/usr/bin/env python3
"""
gRPC Checker - Analyzes and validates gRPC response patterns
Provides detailed analysis of test results and identifies patterns
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


class GrpcChecker:
    def __init__(self):
        """Initialize the gRPC checker"""
        self.response_patterns = {
            "success": [
                "transactionId",
                "success",
                "approved"
            ],
            "errors": [
                "errorCode",
                "errorMessage",
                "error_code",
                "error_message",
                "decline",
                "invalid",
                "rejected"
            ],
            "network_errors": [
                "timeout",
                "connection",
                "unreachable",
                "refused"
            ]
        }

    def parse_response(self, response: str) -> Dict[str, Any]:
        """
        Parse gRPC response and extract key information
        """
        # Try to parse as JSON
        try:
            parsed = json.loads(response)
            return {
                "parsed": True,
                "data": parsed,
                "status": self.analyze_response_structure(parsed)
            }
        except json.JSONDecodeError:
            # Treat as raw text
            return {
                "parsed": False,
                "data": response,
                "status": self.analyze_raw_response(response)
            }

    def analyze_response_structure(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze structured JSON response
        """
        status = {
            "is_success": False,
            "has_transaction_id": False,
            "error_codes": [],
            "error_messages": [],
            "warnings": [],
            "amount": None,
            "currency": None,
            "additional_fields": {}
        }

        # Check for success indicators
        for key, value in response.items():
            # Check for transaction ID
            if "transaction" in key.lower() or key == "id":
                if value:
                    status["has_transaction_id"] = True
                    status["additional_fields"][key] = value

            # Check for error indicators
            if "error" in key.lower() or key.lower() in ["errorcode", "errormessage"]:
                if value:
                    status["error_codes"].append(f"{key}: {value}")

            # Extract amount and currency
            if key.lower() in ["amount", "captureamount", "refundamount"]:
                if isinstance(value, (int, float)):
                    status["amount"] = value

            if key.lower() == "currency":
                if value:
                    status["currency"] = value

        # Determine if response is successful
        if not status["error_codes"] and status["has_transaction_id"]:
            status["is_success"] = True
        elif response.get("status") in ["approved", "AUTHORIZED", "CHARGED", "SETTLED"]:
            status["is_success"] = True
        elif response.get("success") == True:
            status["is_success"] = True

        # Collect other interesting fields
        interesting_fields = ["status", "capture_method", "auth_type", "response_code"]
        for field in interesting_fields:
            if field in response:
                status["additional_fields"][field] = response[field]

        return status

    def analyze_raw_response(self, response: str) -> Dict[str, Any]:
        """
        Analyze raw text response
        """
        status = {
            "is_success": False,
            "has_transaction_id": False,
            "error_codes": [],
            "error_messages": [],
            "warnings": [],
            "raw_text": response[:500] if len(response) > 500 else response
        }

        # Look for transaction ID patterns
        txn_patterns = [
            r"transactionId['\":\s]*['\"]?([a-zA-Z0-9_-]+)['\"]?",
            r"ID['\":\s]*['\"]?([a-zA-Z0-9_-]+)['\"]?",
            r"ref['\":\s]*['\"]?([a-zA-Z0-9_-]+)['\"]?"
        ]

        for pattern in txn_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                status["has_transaction_id"] = True
                status["error_codes"].append(f"Transaction ID: {match.group(1)}")
                break

        # Look for error patterns
        error_patterns = [
            r"errorcode['\":\s]*['\"]?(\d+)['\"]?",
            r"(error|ERROR)['\":\s]*['\"]?([^'\"]+)['\"]?",
            r"(connection timeout|connection refused|unrechable host)"
        ]

        for pattern in error_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            if matches:
                status["error_messages"].extend(str(m) for m in matches)

        # Check for success indicators
        success_indicators = ["approved", "authorized", "charged", "settled", "a0000"]
        response_lower = response.lower()

        if any(indicator in response_lower for indicator in success_indicators):
            status["is_success"] = True
        elif status["error_messages"]:
            status["is_success"] = False
        else:
            status["is_success"] = status["has_transaction_id"]

        return status

    def check_test_results(self, results_file: Path) -> Dict[str, Any]:
        """
        Analyze all test results and provide insights
        """
        if not results_file.exists():
            raise FileNotFoundError(f"Results file not found: {results_file}")

        # Verify file is readable and valid JSON
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in results file: {e}")

        # Verify required fields exist
        required_fields = ["summary", "connector_name", "test_sets"]
        for field in required_fields:
            if field not in results:
                raise ValueError(f"Missing required field in results file: {field}")

        analysis = {
            "summary": results["summary"],
            "connector_name": results["connector_name"],
            "detailed_analysis": [],
            "patterns_identified": {
                "common_errors": {},
                "success_rate_per_operation": {},
                "failure_modes": []
            },
            "recommendations": []
        }

        # Analyze each test set
        for test_set in results["test_sets"]:
            set_analysis = {
                "test_set_name": test_set["test_set_name"],
                "steps_analysis": [],
                "overall_status": "PASSED" if test_set["all_passed"] else "FAILED"
            }

            # Analyze each step
            for step in test_set["steps_executed"]:
                operation = step["operation"]
                response = step.get("response", "")

                response_analysis = self.parse_response(response)
                step_analysis = {
                    "operation": operation,
                    "success": step["success"],
                    "response_status": response_analysis.get("status", {}),
                    "has_transaction_id": response_analysis.get("status", {}).get("has_transaction_id", False),
                    "errors_found": response_analysis.get("status", {}).get("error_codes", [])
                }

                # Track patterns
                if not step["success"]:
                    self._track_failure_patterns(operation, response_analysis, analysis["patterns_identified"])

                set_analysis["steps_analysis"].append(step_analysis)

                # Update operation success rates
                if operation not in analysis["patterns_identified"]["success_rate_per_operation"]:
                    analysis["patterns_identified"]["success_rate_per_operation"][operation] = {"success": 0, "total": 0}

                analysis["patterns_identified"]["success_rate_per_operation"][operation]["total"] += 1
                if step["success"]:
                    analysis["patterns_identified"]["success_rate_per_operation"][operation]["success"] += 1

            analysis["detailed_analysis"].append(set_analysis)

        # Generate recommendations
        analysis["recommendations"] = self._generate_recommendations(analysis)

        return analysis

    def _track_failure_patterns(self, operation: str, response_analysis: Dict[str, Any], patterns: Dict[str, Any]):
        """Track common error patterns"""
        errors = response_analysis.get("status", {}).get("error_codes", [])

        for error in errors:
            # Extract error code/message
            error_key = error[:100]  # Truncate for uniqueness
            patterns["common_errors"][error_key] = patterns["common_errors"].get(error_key, 0) + 1

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on patterns"""
        recommendations = []

        # Check overall success rate
        success_rate = analysis["summary"]["success_rate"]
        if success_rate < 50:
            recommendations.append("🔴 Critical: Low success rate ({:.1f}%) - Investigate connector configuration".format(success_rate))
        elif success_rate < 80:
            recommendations.append("🟡 Warning: Moderate success rate ({:.1f}%) - Review error patterns".format(success_rate))

        # Check common errors
        common_errors = sorted(analysis["patterns_identified"]["common_errors"].items(),
                               key=lambda x: x[1], reverse=True)

        if common_errors:
            top_error = common_errors[0]
            if top_error[1] > 2:  # Same error occurred more than twice
                recommendations.append(f"🔍 Frequent error: '{top_error[0]}' (occurred {top_error[1]} times)")

        # Check operation-specific issues
        for operation, stats in analysis["patterns_identified"]["success_rate_per_operation"].items():
            rate = (stats["success"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            if rate < 50 and stats["total"] > 1:
                recommendations.append(f"⚠️  Low success rate for {operation}: {rate:.1f}%")

        # Check if auth is consistently failing
        auth_stats = analysis["patterns_identified"]["success_rate_per_operation"].get("auth")
        if auth_stats and auth_stats["success"] == 0:
            recommendations.append("🔑 Authentication is consistently failing - Check API keys and auth type")

        if not recommendations:
            recommendations.append("✅ All tests appear to be functioning normally")

        return recommendations

    def generate_report(self, analysis: Dict[str, Any], output_file: Path):
        """Generate a detailed analysis report"""
        report = []
        report.append("# gRPC Test Analysis Report\n")
        report.append(f"Connector: {analysis['connector_name']}")
        report.append(f"Generated: {datetime.now().isoformat()}\n")

        # Summary
        summary = analysis["summary"]
        report.append("## Summary\n")
        report.append(f"- **Total Test Sets**: {summary['total_sets']}")
        report.append(f"- **Passed**: {summary['passed_sets']}")
        report.append(f"- **Failed**: {summary['failed_sets']}")
        report.append(f"- **Success Rate**: {summary['success_rate']:.1f}%\n")

        # Test Set Details
        report.append("## Test Set Details\n")
        for set_analysis in analysis["detailed_analysis"]:
            report.append(f"### {set_analysis['test_set_name']}")
            report.append(f"Status: {set_analysis['overall_status']}\n")

            report.append("| Operation | Success | Transaction ID | Notes |")
            report.append("|-----------|---------|----------------|-------|")

            for step in set_analysis["steps_analysis"]:
                success_emoji = "✅" if step["success"] else "❌"
                txn_emoji = "✓" if step["has_transaction_id"] else "✗"
                notes = "; ".join(step["errors_found"]) if step["errors_found"] else "OK"

                report.append(f"| {step['operation']} | {success_emoji} | {txn_emoji} | {notes} |")

            report.append("")  # Empty line between test sets

        # Patterns Identified
        report.append("## Patterns Identified\n")

        # Success Rate per Operation
        report.append("### Success Rate by Operation")
        for operation, stats in analysis["patterns_identified"]["success_rate_per_operation"].items():
            rate = (stats["success"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            report.append(f"- **{operation}**: {rate:.1f}% ({stats['success']}/{stats['total']})")

        # Common Errors
        if analysis["patterns_identified"]["common_errors"]:
            report.append("\n### Common Errors")
            for error, count in sorted(analysis["patterns_identified"]["common_errors"].items(),
                                      key=lambda x: x[1], reverse=True)[:5]:
                report.append(f"- `{error}` ({count} occurrences)")

        # Recommendations
        report.append("\n## Recommendations\n")
        for rec in analysis["recommendations"]:
            report.append(f"- {rec}")

        # Write report
        with open(output_file, 'w') as f:
            f.write("\n".join(report))

        print(f"Analysis report saved to: {output_file}")


if __name__ == "__main__":
    # Example usage - analyze the latest results
    import glob

    checker = GrpcChecker()
    results_files = list(Path("./grpc_test_results").glob("test_results_*.json"))

    if results_files:
        latest_file = max(results_files, key=lambda p: p.stat().st_mtime)
        print(f"Analyzing: {latest_file}")

        analysis = checker.check_test_results(latest_file)
        report_file = latest_file.parent / f"analysis_report_{latest_file.stem.replace('test_results_', '')}.md"

        checker.generate_report(analysis, report_file)
    else:
        print("No test results found. Run grpc_executor first.")