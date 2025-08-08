#!/usr/bin/env python3
"""
Locust load testing script for Connector Service Dapr solution.
This script generates 200 events per second by making gRPC calls to test Dapr metrics.
"""

# Fix for gevent threading issues - MUST be first
from gevent import monkey
monkey.patch_all()

import json
import random
import time
import uuid
from datetime import datetime
from typing import Dict, Any
import subprocess
import os
import gevent

from locust import User, task, events
from locust.env import Environment


class ConnectorServiceUser(User):
    """
    Locust user class for testing the Connector Service gRPC endpoints.
    Simulates payment authorization and refund requests to generate events.
    """
    
    # Configuration
    weight = 1
    host = "localhost:8000"  # gRPC server address
    
    # Test data configuration
    CONNECTOR_NAME = "checkout"
    TENANT_ID = "test_tenant"
    MERCHANT_ID = "test_merchant"
    
    def __init__(self, environment):
        super().__init__(environment)
        self.api_key = os.getenv("CONNECTOR_API_KEY", "test_api_key")
        self.key1 = os.getenv("CONNECTOR_KEY1", "test_key1")
        self.api_secret = os.getenv("CONNECTOR_API_SECRET", "test_api_secret")
        
        # Validate required environment variables
        if not all([self.api_key, self.key1, self.api_secret]):
            raise ValueError(
                "Required environment variables not set: "
                "CONNECTOR_API_KEY, CONNECTOR_KEY1, CONNECTOR_API_SECRET"
            )
    
    def on_start(self):
        """Called when a user starts running."""
        print(f"Starting user with host: {self.host}")
    
    def generate_payment_id(self) -> str:
        """Generate a unique payment ID."""
        timestamp = int(time.time())
        random_part = random.randint(1000, 9999)
        return f"payment_{timestamp}_{random_part}"
    
    def generate_request_id(self) -> str:
        """Generate a unique request ID."""
        timestamp = int(time.time())
        random_part = random.randint(1000, 9999)
        return f"req_{timestamp}_{random_part}"
    
    def generate_udf_txn_uuid(self) -> str:
        """Generate a unique UDF transaction UUID."""
        timestamp = int(time.time())
        random_part = random.randint(1000, 9999)
        return f"txn_{timestamp}_{random_part}"
    
    def make_grpc_call(self, method: str, data: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Make a gRPC call using grpcurl subprocess.
        This is a workaround since we don't have the generated Python gRPC stubs.
        """
        start_time = time.time()
        
        # Build grpcurl command
        cmd = [
            "grpcurl",
            "-plaintext",
            "-d", json.dumps(data)
        ]
        
        # Add headers
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])
        
        # Add target and method
        cmd.extend([self.host, method])
        
        try:
            # Execute the command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # 30 second timeout
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if result.returncode == 0:
                # Success
                try:
                    response_data = json.loads(result.stdout) if result.stdout.strip() else {}
                except json.JSONDecodeError:
                    response_data = {"raw_response": result.stdout}
                
                # Fire success event
                events.request.fire(
                    request_type="gRPC",
                    name=method,
                    response_time=response_time,
                    response_length=len(result.stdout),
                    exception=None,
                    context=self.context()
                )
                
                return response_data
            else:
                # Error
                error_msg = result.stderr or result.stdout or "Unknown error"
                
                # Fire failure event
                events.request.fire(
                    request_type="gRPC",
                    name=method,
                    response_time=response_time,
                    response_length=len(error_msg),
                    exception=Exception(error_msg),
                    context=self.context()
                )
                
                raise Exception(f"gRPC call failed: {error_msg}")
                
        except subprocess.TimeoutExpired:
            response_time = int((time.time() - start_time) * 1000)
            events.request.fire(
                request_type="gRPC",
                name=method,
                response_time=response_time,
                response_length=0,
                exception=Exception("Request timeout"),
                context=self.context()
            )
            raise Exception("Request timeout")
        except Exception as e:
            response_time = int((time.time() - start_time) * 1000)
            events.request.fire(
                request_type="gRPC",
                name=method,
                response_time=response_time,
                response_length=0,
                exception=e,
                context=self.context()
            )
            raise
    
    @task(1)  # Only authorization requests
    def authorize_payment(self):
        """Make a payment authorization request."""
        payment_id = self.generate_payment_id()
        request_id = self.generate_request_id()
        udf_txn_uuid = self.generate_udf_txn_uuid()
        
        # Generate random card numbers for testing (using test card numbers)
        test_cards = [
            "4000020000000000",  # Visa test card
            "4000000000000002",  # Visa test card (declined)
            "5555555555554444",  # Mastercard test card
            "4000000000000069",  # Visa test card (expired)
        ]
        
        card_number = random.choice(test_cards)
        amount = random.randint(100, 10000)  # Random amount between $1 and $100
        
        headers = {
            "x-tenant-id": self.TENANT_ID,
            "x-request-id": request_id,
            "x-connector": self.CONNECTOR_NAME,
            "x-merchant-id": self.MERCHANT_ID,
            "x-auth": "signature-key",
            "x-api-key": self.api_key,
            "x-key1": self.key1,
            "x-api-secret": self.api_secret,
            "udf-txn-uuid": udf_txn_uuid,
        }
        
        data = {
            "amount": amount,
            "minor_amount": amount,
            "currency": "USD",
            "payment_method": {
                "card": {
                    "credit": {
                        "card_number": card_number,
                        "card_exp_month": "12",
                        "card_exp_year": "2030",
                        "card_cvc": "123",
                        "card_holder_name": "Test User",
                        "card_network": "VISA"
                    }
                }
            },
            "email": f"customer{random.randint(1, 1000)}@example.com",
            "address": {
                "shipping_address": {},
                "billing_address": {}
            },
            "auth_type": "NO_THREE_DS",
            "request_ref_id": {
                "id": payment_id
            },
            "enrolled_for_3ds": False,
            "request_incremental_authorization": False,
            "capture_method": "AUTOMATIC",
            "metadata": {
                "udf_txn_uuid": udf_txn_uuid,
                "transaction_id": payment_id
            }
        }
        
        try:
            response = self.make_grpc_call(
                "ucs.v2.PaymentService/Authorize",
                data,
                headers
            )
            print(f"Authorization successful for payment {payment_id}")
                
        except Exception as e:
            print(f"Authorization failed for payment {payment_id}: {e}")


def run_load_test():
    """
    Run the load test with 200 events per second.
    """
    # Check if required environment variables are set
    required_vars = ["CONNECTOR_API_KEY", "CONNECTOR_KEY1", "CONNECTOR_API_SECRET"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print("Error: Missing required environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these variables before running the test:")
        print("export CONNECTOR_API_KEY=your_api_key")
        print("export CONNECTOR_KEY1=your_key1")
        print("export CONNECTOR_API_SECRET=your_api_secret")
        return
    
    # Check if grpcurl is available
    try:
        subprocess.run(["grpcurl", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: grpcurl is not installed or not in PATH")
        print("Please install grpcurl: https://github.com/fullstorydev/grpcurl")
        return
    
    print("Starting Locust load test for Connector Service...")
    print("Target: 200 events per second")
    print("Mix: 100% payment authorizations only")
    
    # Create environment
    env = Environment(user_classes=[ConnectorServiceUser])
    
    # Start the test
    # To achieve 200 events per second, we need to calculate users and spawn rate
    # Each user makes requests based on task weights and wait times
    # With default wait time, each user makes ~1 request per second
    # So we need ~200 users to get 200 requests per second
    
    users = 200
    spawn_rate = 10  # Spawn 10 users per second
    
    print(f"Spawning {users} users at rate of {spawn_rate} users/second")
    
    env.create_local_runner()
    env.runner.start(users, spawn_rate)
    
    # Run for a specified duration or until interrupted
    try:
        print("Load test running... Press Ctrl+C to stop")
        env.runner.greenlet.join()
    except KeyboardInterrupt:
        print("\nStopping load test...")
        env.runner.stop()
    
    # Print final stats
    print("\nLoad test completed!")
    print("Check Dapr metrics and Kafka for generated events.")


if __name__ == "__main__":
    run_load_test()
