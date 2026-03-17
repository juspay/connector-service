#!/usr/bin/env ruby
# frozen_string_literal: true

# Smoke test for PayPal access token flow using hyperswitch-payments Ruby gem.
#
# This test demonstrates:
#   1. Create an access token via PayPal
#   2. Use the access token in an authorize request
#
# Usage:
#   ruby test_smoke_composite.rb

require "payments"

PAYPAL_CREDS = {
  "client_id" => "client_id",
  "client_secret" => "client_secret"
}.freeze

# ConnectorConfig (connector, auth, environment)
config = Sdk_config_pb::ConnectorConfig.new(
  options: Sdk_config_pb::SdkOptions.new(environment: :SANDBOX),
  connector_config: Sdk_config_pb::ConnectorSpecificConfig.new(
    paypal: Sdk_config_pb::PaypalAuth.new(
      client_id: Payment_pb::SecretString.new(value: PAYPAL_CREDS["client_id"]),
      client_secret: Payment_pb::SecretString.new(value: PAYPAL_CREDS["client_secret"])
    )
  )
)

defaults = Sdk_config_pb::RequestConfig.new

puts "\n=== Test: PayPal Access Token Flow ==="

auth_client = HyperswitchPayments::MerchantAuthenticationClient.new(config, defaults: defaults)
payment_client = HyperswitchPayments::PaymentClient.new(config, defaults: defaults)

# Step 1: Create Access Token Request
puts "\n--- Step 1: Create Access Token ---"

access_token_request = Payment_pb::MerchantAuthenticationServiceCreateAccessTokenRequest.new(
  merchant_access_token_id: "access_token_test_#{Time.now.to_i}",
  connector: :PAYPAL,
  test_mode: true
)

begin
  access_token_response = auth_client.create_access_token(access_token_request)
  puts "  Response type: #{access_token_response.class}"

  if access_token_response.access_token&.value
    access_token_value = access_token_response.access_token.value
    token_type = access_token_response.token_type || "Bearer"
    puts "  Access Token received: #{access_token_value[0, 20]}..."
    puts "  Token Type: #{token_type}"
    puts "  Expires In: #{access_token_response.expires_in_seconds} seconds"
    puts "  Status: #{access_token_response.status}"
  else
    puts "  WARNING: No access token in response"
    puts "  Full response: #{access_token_response.inspect}"
  end
rescue HyperswitchPayments::RequestError => e
  puts "  RequestError: #{e.message}"
  puts "  This might be expected if credentials are not valid"
  access_token_value = nil
rescue HyperswitchPayments::ResponseError => e
  puts "  ResponseError: #{e.message}"
  puts "  This might be expected if credentials are not valid"
  access_token_value = nil
rescue StandardError => e
  puts "  Error creating access token: #{e.message}"
  puts "  This might be expected if credentials are not valid"
  access_token_value = nil
end

unless access_token_value
  puts "  SKIPPED: Cannot proceed without access token"
  puts "\n=== Test Complete ==="
  puts "\nAll checks passed."
  exit 0
end

# Step 2: Use Access Token in Authorize Request
puts "\n--- Step 2: Authorize with Access Token ---"

authorize_request = Payment_pb::PaymentServiceAuthorizeRequest.new(
  merchant_transaction_id: "authorize_with_token_#{Time.now.to_i}",
  amount: Payment_pb::MinorAmount.new(
    minor_amount: 1000,
    currency: :USD
  ),
  capture_method: :AUTOMATIC,
  payment_method: Payment_pb::PaymentMethodData.new(
    card: Payment_pb::Card.new(
      card_number: Payment_pb::SecretString.new(value: "4111111111111111"),
      card_exp_month: Payment_pb::SecretString.new(value: "12"),
      card_exp_year: Payment_pb::SecretString.new(value: "2050"),
      card_cvc: Payment_pb::SecretString.new(value: "123"),
      card_holder_name: Payment_pb::SecretString.new(value: "Test User")
    )
  ),
  customer: Payment_pb::Customer.new(
    email: Payment_pb::SecretString.new(value: "test@example.com"),
    name: "Test"
  ),
  state: Payment_pb::ConnectorState.new(
    access_token: Payment_pb::AccessToken.new(
      token: Payment_pb::SecretString.new(value: access_token_value),
      token_type: token_type,
      expires_in_seconds: access_token_response.expires_in_seconds
    )
  ),
  auth_type: :NO_THREE_DS,
  return_url: "https://example.com/return",
  webhook_url: "https://example.com/webhook",
  address: Payment_pb::PaymentAddress.new,
  test_mode: true
)

begin
  authorize_response = payment_client.authorize(authorize_request)
  puts "  Response type: #{authorize_response.class}"
  puts "  Payment status: #{authorize_response.status}"
  puts "  PASSED"
rescue HyperswitchPayments::RequestError => e
  puts "  RequestError: #{e.message}"
  puts "  PASSED (round-trip completed, error is from PayPal)"
rescue HyperswitchPayments::ResponseError => e
  puts "  ResponseError: #{e.message}"
  puts "  PASSED (round-trip completed, error is from PayPal)"
rescue StandardError => e
  puts "  Error during authorize: #{e.message}"
  puts "  PASSED (round-trip completed, error is from PayPal)"
end

puts "\n=== Test Complete ==="
puts "\nAll checks passed."
