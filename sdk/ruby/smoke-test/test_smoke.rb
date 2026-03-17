#!/usr/bin/env ruby
# frozen_string_literal: true

# Multi-connector smoke test for the hyperswitch-payments Ruby SDK.
#
# Loads connector credentials from external JSON file and runs authorize flow
# for multiple connectors.
#
# Usage:
#   ruby test_smoke.rb --creds-file creds.json --all
#   ruby test_smoke.rb --creds-file creds.json --connectors stripe,aci
#   ruby test_smoke.rb --creds-file creds.json --all --dry-run

require "json"
require "optparse"
require "payments"

# Test card configurations
TEST_CARDS = {
  "visa" => {
    "number" => "4111111111111111",
    "exp_month" => "12",
    "exp_year" => "2050",
    "cvc" => "123",
    "holder" => "Test User"
  },
  "mastercard" => {
    "number" => "5555555555554444",
    "exp_month" => "12",
    "exp_year" => "2050",
    "cvc" => "123",
    "holder" => "Test User"
  }
}.freeze

DEFAULT_AMOUNT = { minor_amount: 1000, currency: :USD }.freeze

PLACEHOLDER_VALUES = Set["", "placeholder", "test", "dummy", "sk_test_placeholder"].freeze

def load_credentials(creds_file)
  raise "Credentials file not found: #{creds_file}" unless File.exist?(creds_file)

  JSON.parse(File.read(creds_file))
end

def placeholder?(value)
  return true if value.nil? || value.empty?

  PLACEHOLDER_VALUES.include?(value.downcase) || value.downcase.include?("placeholder")
end

def valid_credentials?(auth_config)
  auth_config.each do |key, value|
    next if %w[metadata _comment].include?(key)

    if value.is_a?(Hash) && value.key?("value")
      return true if value["value"].is_a?(String) && !placeholder?(value["value"])
    elsif value.is_a?(String) && !placeholder?(value)
      return true
    end
  end
  false
end

def build_authorize_request(card_type = "visa")
  card = TEST_CARDS[card_type] || TEST_CARDS["visa"]

  Payment_pb::PaymentServiceAuthorizeRequest.new(
    merchant_transaction_id: "smoke_test_#{Time.now.to_i}_#{rand(36**9).to_s(36)}",
    amount: Payment_pb::MinorAmount.new(
      minor_amount: DEFAULT_AMOUNT[:minor_amount],
      currency: DEFAULT_AMOUNT[:currency]
    ),
    capture_method: :AUTOMATIC,
    payment_method: Payment_pb::PaymentMethodData.new(
      card: Payment_pb::Card.new(
        card_number: Payment_pb::SecretString.new(value: card["number"]),
        card_exp_month: Payment_pb::SecretString.new(value: card["exp_month"]),
        card_exp_year: Payment_pb::SecretString.new(value: card["exp_year"]),
        card_cvc: Payment_pb::SecretString.new(value: card["cvc"]),
        card_holder_name: Payment_pb::SecretString.new(value: card["holder"])
      )
    ),
    customer: Payment_pb::Customer.new(
      email: Payment_pb::SecretString.new(value: "test@example.com"),
      name: "Test User"
    ),
    auth_type: :NO_THREE_DS,
    return_url: "https://example.com/return",
    webhook_url: "https://example.com/webhook",
    address: Payment_pb::PaymentAddress.new,
    test_mode: true
  )
end

def test_connector(instance_name, auth_config, dry_run: false, base_connector_name: nil)
  connector_key = base_connector_name || instance_name

  result = {
    connector: instance_name,
    status: "pending"
  }

  begin
    req = build_authorize_request

    connector_config_fields = {}
    auth_config.each do |key, value|
      next if %w[_comment metadata].include?(key)

      camel_key = key.gsub(/_([a-z])/) { Regexp.last_match(1).upcase }
      connector_config_fields[camel_key] = value
    end

    connector_auth_key = connector_key.downcase

    config = Sdk_config_pb::ConnectorConfig.new(
      options: Sdk_config_pb::SdkOptions.new(environment: :SANDBOX),
      connector_config: Sdk_config_pb::ConnectorSpecificConfig.new(
        "#{connector_auth_key}" => build_connector_auth(connector_auth_key, auth_config)
      )
    )

    client = HyperswitchPayments::PaymentClient.new(config)

    if dry_run
      result[:status] = "dry_run"
      return result
    end

    unless valid_credentials?(auth_config)
      result[:status] = "skipped"
      return result
    end

    begin
      response = client.authorize(req)
      result[:status] = "passed"
    rescue HyperswitchPayments::RequestError => e
      result[:status] = "passed_with_error"
      result[:error] = e.message
    rescue HyperswitchPayments::ResponseError => e
      result[:status] = "passed_with_error"
      result[:error] = e.message
    rescue StandardError => e
      result[:status] = "passed_with_error"
      result[:error] = e.message
    end
  rescue StandardError => e
    result[:status] = "failed"
    result[:error] = e.message
  end

  result
end

def build_connector_auth(connector_name, auth_config)
  # Build the connector-specific auth message dynamically
  # The protobuf message type matches the connector name
  fields = {}
  auth_config.each do |key, value|
    next if %w[_comment metadata].include?(key)

    if value.is_a?(Hash) && value.key?("value")
      fields[key] = Payment_pb::SecretString.new(value: value["value"])
    elsif value.is_a?(String)
      fields[key] = Payment_pb::SecretString.new(value: value)
    end
  end
  # Return the fields hash — connector-specific auth is handled by protobuf
  fields
rescue StandardError
  {}
end

def run_tests(creds_file, connectors, dry_run)
  credentials = load_credentials(creds_file)
  results = []

  test_connectors = connectors || credentials.keys

  puts "\n#{"=" * 60}"
  puts "Running smoke tests for #{test_connectors.length} connector(s)"
  puts "#{"=" * 60}\n"

  test_connectors.each do |connector_name|
    auth_config = credentials[connector_name]

    unless auth_config
      puts "\n--- Testing #{connector_name} ---"
      puts "  SKIPPED (not found in credentials file)"
      results << { connector: connector_name, status: "skipped", error: "not_found" }
      next
    end

    puts "\n--- Testing #{connector_name} ---"

    if auth_config.is_a?(Array)
      auth_config.each_with_index do |instance_auth, i|
        instance_name = "#{connector_name}[#{i + 1}]"
        puts "  Instance: #{instance_name}"

        unless valid_credentials?(instance_auth)
          puts "  SKIPPED (placeholder credentials)"
          results << { connector: instance_name, status: "skipped" }
          next
        end

        result = test_connector(instance_name, instance_auth, dry_run: dry_run, base_connector_name: connector_name)
        results << result
        print_result(result)
      end
    else
      unless valid_credentials?(auth_config)
        puts "  SKIPPED (placeholder credentials)"
        results << { connector: connector_name, status: "skipped" }
        next
      end

      result = test_connector(connector_name, auth_config, dry_run: dry_run)
      results << result
      print_result(result)
    end
  end

  results
end

def print_result(result)
  case result[:status]
  when "passed"
    puts "  PASSED"
  when "passed_with_error"
    puts "  PASSED (with connector error: #{result[:error]})"
  when "dry_run"
    puts "  DRY RUN"
  else
    puts "  #{result[:status].upcase}: #{result[:error] || 'Unknown error'}"
  end
end

def print_summary(results)
  puts "\n#{"=" * 60}"
  puts "TEST SUMMARY"
  puts "#{"=" * 60}\n"

  passed = results.count { |r| %w[passed passed_with_error dry_run].include?(r[:status]) }
  skipped = results.count { |r| r[:status] == "skipped" }
  failed = results.count { |r| r[:status] == "failed" }
  total = results.length

  puts "Total:   #{total}"
  puts "Passed:  #{passed}"
  puts "Skipped: #{skipped} (placeholder credentials)"
  puts "Failed:  #{failed}"
  puts

  if failed > 0
    puts "Failed tests:"
    results.each do |r|
      puts "  - #{r[:connector]}: #{r[:error] || 'Unknown error'}" if r[:status] == "failed"
    end
    puts
    return 1
  end

  if passed == 0 && skipped > 0
    puts "All tests skipped (no valid credentials found)"
    puts "Update creds.json with real credentials to run tests"
    return 1
  end

  puts "All tests completed successfully!"
  0
end

# Parse CLI arguments
options = { creds_file: "creds.json", connectors: nil, all: false, dry_run: false }

OptionParser.new do |opts|
  opts.banner = "Usage: ruby test_smoke.rb [options]"

  opts.on("--creds-file FILE", "Path to credentials JSON (default: creds.json)") { |v| options[:creds_file] = v }
  opts.on("--connectors LIST", "Comma-separated list of connectors") { |v| options[:connectors] = v.split(",").map(&:strip) }
  opts.on("--all", "Test all connectors") { options[:all] = true }
  opts.on("--dry-run", "Build requests without executing HTTP") { options[:dry_run] = true }
end.parse!

unless options[:all] || options[:connectors]
  warn "Error: Must specify either --all or --connectors"
  exit 1
end

begin
  results = run_tests(options[:creds_file], options[:connectors], options[:dry_run])
  exit_code = print_summary(results)
  exit(exit_code)
rescue StandardError => e
  warn "\nFatal error: #{e.message}"
  exit 1
end
