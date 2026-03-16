# frozen_string_literal: true

# Hyperswitch Payments SDK for Ruby
#
# Provides high-level client classes for payment connector integrations
# using Rust UniFFI FFI bindings.

require "google/protobuf"

# Load generated protobuf types
require_relative "payments/generated/payment_pb"
require_relative "payments/generated/payment_methods_pb"
require_relative "payments/generated/sdk_config_pb"

# Load SDK core
require_relative "payments/uniffi_client"
require_relative "payments/http_client"
require_relative "payments/connector_client"
require_relative "payments/_generated_flows"
require_relative "payments/_generated_service_clients"

module HyperswitchPayments
  # Re-export commonly used protobuf types for convenience
  ConnectorConfig = Sdk_config_pb::ConnectorConfig
  RequestConfig = Sdk_config_pb::RequestConfig
  FfiOptions = Sdk_config_pb::FfiOptions
  Environment = Sdk_config_pb::Environment
end
