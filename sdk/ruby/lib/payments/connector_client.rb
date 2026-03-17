# frozen_string_literal: true

# ConnectorClientBase — high-level wrapper using UniFFI bindings via Ruby FFI.
#
# Handles the full round-trip for any payment flow:
#   1. Serialize protobuf request to bytes
#   2. Build connector HTTP request via UniffiClient.call_req (generic FFI dispatch)
#   3. Execute the HTTP request via our standardized HttpClient
#   4. Parse the connector response via UniffiClient.call_res (generic FFI dispatch)
#   5. Deserialize protobuf response from bytes
#
# Flow methods (authorize, capture, void, refund, ...) are in _generated_service_clients.rb.
# To add a new flow: implement a req_transformer in services/payments.rs and run `make generate`.

require_relative "uniffi_client"
require_relative "http_client"

module HyperswitchPayments
  # Exception raised when req_transformer fails.
  class RequestError < StandardError
    attr_reader :proto

    def initialize(proto)
      @proto = proto
      super(proto.respond_to?(:error_message) ? proto.error_message : proto.to_s)
    end

    def method_missing(name, *args)
      if @proto.respond_to?(name)
        @proto.send(name, *args)
      else
        super
      end
    end

    def respond_to_missing?(name, include_private = false)
      @proto.respond_to?(name, include_private) || super
    end
  end

  # Exception raised when res_transformer fails.
  class ResponseError < StandardError
    attr_reader :proto

    def initialize(proto)
      @proto = proto
      super(proto.respond_to?(:error_message) ? proto.error_message : proto.to_s)
    end

    def method_missing(name, *args)
      if @proto.respond_to?(name)
        @proto.send(name, *args)
      else
        super
      end
    end

    def respond_to_missing?(name, include_private = false)
      @proto.respond_to?(name, include_private) || super
    end
  end

  # Base class for per-service connector clients. Do not instantiate directly.
  class ConnectorClientBase
    # @param config [Sdk_config_pb::ConnectorConfig] connector config and environment
    # @param defaults [Sdk_config_pb::RequestConfig, nil] optional per-request defaults
    # @param lib_path [String, nil] optional path to the shared library
    def initialize(config, defaults: nil, lib_path: nil)
      @config = config
      @defaults = defaults
      @uniffi = UniffiClient.new(lib_path)
    end

    private

    # Merges request-level options with client defaults.
    def resolve_config(options = nil)
      environment = @config.options.environment
      connector_config = @config.connector_config

      http_config = if options&.respond_to?(:http) && options.http
                      options.http
                    elsif @defaults&.respond_to?(:http) && @defaults.http
                      @defaults.http
                    end

      ffi = Sdk_config_pb::FfiOptions.new(
        environment: environment,
        connector_config: connector_config
      )

      [ffi, http_config]
    end

    # Execute a full round-trip for any registered payment flow.
    #
    # @param flow [String] flow name matching the FFI transformer prefix
    # @param request [Object] protobuf request message
    # @param response_cls [Class] protobuf message class for the response
    # @param options [Object, nil] optional per-request config overrides
    # @return [Object] decoded domain response proto
    def execute_flow(flow, request, response_cls, options = nil)
      ffi_options, http_config = resolve_config(options)

      request_bytes = request.class.encode(request)
      options_bytes = Sdk_config_pb::FfiOptions.encode(ffi_options)

      # Build connector HTTP request via FFI
      result_bytes = @uniffi.call_req(flow, request_bytes, options_bytes)

      # Try to decode as RequestError first
      begin
        error_proto = Sdk_config_pb::RequestError.decode(result_bytes)
        raise RequestError, error_proto if error_proto.respond_to?(:status) && error_proto.status != :PAYMENT_STATUS_UNSPECIFIED && error_proto.status != 0
      rescue Google::Protobuf::ParseError
        # Not an error proto, continue
      rescue RequestError
        raise
      end

      connector_req = Sdk_config_pb::FfiConnectorHttpRequest.decode(result_bytes)

      http_request = HttpRequest.new(
        url: connector_req.url,
        method: connector_req.method,
        headers: connector_req.headers.to_h,
        body: connector_req.respond_to?(:body) && !connector_req.body.empty? ? connector_req.body : nil
      )

      # Execute HTTP using the standardized client
      response = HyperswitchPayments.execute_http(http_request, http_config: http_config)

      # Encode HTTP response for FFI
      res_proto = Sdk_config_pb::FfiConnectorHttpResponse.new(
        status_code: response.status_code,
        headers: response.headers,
        body: response.body
      )
      res_bytes = Sdk_config_pb::FfiConnectorHttpResponse.encode(res_proto)

      # Parse connector response via FFI and decode
      result_bytes_res = @uniffi.call_res(flow, res_bytes, request_bytes, options_bytes)

      # Try to decode as ResponseError first
      begin
        error_proto = Sdk_config_pb::ResponseError.decode(result_bytes_res)
        raise ResponseError, error_proto if error_proto.respond_to?(:status) && error_proto.status != :PAYMENT_STATUS_UNSPECIFIED && error_proto.status != 0
      rescue Google::Protobuf::ParseError
        # Not an error proto, continue
      rescue ResponseError
        raise
      end

      response_cls.decode(result_bytes_res)
    end

    # Execute a single-step flow directly via FFI (no HTTP round-trip).
    # Used for inbound flows like webhook processing.
    #
    # @param flow [String] flow name
    # @param request [Object] protobuf request message
    # @param response_cls [Class] protobuf message class for the response
    # @param options [Object, nil] optional per-request config overrides
    # @return [Object] decoded domain response proto
    def execute_direct(flow, request, response_cls, options = nil)
      ffi_options, _ = resolve_config(options)

      request_bytes = request.class.encode(request)
      options_bytes = Sdk_config_pb::FfiOptions.encode(ffi_options)

      result_bytes = @uniffi.call_direct(flow, request_bytes, options_bytes)

      # Try to decode as ResponseError first
      begin
        error_proto = Sdk_config_pb::ResponseError.decode(result_bytes)
        raise ResponseError, error_proto if error_proto.respond_to?(:status) && error_proto.status != :PAYMENT_STATUS_UNSPECIFIED && error_proto.status != 0
      rescue Google::Protobuf::ParseError
        # Not an error proto, continue
      rescue ResponseError
        raise
      end

      response_cls.decode(result_bytes)
    end
  end
end
