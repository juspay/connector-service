# frozen_string_literal: true

# Standardized HTTP client for the Hyperswitch Connector Service Ruby SDK.
#
# Uses Net::HTTP with fintech-grade timeout handling.
# Mirrors the http_client.ts / http_client.py implementations.

require "net/http"
require "uri"

module HyperswitchPayments
  # Default HTTP timeout values (in milliseconds) matching the proto HttpDefault enum.
  module HttpDefaults
    CONNECT_TIMEOUT_MS    = 10_000
    RESPONSE_TIMEOUT_MS   = 30_000
    TOTAL_TIMEOUT_MS      = 45_000
    KEEP_ALIVE_TIMEOUT_MS = 60_000
  end

  # Specialized error class for HTTP failures in the Connector Service.
  class ConnectorError < StandardError
    attr_reader :status_code, :error_code, :body, :headers

    def initialize(message, status_code: nil, error_code: nil, body: nil, headers: nil)
      super(message)
      @status_code = status_code
      @error_code = error_code
      @body = body
      @headers = headers
    end
  end

  # Normalized HTTP Request structure.
  HttpRequest = Struct.new(:url, :method, :headers, :body, keyword_init: true)

  # Normalized HTTP Response structure.
  HttpResponse = Struct.new(:status_code, :headers, :body, :latency_ms, keyword_init: true)

  # Execute an HTTP request with configurable timeouts.
  #
  # @param request [HttpRequest] the request to execute
  # @param http_config [Object, nil] protobuf HttpConfig with timeout overrides
  # @return [HttpResponse]
  def self.execute_http(request, http_config: nil)
    uri = URI.parse(request.url)

    connect_timeout = (http_config&.respond_to?(:connect_timeout_ms) && http_config.connect_timeout_ms > 0 ?
      http_config.connect_timeout_ms : HttpDefaults::CONNECT_TIMEOUT_MS) / 1000.0
    response_timeout = (http_config&.respond_to?(:response_timeout_ms) && http_config.response_timeout_ms > 0 ?
      http_config.response_timeout_ms : HttpDefaults::RESPONSE_TIMEOUT_MS) / 1000.0

    start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.open_timeout = connect_timeout
    http.read_timeout = response_timeout
    http.write_timeout = response_timeout

    req_class = case request.method.upcase
                when "GET"    then Net::HTTP::Get
                when "POST"   then Net::HTTP::Post
                when "PUT"    then Net::HTTP::Put
                when "DELETE" then Net::HTTP::Delete
                when "PATCH"  then Net::HTTP::Patch
                else
                  raise ConnectorError.new(
                    "Unsupported HTTP method: #{request.method}",
                    error_code: "INVALID_CONFIGURATION"
                  )
                end

    http_req = req_class.new(uri.request_uri)

    # Set headers
    (request.headers || {}).each do |key, value|
      http_req[key] = value
    end

    # Set body
    http_req.body = request.body if request.body && !request.body.empty?

    response = http.request(http_req)

    elapsed_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time) * 1000).round

    response_headers = {}
    response.each_header { |k, v| response_headers[k.downcase] = v }

    HttpResponse.new(
      status_code: response.code.to_i,
      headers: response_headers,
      body: (response.body || "").b,
      latency_ms: elapsed_ms
    )
  rescue Net::OpenTimeout
    raise ConnectorError.new(
      "Connection Timeout: Failed to connect to #{request.url}",
      status_code: 504,
      error_code: "CONNECT_TIMEOUT"
    )
  rescue Net::ReadTimeout
    raise ConnectorError.new(
      "Response Timeout: Gateway #{request.url} accepted connection but failed to respond",
      status_code: 504,
      error_code: "RESPONSE_TIMEOUT"
    )
  rescue Timeout::Error
    raise ConnectorError.new(
      "Total Request Timeout: #{request.method} #{request.url} exceeded timeout",
      status_code: 504,
      error_code: "TOTAL_TIMEOUT"
    )
  rescue StandardError => e
    raise ConnectorError.new(
      "Network Error: #{e.message}",
      status_code: 500,
      error_code: "NETWORK_FAILURE"
    )
  end
end
