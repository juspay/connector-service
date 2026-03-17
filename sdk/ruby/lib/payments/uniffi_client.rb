# frozen_string_literal: true

# UniFFI client for Ruby — calls the same shared library as Python/Kotlin/JS.
#
# Uses Ruby FFI to call the UniFFI C ABI directly.
# Handles RustBuffer serialization/deserialization for the UniFFI protocol.
#
# Flow dispatch is generic: call_req(flow, ...) and call_res(flow, ...) load
# the corresponding C symbol dynamically from the flow list in _generated_flows.rb.
# No flow names are hardcoded here — add new flows to services.proto and run `make generate`.

require "ffi"
require_relative "_generated_flows"

module HyperswitchPayments
  # Low-level FFI module that maps the UniFFI C ABI symbols.
  module ConnectorFFI
    extend FFI::Library

    # RustBuffer struct layout: { capacity: u64, len: u64, data: *u8 }
    class RustBuffer < FFI::Struct
      layout :capacity, :uint64,
             :len,      :uint64,
             :data,     :pointer
    end

    # RustCallStatus struct layout: { code: i8, error_buf: RustBuffer }
    class RustCallStatus < FFI::Struct
      layout :code,      :int8,
             :error_buf, RustBuffer
    end

    class << self
      # Load the native library from the given path or auto-detect.
      #
      # @param lib_path [String, nil] optional path to the shared library
      def load_native!(lib_path = nil)
        unless lib_path
          ext = FFI::Platform.mac? ? "dylib" : "so"
          lib_path = File.join(__dir__, "generated", "libconnector_service_ffi.#{ext}")
        end

        ffi_lib lib_path

        # RustBuffer alloc/free
        attach_function :ffi_connector_service_ffi_rustbuffer_alloc,
                        [:uint64, RustCallStatus.by_ref],
                        RustBuffer.by_value

        attach_function :ffi_connector_service_ffi_rustbuffer_free,
                        [RustBuffer.by_value, RustCallStatus.by_ref],
                        :void

        # Attach req/res transformer symbols for every registered flow.
        FLOWS.each_key do |flow|
          attach_function :"uniffi_connector_service_ffi_fn_func_#{flow}_req_transformer",
                          [RustBuffer.by_value, RustBuffer.by_value, RustCallStatus.by_ref],
                          RustBuffer.by_value

          attach_function :"uniffi_connector_service_ffi_fn_func_#{flow}_res_transformer",
                          [RustBuffer.by_value, RustBuffer.by_value, RustBuffer.by_value, RustCallStatus.by_ref],
                          RustBuffer.by_value
        end

        # Attach single-step transformer symbols (no HTTP round-trip).
        SINGLE_FLOWS.each_key do |flow|
          attach_function :"uniffi_connector_service_ffi_fn_func_#{flow}_transformer",
                          [RustBuffer.by_value, RustBuffer.by_value, RustCallStatus.by_ref],
                          RustBuffer.by_value
        end
      end
    end
  end

  # Helper methods for RustBuffer manipulation.
  module RustBufferHelper
    module_function

    def make_call_status
      status = ConnectorFFI::RustCallStatus.new
      status[:code] = 0
      status[:error_buf][:capacity] = 0
      status[:error_buf][:len] = 0
      status[:error_buf][:data] = FFI::Pointer::NULL
      status
    end

    def check_call_status!(status)
      return if status[:code] == 0

      if status[:error_buf][:len] > 0
        msg = lift_string(status[:error_buf])
        free_rust_buffer(status[:error_buf])
        raise "Rust panic: #{msg}"
      end

      raise "Unknown Rust panic"
    end

    # UniFFI Strings are serialized as raw UTF-8 bytes in RustBuffer.
    def lift_string(buf)
      return "" if buf[:data].null? || buf[:len] == 0
      buf[:data].read_bytes(buf[:len]).force_encoding("UTF-8")
    end

    # UniFFI Vec<u8> (Bytes) return values: [i32 length] + [raw bytes]
    def lift_bytes(buf)
      return "".b if buf[:data].null? || buf[:len] == 0
      raw = buf[:data].read_bytes(buf[:len])

      # UniFFI protocol for return values: first 4 bytes are the length of the actual payload
      len = raw[0, 4].unpack1("N") # big-endian i32 — interpret as unsigned for length
      # Handle signed i32: if top bit set, treat as unsigned
      len = len & 0x7FFFFFFF if len & 0x80000000 != 0
      raw[4, len]
    end

    def free_rust_buffer(buf)
      return if buf[:data].null? || buf[:len] == 0
      ConnectorFFI.ffi_connector_service_ffi_rustbuffer_free(buf, make_call_status)
    end

    def alloc_rust_buffer(data)
      status = make_call_status
      buf = ConnectorFFI.ffi_connector_service_ffi_rustbuffer_alloc(data.bytesize, status)
      check_call_status!(status)
      buf[:data].write_bytes(data)
      buf[:len] = data.bytesize
      buf
    end

    # Lowers raw bytes into a UniFFI-compliant buffer for top-level arguments.
    # Protocol: [i32 length prefix] + [raw bytes]
    def lower_bytes(data)
      prefixed = [data.bytesize].pack("N") + data.b
      alloc_rust_buffer(prefixed)
    end
  end

  # High-level UniFFI client wrapping the raw FFI calls.
  #
  # Provides call_req, call_res, and call_direct methods that handle
  # RustBuffer allocation, lowering, lifting, and freeing.
  class UniffiClient
    include RustBufferHelper

    # @param lib_path [String, nil] optional path to the shared library
    def initialize(lib_path = nil)
      ConnectorFFI.load_native!(lib_path)
    end

    # Build the connector HTTP request for any flow.
    # Returns protobuf-encoded FfiConnectorHttpRequest bytes.
    #
    # @param flow [String] flow name (e.g. "authorize")
    # @param request_bytes [String] protobuf-encoded request
    # @param options_bytes [String] protobuf-encoded FfiOptions
    # @return [String] protobuf-encoded FfiConnectorHttpRequest bytes
    def call_req(flow, request_bytes, options_bytes)
      fn_name = :"uniffi_connector_service_ffi_fn_func_#{flow}_req_transformer"
      unless ConnectorFFI.respond_to?(fn_name)
        raise ArgumentError, "Unknown flow: '#{flow}'. Supported: #{FLOWS.keys.join(', ')}"
      end

      rb_req = lower_bytes(request_bytes)
      rb_opts = lower_bytes(options_bytes)
      status = make_call_status

      result = ConnectorFFI.send(fn_name, rb_req, rb_opts, status)

      begin
        check_call_status!(status)
        lift_bytes(result)
      ensure
        free_rust_buffer(result)
      end
    end

    # Parse the connector HTTP response for any flow.
    # response_bytes: protobuf-encoded FfiConnectorHttpResponse.
    # Returns protobuf-encoded response bytes for the flow's response type.
    #
    # @param flow [String] flow name
    # @param response_bytes [String] protobuf-encoded FfiConnectorHttpResponse
    # @param request_bytes [String] protobuf-encoded original request
    # @param options_bytes [String] protobuf-encoded FfiOptions
    # @return [String] protobuf-encoded response bytes
    def call_res(flow, response_bytes, request_bytes, options_bytes)
      fn_name = :"uniffi_connector_service_ffi_fn_func_#{flow}_res_transformer"
      unless ConnectorFFI.respond_to?(fn_name)
        raise ArgumentError, "Unknown flow: '#{flow}'. Supported: #{FLOWS.keys.join(', ')}"
      end

      rb_res = lower_bytes(response_bytes)
      rb_req = lower_bytes(request_bytes)
      rb_opts = lower_bytes(options_bytes)
      status = make_call_status

      result = ConnectorFFI.send(fn_name, rb_res, rb_req, rb_opts, status)

      begin
        check_call_status!(status)
        lift_bytes(result)
      ensure
        free_rust_buffer(result)
      end
    end

    # Execute a single-step transformer directly (no HTTP round-trip).
    # Used for inbound flows like webhook processing.
    #
    # @param flow [String] flow name (e.g. "handle_event")
    # @param request_bytes [String] protobuf-encoded request
    # @param options_bytes [String] protobuf-encoded FfiOptions
    # @return [String] protobuf-encoded response bytes
    def call_direct(flow, request_bytes, options_bytes)
      fn_name = :"uniffi_connector_service_ffi_fn_func_#{flow}_transformer"
      unless ConnectorFFI.respond_to?(fn_name)
        raise ArgumentError, "Unknown single-step flow: '#{flow}'. Supported: #{SINGLE_FLOWS.keys.join(', ')}"
      end

      rb_req = lower_bytes(request_bytes)
      rb_opts = lower_bytes(options_bytes)
      status = make_call_status

      result = ConnectorFFI.send(fn_name, rb_req, rb_opts, status)

      begin
        check_call_status!(status)
        lift_bytes(result)
      ensure
        free_rust_buffer(result)
      end
    end
  end
end
