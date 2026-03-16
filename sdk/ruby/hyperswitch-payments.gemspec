# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = "hyperswitch-payments"
  spec.version       = "0.1.0"
  spec.summary       = "Hyperswitch Payments SDK - Ruby client for connector integrations via UniFFI FFI"
  spec.description   = "Ruby SDK for the Hyperswitch Connector Service. " \
                        "Uses FFI bindings to call Rust UniFFI shared library for payment connector integrations."
  spec.authors       = ["Juspay"]
  spec.license       = "Apache-2.0"
  spec.homepage      = "https://github.com/juspay/connector-service"

  spec.required_ruby_version = ">= 3.0.0"

  spec.files = Dir[
    "lib/**/*.rb",
    "lib/payments/generated/*",
  ]
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi", "~> 1.17"
  spec.add_dependency "google-protobuf", "~> 4.29"

  spec.add_development_dependency "net-http", "~> 0.6"
  spec.add_development_dependency "json", "~> 2.9"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
