# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- PayTMv2 connector implementation with UCS v2 macro framework
  - Support for UPI payment flows (Intent and Collect)
  - Authorize flow for UPI payment initiation
  - PSync flow for payment status synchronization
  - RSync flow for refund status synchronization
  - Type-safe implementation using Secret<String> for sensitive data
  - Proper amount framework using MinorUnit for monetary values
  - Comprehensive error handling and status mapping
  - API endpoint constants and configuration management

### Changed
- Updated connector registration system to include PayTMv2
- Added PayTMv2 to ConnectorEnum in domain_types
- Updated types.rs convert_connector function to support PayTMv2
- Enhanced connector module exports to include PayTMv2

### Security
- Implemented proper checksum generation for PayTMv2 API authentication
- Added secure handling of merchant credentials using Secret<String>
- Enhanced validation for UPI payment methods

## [0.1.0] - 2024-01-01

### Added
- Initial connector framework implementation
- UCS v2 macro framework for connector development
- Base connector types and traits
- Payment flow data structures
- Error handling framework
- Amount conversion utilities

### Added
- Support for existing connectors:
  - Adyen
  - Razorpay
  - RazorpayV2
  - Fiserv
  - Elavon
  - Xendit
  - Checkout
  - Authorizedotnet
  - Mifinity
  - Phonepe
  - Cashfree
  - Paytm
  - Fiuu
  - Payu
  - Cashtocode
  - Novalnet
  - Nexinets
  - Noon