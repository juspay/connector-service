# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Billdesk connector implementation with UPI (Authorize) and PSync flows
  - Added Billdesk connector enum in domain_types/src/connector_types.rs
  - Added Billdesk connector parameters in domain_types/src/types.rs
  - Added Billdesk connector integration in connector-integration/src/types.rs
  - Created connector module at src/connectors/billdesk/
  - Implemented transformers for UPI flows at src/connectors/billdesk/transformers.rs
  - Added API endpoints and constants at src/connectors/billdesk/constants.rs
  - Implemented main connector logic using UCS v2 macro framework at src/connectors/billdesk.rs