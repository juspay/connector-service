// Re-export client classes flat (high-level API)
export * from "./payments/_generated_connector_client_flows";
export { UniffiClient } from "./payments/_generated_uniffi_client_flows";
export type { RustBuffer, RustCallStatus } from "./payments/uniffi_client";
export * from "./http_client";
export * from './payments/generated/proto';

// ---------------------------------------------------------------------------
// Domain namespaces — runtime values
// Usage: import { payments, payment_methods, configs } from '@juspay/connector-service-sdk';
//        const identity: configs.IClientIdentity = { ... };
//        const client = new ConnectorClient(identity);
// ---------------------------------------------------------------------------
