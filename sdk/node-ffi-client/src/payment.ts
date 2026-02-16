/**
 * Type definitions for connector-service-node-ffi
 * 
 * Provides TypeScript interfaces for PaymentServiceAuthorizeRequest,
 * MetadataPayload, and other payment-related types.
 */

/**
 * Payment authorization request
 */
export interface PaymentServiceAuthorizeRequest {
  request_ref_id: {
    id: string;
  };
  amount: number;
  minor_amount: number;
  currency: string;
  payment_method: PaymentMethod;
  capture_method: string;
  email: string;
  customer_name: string;
  auth_type: string;
  enrolled_for_3ds: boolean;
  return_url: string;
  webhook_url: string;
  description: string;
  test_mode: boolean;
  order_details: unknown[];
  address: Address;
}

/**
 * Payment method container
 */
export interface PaymentMethod {
  payment_method: {
    Card: CardPaymentMethod;
  };
}

/**
 * Card payment method details
 */
export interface CardPaymentMethod {
  card_number: string;
  card_exp_month: string;
  card_exp_year: string;
  card_cvc: string;
  card_holder_name: string;
  card_network: number;
}

/**
 * Shipping and billing address
 */
export interface Address {
  shipping_address: unknown;
  billing_address: unknown;
}

/**
 * Metadata payload containing connector and auth information
 */
export interface MetadataPayload {
  connector: string;
  connector_auth_type: {
    auth_type: string;
    api_key: string;
  };
}

/**
 * Authorization response from the FFI
 */
export interface AuthorizeResponse {
  [key: string]: unknown;
}

// Import the native FFI module (CommonJS)
const ffi = require('../index');


/**
 * Access to the underlying native module for advanced use cases
 */
export const _native = ffi._native;
