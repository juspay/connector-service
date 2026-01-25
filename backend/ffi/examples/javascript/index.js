/**
 * Connector Service FFI - JavaScript/Node.js Bindings
 *
 * This module provides JavaScript bindings for the connector-service FFI library.
 * It allows you to transform payment requests to connector-specific HTTP requests
 * and transform connector responses back to standardized payment responses.
 *
 * @example
 * const { ConnectorClient, PaymentMethod } = require('@connector-service/ffi');
 *
 * const client = new ConnectorClient('stripe', { api_key: 'sk_test_xxx' });
 *
 * const result = await client.authorize({
 *   amount: 1000,
 *   currency: 'USD',
 *   paymentMethod: PaymentMethod.card({
 *     number: '4242424242424242',
 *     expMonth: 12,
 *     expYear: 2025,
 *     cvc: '123'
 *   })
 * });
 */

'use strict';

const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// Try to load ffi-napi, fall back to pure JS mock if not available
let ffi, ref;
let useNativeFFI = false;

try {
  ffi = require('ffi-napi');
  ref = require('ref-napi');
  useNativeFFI = true;
} catch (e) {
  // ffi-napi not available, will use pure JS implementation
  console.warn('ffi-napi not available, using pure JavaScript implementation');
}

/**
 * Payment status enum
 */
const PaymentStatus = {
  SUCCEEDED: 'succeeded',
  AUTHORIZED: 'authorized',
  PENDING: 'pending',
  FAILED: 'failed',
  CANCELLED: 'cancelled',
  REQUIRES_ACTION: 'requires_action',
  UNKNOWN: 'unknown'
};

/**
 * HTTP methods
 */
const HttpMethod = {
  GET: 'GET',
  POST: 'POST',
  PUT: 'PUT',
  DELETE: 'DELETE',
  PATCH: 'PATCH'
};

/**
 * Payment method factory
 */
const PaymentMethod = {
  /**
   * Create a card payment method
   * @param {Object} params Card parameters
   * @param {string} params.number Card number
   * @param {number} params.expMonth Expiration month
   * @param {number} params.expYear Expiration year
   * @param {string} params.cvc CVC/CVV
   * @param {string} [params.holderName] Cardholder name
   * @returns {Object} Payment method data
   */
  card({ number, expMonth, expYear, cvc, holderName }) {
    const data = {
      type: 'card',
      number,
      exp_month: expMonth,
      exp_year: expYear,
      cvc
    };
    if (holderName) {
      data.holder_name = holderName;
    }
    return data;
  },

  /**
   * Create a wallet payment method
   * @param {string} walletType Wallet type (e.g., 'apple_pay', 'google_pay')
   * @param {string} token Payment token
   * @returns {Object} Payment method data
   */
  wallet(walletType, token) {
    return {
      type: 'wallet',
      wallet_type: walletType,
      token
    };
  },

  /**
   * Create a bank transfer payment method
   * @param {Object} params Bank parameters
   * @param {string} [params.bankCode] Bank code
   * @param {string} [params.accountNumber] Account number
   * @returns {Object} Payment method data
   */
  bankTransfer({ bankCode, accountNumber } = {}) {
    return {
      type: 'banktransfer',
      bank_code: bankCode,
      account_number: accountNumber
    };
  }
};

/**
 * Payment result class
 */
class PaymentResult {
  constructor(data, httpStatusCode = null) {
    this.success = ['succeeded', 'authorized'].includes(data.status);
    this.status = data.status || PaymentStatus.UNKNOWN;
    this.transactionId = data.transaction_id || null;
    this.amount = data.amount || null;
    this.currency = data.currency || null;
    this.errorCode = data.error_code || null;
    this.errorMessage = data.error_message || null;
    this.redirectUrl = data.redirect_url || null;
    this.rawResponse = data.raw_response || null;
    this.httpStatusCode = httpStatusCode;
  }

  static error(code, message) {
    return new PaymentResult({
      status: PaymentStatus.FAILED,
      error_code: code,
      error_message: message
    });
  }
}

/**
 * Connector information
 */
class ConnectorInfo {
  constructor(data) {
    this.name = data.name;
    this.displayName = data.display_name;
    this.baseUrl = data.base_url;
    this.authType = data.auth_type;
    this.authFields = data.auth_fields;
    this.supportedFlows = data.supported_flows;
    this.supportedCurrencies = data.supported_currencies;
    this.bodyFormat = data.body_format;
  }
}

/**
 * Find the FFI library path
 */
function findLibraryPath() {
  const platform = process.platform;
  let libName;

  switch (platform) {
    case 'linux':
      libName = 'libconnector_ffi.so';
      break;
    case 'darwin':
      libName = 'libconnector_ffi.dylib';
      break;
    case 'win32':
      libName = 'connector_ffi.dll';
      break;
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }

  const searchPaths = [
    path.join(__dirname, libName),
    path.join(__dirname, '..', '..', 'target', 'release', libName),
    path.join(__dirname, '..', '..', '..', '..', 'target', 'release', libName),
    path.join(process.cwd(), libName),
    path.join(process.cwd(), 'target', 'release', libName)
  ];

  const fs = require('fs');
  for (const searchPath of searchPaths) {
    if (fs.existsSync(searchPath)) {
      return searchPath;
    }
  }

  throw new Error(
    `Could not find ${libName}. Build with 'cargo build --release -p connector-ffi'`
  );
}

/**
 * Native FFI library wrapper
 */
class NativeFFI {
  constructor(libraryPath = null) {
    if (!useNativeFFI) {
      throw new Error('ffi-napi is not available. Install with: npm install ffi-napi ref-napi');
    }

    const libPath = libraryPath || findLibraryPath();

    this.lib = ffi.Library(libPath, {
      'connector_transform_request_json': ['string', ['string']],
      'connector_transform_response_json': ['string', ['string']],
      'connector_list_supported': ['string', []],
      'connector_list_flows': ['string', []],
      'connector_get_info': ['string', ['string']],
      'connector_ffi_version': ['string', []]
    });
  }

  transformRequest(request) {
    const result = this.lib.connector_transform_request_json(JSON.stringify(request));
    return JSON.parse(result);
  }

  transformResponse(response) {
    const result = this.lib.connector_transform_response_json(JSON.stringify(response));
    return JSON.parse(result);
  }

  listConnectors() {
    const result = this.lib.connector_list_supported();
    return JSON.parse(result);
  }

  listFlows() {
    const result = this.lib.connector_list_flows();
    return JSON.parse(result);
  }

  getConnectorInfo(connector) {
    const result = this.lib.connector_get_info(connector);
    return JSON.parse(result);
  }

  version() {
    return this.lib.connector_ffi_version();
  }
}

/**
 * Pure JavaScript FFI implementation (fallback when native FFI not available)
 * This implements the same transformations as the Rust code.
 */
class PureJSFFI {
  constructor() {
    this.connectors = {
      stripe: {
        name: 'stripe',
        display_name: 'Stripe',
        base_url: 'https://api.stripe.com/v1',
        auth_type: 'header_key',
        auth_fields: ['api_key'],
        supported_flows: ['authorize', 'capture', 'void', 'refund', 'sync'],
        supported_currencies: ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD'],
        body_format: 'form'
      },
      adyen: {
        name: 'adyen',
        display_name: 'Adyen',
        base_url: 'https://checkout-test.adyen.com/v71',
        auth_type: 'header_key',
        auth_fields: ['api_key', 'merchant_id'],
        supported_flows: ['authorize', 'capture', 'void', 'refund', 'sync'],
        supported_currencies: ['USD', 'EUR', 'GBP', 'JPY', 'SEK', 'NOK', 'DKK'],
        body_format: 'json'
      },
      forte: {
        name: 'forte',
        display_name: 'Forte',
        base_url: 'https://sandbox.forte.net/api/v3',
        auth_type: 'basic_auth',
        auth_fields: ['api_key', 'api_secret', 'organization_id', 'location_id'],
        supported_flows: ['authorize', 'capture', 'void', 'refund', 'sync'],
        supported_currencies: ['USD'],
        body_format: 'json'
      },
      checkout: {
        name: 'checkout',
        display_name: 'Checkout.com',
        base_url: 'https://api.sandbox.checkout.com',
        auth_type: 'header_key',
        auth_fields: ['api_key'],
        supported_flows: ['authorize', 'capture', 'void', 'refund', 'sync'],
        supported_currencies: ['USD', 'EUR', 'GBP'],
        body_format: 'json'
      }
    };
  }

  transformRequest(request) {
    const { connector, flow, auth, payment, config } = request;
    const connectorInfo = this.connectors[connector.toLowerCase()];

    if (!connectorInfo) {
      return {
        success: false,
        error: { code: 'UNKNOWN_CONNECTOR', message: `Unknown connector: ${connector}` }
      };
    }

    const baseUrl = config?.base_url || connectorInfo.base_url;

    try {
      switch (connector.toLowerCase()) {
        case 'stripe':
          return this._transformStripeRequest(baseUrl, flow, auth, payment);
        case 'adyen':
          return this._transformAdyenRequest(baseUrl, flow, auth, payment);
        default:
          return this._transformGenericRequest(baseUrl, flow, auth, payment);
      }
    } catch (e) {
      return {
        success: false,
        error: { code: 'TRANSFORM_ERROR', message: e.message }
      };
    }
  }

  _transformStripeRequest(baseUrl, flow, auth, payment) {
    if (!auth.api_key) {
      return {
        success: false,
        error: { code: 'MISSING_API_KEY', message: 'Stripe requires api_key' }
      };
    }

    const headers = {
      'Authorization': `Bearer ${auth.api_key}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    };

    let url, method, body;

    switch (flow.toLowerCase()) {
      case 'authorize': {
        url = `${baseUrl}/payment_intents`;
        method = 'POST';
        const params = [
          `amount=${payment.amount}`,
          `currency=${payment.currency.toLowerCase()}`
        ];
        if (payment.payment_method?.type === 'card') {
          params.push('payment_method_data[type]=card');
          params.push(`payment_method_data[card][number]=${payment.payment_method.number}`);
          params.push(`payment_method_data[card][exp_month]=${payment.payment_method.exp_month}`);
          params.push(`payment_method_data[card][exp_year]=${payment.payment_method.exp_year}`);
          params.push(`payment_method_data[card][cvc]=${payment.payment_method.cvc}`);
        }
        params.push('confirm=true');
        body = params.join('&');
        break;
      }
      case 'capture': {
        const txnId = payment.transaction_id || 'pi_unknown';
        url = `${baseUrl}/payment_intents/${txnId}/capture`;
        method = 'POST';
        body = `amount_to_capture=${payment.amount}`;
        break;
      }
      case 'void': {
        const txnId = payment.transaction_id || 'pi_unknown';
        url = `${baseUrl}/payment_intents/${txnId}/cancel`;
        method = 'POST';
        body = null;
        break;
      }
      case 'refund': {
        url = `${baseUrl}/refunds`;
        method = 'POST';
        const txnId = payment.transaction_id || 'pi_unknown';
        body = `payment_intent=${txnId}&amount=${payment.amount}`;
        break;
      }
      case 'sync': {
        const txnId = payment.transaction_id || 'pi_unknown';
        url = `${baseUrl}/payment_intents/${txnId}`;
        method = 'GET';
        body = null;
        break;
      }
      default:
        return {
          success: false,
          error: { code: 'UNKNOWN_FLOW', message: `Unknown flow: ${flow}` }
        };
    }

    return {
      success: true,
      data: { url, method, headers, body, body_type: 'form' }
    };
  }

  _transformAdyenRequest(baseUrl, flow, auth, payment) {
    if (!auth.api_key) {
      return {
        success: false,
        error: { code: 'MISSING_API_KEY', message: 'Adyen requires api_key' }
      };
    }

    const merchantAccount = auth.merchant_id || 'TestMerchant';
    const headers = {
      'X-API-Key': auth.api_key,
      'Content-Type': 'application/json'
    };

    let url, method, body;

    switch (flow.toLowerCase()) {
      case 'authorize': {
        url = `${baseUrl}/payments`;
        method = 'POST';
        const request = {
          merchantAccount,
          amount: {
            value: payment.amount,
            currency: payment.currency.toUpperCase()
          },
          reference: payment.reference_id || 'ref_001'
        };
        if (payment.payment_method?.type === 'card') {
          request.paymentMethod = {
            type: 'scheme',
            number: payment.payment_method.number,
            expiryMonth: String(payment.payment_method.exp_month).padStart(2, '0'),
            expiryYear: String(payment.payment_method.exp_year),
            cvc: payment.payment_method.cvc,
            holderName: payment.payment_method.holder_name || 'Card Holder'
          };
        }
        body = JSON.stringify(request);
        break;
      }
      case 'capture': {
        const txnId = payment.transaction_id || 'unknown';
        url = `${baseUrl}/payments/${txnId}/captures`;
        method = 'POST';
        body = JSON.stringify({
          merchantAccount,
          amount: {
            value: payment.amount,
            currency: payment.currency.toUpperCase()
          }
        });
        break;
      }
      case 'void': {
        const txnId = payment.transaction_id || 'unknown';
        url = `${baseUrl}/payments/${txnId}/cancels`;
        method = 'POST';
        body = JSON.stringify({ merchantAccount });
        break;
      }
      case 'refund': {
        const txnId = payment.transaction_id || 'unknown';
        url = `${baseUrl}/payments/${txnId}/refunds`;
        method = 'POST';
        body = JSON.stringify({
          merchantAccount,
          amount: {
            value: payment.amount,
            currency: payment.currency.toUpperCase()
          }
        });
        break;
      }
      case 'sync': {
        const txnId = payment.transaction_id || 'unknown';
        url = `${baseUrl}/payments/${txnId}`;
        method = 'GET';
        body = null;
        break;
      }
      default:
        return {
          success: false,
          error: { code: 'UNKNOWN_FLOW', message: `Unknown flow: ${flow}` }
        };
    }

    return {
      success: true,
      data: { url, method, headers, body, body_type: 'json' }
    };
  }

  _transformGenericRequest(baseUrl, flow, auth, payment) {
    const headers = {
      'Content-Type': 'application/json'
    };
    if (auth.api_key) {
      headers['Authorization'] = `Bearer ${auth.api_key}`;
    }

    let url, method, body;

    switch (flow.toLowerCase()) {
      case 'authorize':
        url = `${baseUrl}/payments`;
        method = 'POST';
        body = JSON.stringify({
          amount: payment.amount,
          currency: payment.currency,
          reference: payment.reference_id
        });
        break;
      case 'capture':
        url = `${baseUrl}/payments/${payment.transaction_id}/capture`;
        method = 'POST';
        body = JSON.stringify({ amount: payment.amount });
        break;
      case 'void':
        url = `${baseUrl}/payments/${payment.transaction_id}/cancel`;
        method = 'POST';
        body = null;
        break;
      case 'refund':
        url = `${baseUrl}/payments/${payment.transaction_id}/refund`;
        method = 'POST';
        body = JSON.stringify({ amount: payment.amount });
        break;
      case 'sync':
        url = `${baseUrl}/payments/${payment.transaction_id}`;
        method = 'GET';
        body = null;
        break;
      default:
        return {
          success: false,
          error: { code: 'UNKNOWN_FLOW', message: `Unknown flow: ${flow}` }
        };
    }

    return {
      success: true,
      data: { url, method, headers, body, body_type: 'json' }
    };
  }

  transformResponse(response) {
    const { connector, status_code, body } = response;

    try {
      const raw = JSON.parse(body);

      switch (connector.toLowerCase()) {
        case 'stripe':
          return this._transformStripeResponse(status_code, raw);
        case 'adyen':
          return this._transformAdyenResponse(status_code, raw);
        default:
          return this._transformGenericResponse(status_code, raw);
      }
    } catch (e) {
      return {
        success: false,
        error: { code: 'PARSE_ERROR', message: `Failed to parse response: ${e.message}` }
      };
    }
  }

  _transformStripeResponse(statusCode, raw) {
    if (statusCode >= 400) {
      return {
        success: true,
        data: {
          status: 'failed',
          error_code: raw.error?.code || 'unknown',
          error_message: raw.error?.message || 'Unknown error',
          raw_response: raw
        }
      };
    }

    const statusMap = {
      'succeeded': 'succeeded',
      'requires_capture': 'authorized',
      'requires_action': 'requires_action',
      'canceled': 'cancelled',
      'processing': 'pending'
    };

    return {
      success: true,
      data: {
        status: statusMap[raw.status] || 'unknown',
        transaction_id: raw.id,
        amount: raw.amount,
        currency: raw.currency?.toUpperCase(),
        raw_response: raw
      }
    };
  }

  _transformAdyenResponse(statusCode, raw) {
    if (statusCode >= 400) {
      return {
        success: true,
        data: {
          status: 'failed',
          error_code: raw.errorCode || 'unknown',
          error_message: raw.message || 'Unknown error',
          raw_response: raw
        }
      };
    }

    const statusMap = {
      'Authorised': 'succeeded',
      'Pending': 'pending',
      'Received': 'pending',
      'Cancelled': 'cancelled',
      'Refused': 'failed',
      'Error': 'failed',
      'RedirectShopper': 'requires_action'
    };

    return {
      success: true,
      data: {
        status: statusMap[raw.resultCode] || 'unknown',
        transaction_id: raw.pspReference,
        amount: raw.amount?.value,
        currency: raw.amount?.currency,
        error_code: raw.refusalReasonCode,
        error_message: raw.refusalReason,
        raw_response: raw
      }
    };
  }

  _transformGenericResponse(statusCode, raw) {
    const status = statusCode >= 400 ? 'failed' : statusCode === 202 ? 'pending' : 'succeeded';

    return {
      success: true,
      data: {
        status,
        transaction_id: raw.id || raw.transaction_id,
        amount: raw.amount,
        currency: raw.currency,
        error_code: raw.error?.code,
        error_message: raw.error?.message,
        raw_response: raw
      }
    };
  }

  listConnectors() {
    return Object.keys(this.connectors);
  }

  listFlows() {
    return ['authorize', 'capture', 'void', 'refund', 'sync'];
  }

  getConnectorInfo(connector) {
    const info = this.connectors[connector.toLowerCase()];
    if (info) {
      return { success: true, data: info };
    }
    return {
      success: false,
      error: { code: 'UNKNOWN_CONNECTOR', message: `Unknown connector: ${connector}` }
    };
  }

  version() {
    return '0.1.0-js';
  }
}

/**
 * Get FFI instance (native if available, pure JS fallback)
 */
function getFFI(libraryPath = null) {
  if (useNativeFFI) {
    try {
      return new NativeFFI(libraryPath);
    } catch (e) {
      console.warn(`Failed to load native FFI: ${e.message}, using pure JS implementation`);
      return new PureJSFFI();
    }
  }
  return new PureJSFFI();
}

/**
 * HTTP client for making requests
 */
class HttpClient {
  constructor(options = {}) {
    this.timeout = options.timeout || 30000;
    this.rejectUnauthorized = options.rejectUnauthorized !== false;
  }

  request(method, url, headers, body) {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const lib = isHttps ? https : http;

      const options = {
        method: method.toUpperCase(),
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        headers,
        timeout: this.timeout,
        rejectUnauthorized: this.rejectUnauthorized
      };

      const req = lib.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: data
          });
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (body) {
        req.write(body);
      }
      req.end();
    });
  }
}

/**
 * High-level connector client
 */
class ConnectorClient {
  /**
   * Create a connector client
   * @param {string} connector Connector name (e.g., 'stripe', 'adyen')
   * @param {Object} auth Authentication credentials
   * @param {Object} [options] Options
   * @param {Object} [options.config] Connector configuration
   * @param {HttpClient} [options.httpClient] Custom HTTP client
   * @param {string} [options.libraryPath] Path to FFI library
   */
  constructor(connector, auth, options = {}) {
    this.connector = connector;
    this.auth = auth;
    this.config = options.config || null;
    this.http = options.httpClient || new HttpClient();
    this._ffi = getFFI(options.libraryPath);

    // Validate connector
    const infoResult = this._ffi.getConnectorInfo(connector);
    if (!infoResult.success) {
      throw new Error(`Unknown connector: ${connector}`);
    }
    this._info = new ConnectorInfo(infoResult.data);
  }

  /**
   * Get connector information
   * @returns {ConnectorInfo}
   */
  get info() {
    return this._info;
  }

  /**
   * Execute a payment flow
   * @private
   */
  async _executeFlow(flow, payment) {
    // Step 1: Transform request
    const transformInput = {
      connector: this.connector,
      flow,
      auth: this.auth,
      payment
    };
    if (this.config) {
      transformInput.config = this.config;
    }

    const requestResult = this._ffi.transformRequest(transformInput);

    if (!requestResult.success) {
      return PaymentResult.error(
        requestResult.error?.code || 'TRANSFORM_ERROR',
        requestResult.error?.message || 'Request transformation failed'
      );
    }

    const httpRequest = requestResult.data;

    // Step 2: Execute HTTP request
    let response;
    try {
      response = await this.http.request(
        httpRequest.method,
        httpRequest.url,
        httpRequest.headers,
        httpRequest.body
      );
    } catch (e) {
      return PaymentResult.error('HTTP_ERROR', e.message);
    }

    // Step 3: Transform response
    const responseInput = {
      connector: this.connector,
      flow,
      status_code: response.statusCode,
      body: response.body
    };

    const responseResult = this._ffi.transformResponse(responseInput);

    if (!responseResult.success) {
      return PaymentResult.error(
        responseResult.error?.code || 'TRANSFORM_ERROR',
        responseResult.error?.message || 'Response transformation failed'
      );
    }

    return new PaymentResult(responseResult.data, response.statusCode);
  }

  /**
   * Authorize a payment
   * @param {Object} params Payment parameters
   * @param {number} params.amount Amount in minor units (cents)
   * @param {string} params.currency 3-letter currency code
   * @param {Object} [params.paymentMethod] Payment method data
   * @param {string} [params.referenceId] Reference ID
   * @param {Object} [params.metadata] Additional metadata
   * @returns {Promise<PaymentResult>}
   */
  async authorize({ amount, currency, paymentMethod, referenceId, metadata }) {
    const payment = { amount, currency };
    if (paymentMethod) payment.payment_method = paymentMethod;
    if (referenceId) payment.reference_id = referenceId;
    if (metadata) payment.metadata = metadata;

    return this._executeFlow('authorize', payment);
  }

  /**
   * Capture a previously authorized payment
   * @param {Object} params Capture parameters
   * @param {string} params.transactionId Original transaction ID
   * @param {number} [params.amount] Amount to capture
   * @param {string} [params.currency] Currency code
   * @returns {Promise<PaymentResult>}
   */
  async capture({ transactionId, amount, currency = 'USD' }) {
    const payment = {
      transaction_id: transactionId,
      amount: amount || 0,
      currency
    };

    return this._executeFlow('capture', payment);
  }

  /**
   * Void/cancel a payment
   * @param {Object} params Void parameters
   * @param {string} params.transactionId Transaction ID to void
   * @param {string} [params.currency] Currency code
   * @returns {Promise<PaymentResult>}
   */
  async void({ transactionId, currency = 'USD' }) {
    const payment = {
      transaction_id: transactionId,
      amount: 0,
      currency
    };

    return this._executeFlow('void', payment);
  }

  /**
   * Refund a payment
   * @param {Object} params Refund parameters
   * @param {string} params.transactionId Original transaction ID
   * @param {number} params.amount Amount to refund
   * @param {string} [params.currency] Currency code
   * @param {string} [params.reason] Refund reason
   * @returns {Promise<PaymentResult>}
   */
  async refund({ transactionId, amount, currency = 'USD', reason }) {
    const payment = {
      transaction_id: transactionId,
      amount,
      currency
    };
    if (reason) {
      payment.metadata = { refund_reason: reason };
    }

    return this._executeFlow('refund', payment);
  }

  /**
   * Get current status of a payment
   * @param {Object} params Sync parameters
   * @param {string} params.transactionId Transaction ID to check
   * @param {string} [params.currency] Currency code
   * @returns {Promise<PaymentResult>}
   */
  async sync({ transactionId, currency = 'USD' }) {
    const payment = {
      transaction_id: transactionId,
      amount: 0,
      currency
    };

    return this._executeFlow('sync', payment);
  }
}

// Convenience functions
function listConnectors() {
  return getFFI().listConnectors();
}

function listFlows() {
  return getFFI().listFlows();
}

function getConnectorInfo(connector) {
  const result = getFFI().getConnectorInfo(connector);
  if (result.success) {
    return new ConnectorInfo(result.data);
  }
  return null;
}

function version() {
  return getFFI().version();
}

// Exports
module.exports = {
  ConnectorClient,
  PaymentMethod,
  PaymentResult,
  PaymentStatus,
  ConnectorInfo,
  HttpClient,
  listConnectors,
  listFlows,
  getConnectorInfo,
  version,
  // Low-level access
  NativeFFI,
  PureJSFFI,
  getFFI
};
