/**
 * High-level client for connector-service-ffi
 * 
 * Provides a simplified interface for payment operations by wrapping
 * the low-level FFI bindings with automatic request/response handling.
 */

"use strict";

const fetch = require('node-fetch');

/**
 * ConnectorClient - Simplifies payment operations
 * 
 * @example
 * const metadata = {
 *   connector: 'Stripe',
 *   connector_auth_type: { 
 *     auth_type: "HeaderKey", 
 *     api_key: "sk_test_xxx" 
 *   }
 * };
 * const client = new ConnectorClient(metadata);
 * const result = await client.authorize(payload);
 */
class ConnectorClient {
    /**
     * Create a new ConnectorClient
     * @param {object} metadata - Metadata containing connector and auth info
     * @param {string} metadata.connector - Connector name (e.g., 'Stripe', 'Adyen')
     * @param {object} metadata.connector_auth_type - Authentication configuration
     */
    constructor(metadata) {
        if (!metadata || typeof metadata !== 'object') {
            throw new Error('Metadata must be a non-null object');
        }
        
        this.metadata = metadata;
    }

    /**
     * Authorize a payment
     * @param {object} payload - Complete payment payload matching PaymentServiceAuthorizeRequest structure
     * @returns {Promise<object>} Payment response
     * @throws {Error} If authorization fails
     */
    async authorize(payload) {
        if (!payload || typeof payload !== 'object') {
            throw new Error('Payload must be a non-null object');
        }

        const { authorizeReq, authorizeRes } = require('../index');

        try {
            // Step 1: Build HTTP request using FFI
            const requestJson = authorizeReq(payload, this.metadata);
            const { body, headers, method, url } = JSON.parse(requestJson);

            // Step 2: Execute HTTP request
            const response = await fetch(url, {
                method,
                headers,
                body: body || undefined,
            });

            // Step 3: Collect response data
            const responseText = await response.text();
            const responseHeaders = {};
            response.headers.forEach((value, key) => {
                responseHeaders[key] = value;
            });

            const formattedResponse = {
                status: response.status,
                headers: responseHeaders,
                body: responseText
            };

            // Step 4: Parse response using FFI
            const resultJson = authorizeRes(payload, this.metadata, formattedResponse);
            return JSON.parse(resultJson);

        } catch (error) {
            const enhancedError = new Error(
                `Payment authorization failed: ${error.message}`
            );
            enhancedError.cause = error;
            throw enhancedError;
        }
    }
}

module.exports = { ConnectorClient };