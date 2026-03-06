/**
 * Re-exports for SDK configuration types.
 *
 * Usage:
 *   import payments.FfiOptions
 *   import payments.ClientConfig
 *   import payments.FfiConnectorHttpRequest
 *
 * Mirrors the JavaScript `configs` namespace and Python `ConfigsNamespace`.
 */
@file:Suppress("unused")

package payments

import ucs.v2.SdkConfig

typealias Environment = SdkConfig.Environment
typealias ClientConfig = SdkConfig.ClientConfig
typealias RequestOptions = SdkConfig.RequestOptions
typealias HttpConfig = SdkConfig.HttpConfig
typealias HttpTimeoutConfig = SdkConfig.HttpTimeoutConfig
typealias CaCert = SdkConfig.CaCert
typealias ProxyOptions = SdkConfig.ProxyOptions
typealias FfiOptions = SdkConfig.FfiOptions
typealias FfiConnectorHttpRequest = SdkConfig.FfiConnectorHttpRequest
typealias FfiConnectorHttpResponse = SdkConfig.FfiConnectorHttpResponse
