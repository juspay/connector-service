/**
 * Re-exports for SDK configuration types.
 *
 * Usage:
 *   import payments.FfiOptions
 *   import payments.EnvOptions
 *   import payments.FfiConnectorHttpRequest
 *
 * Mirrors the JavaScript `configs` namespace and Python `ConfigsNamespace`.
 */
@file:Suppress("unused")

package payments

typealias EnvOptions = ucs.v2.SdkOptions.EnvOptions
typealias FfiOptions = ucs.v2.SdkOptions.FfiOptions
typealias Options = ucs.v2.SdkOptions.Options
typealias HttpOptions = ucs.v2.SdkOptions.HttpOptions
typealias ProxyOptions = ucs.v2.SdkOptions.ProxyOptions
typealias FfiConnectorHttpRequest = ucs.v2.SdkOptions.FfiConnectorHttpRequest
typealias FfiConnectorHttpResponse = ucs.v2.SdkOptions.FfiConnectorHttpResponse
