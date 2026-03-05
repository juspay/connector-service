/**
 * Re-exports for payment method types.
 *
 * Usage:
 *   import payments.PaymentMethod
 *   import payments.CardDetails
 *   import payments.CardNetwork
 *
 * Mirrors the JavaScript `payment_methods` namespace and Python `PaymentMethodsNamespace`.
 */
@file:Suppress("unused")

package payments

typealias PaymentMethod = ucs.v2.PaymentMethods.PaymentMethod
typealias CardDetails = ucs.v2.PaymentMethods.CardDetails
typealias CardNumberType = ucs.v2.PaymentMethods.CardNumberType
typealias NetworkTokenType = ucs.v2.PaymentMethods.NetworkTokenType
typealias CardRedirect = ucs.v2.PaymentMethods.CardRedirect
typealias CardNetwork = ucs.v2.PaymentMethods.CardNetwork
typealias TokenPaymentMethodType = ucs.v2.PaymentMethods.TokenPaymentMethodType
