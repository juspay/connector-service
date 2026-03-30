// Auto-generated for payme
package examples.payme

import payments.ConnectorConfig
import payments.Currency
import payments.DirectPaymentClient
import payments.Environment
import payments.Money
import payments.PaymentServiceCaptureRequest
import payments.PaymentServiceCreateOrderRequest
import payments.PaymentServiceGetRequest
import payments.PaymentServiceRefundRequest
import payments.PaymentServiceVoidRequest

fun capture(txnId: String, config: ConnectorConfig): Map<String, Any?> {
    // Flow: PaymentService.capture
    val directPaymentClient = DirectPaymentClient(config)

    val result = directPaymentClient.capture(PaymentServiceCaptureRequest.newBuilder().setMerchantCaptureId("probe_capture_001").setConnectorTransactionId("probe_connector_txn_001").setAmountToCapture(Money.newBuilder().setMinorAmount(1000).setCurrency(Currency.USD).build()).build())
    return mapOf("status" to "ok")
}
fun create_order(txnId: String, config: ConnectorConfig): Map<String, Any?> {
    // Flow: PaymentService.create_order
    val directPaymentClient = DirectPaymentClient(config)

    val result = directPaymentClient.create_order(PaymentServiceCreateOrderRequest.newBuilder().setMerchantOrderId("probe_order_001").setAmount(Money.newBuilder().setMinorAmount(1000).setCurrency(Currency.USD).build()).build())
    return mapOf("status" to "ok")
}
fun get(txnId: String, config: ConnectorConfig): Map<String, Any?> {
    // Flow: PaymentService.get
    val directPaymentClient = DirectPaymentClient(config)

    val result = directPaymentClient.get(PaymentServiceGetRequest.newBuilder().setMerchantTransactionId("probe_merchant_txn_001").setConnectorTransactionId("probe_connector_txn_001").setAmount(Money.newBuilder().setMinorAmount(1000).setCurrency(Currency.USD).build()).build())
    return mapOf("status" to "ok")
}
fun refund(txnId: String, config: ConnectorConfig): Map<String, Any?> {
    // Flow: PaymentService.refund
    val directPaymentClient = DirectPaymentClient(config)

    val result = directPaymentClient.refund(PaymentServiceRefundRequest.newBuilder().setMerchantRefundId("probe_refund_001").setConnectorTransactionId("probe_connector_txn_001").setPaymentAmount(1000).setRefundAmount(Money.newBuilder().setMinorAmount(1000).setCurrency(Currency.USD).build()).setReason("customer_request").build())
    return mapOf("status" to "ok")
}
fun void(txnId: String, config: ConnectorConfig): Map<String, Any?> {
    // Flow: PaymentService.void
    val directPaymentClient = DirectPaymentClient(config)

    val result = directPaymentClient.void(PaymentServiceVoidRequest.newBuilder().setMerchantVoidId("probe_void_001").setConnectorTransactionId("probe_connector_txn_001").setAmount(Money.newBuilder().setMinorAmount(1000).setCurrency(Currency.USD).build()).build())
    return mapOf("status" to "ok")
}