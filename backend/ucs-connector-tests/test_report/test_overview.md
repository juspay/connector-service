# UCS Connector Test Report

> Generated: epoch 1773330215

## Scenario Performance Matrix

<details open>
<summary><strong>Show/Hide Scenario Performance Matrix</strong></summary>

| Scenario | PM | PMT | Connectors Tested | Passed | Failed | Pass Rate |
|:---------|:--:|:---:|------------------:|------:|------:|---------:|
| [`create_access_token`](./scenarios/create-access-token/create-access-token.md) | - | - | 1 | 1 | 0 | 100.0% |
| [`create_customer`](./scenarios/create-customer/create-customer.md) | - | - | 2 | 2 | 0 | 100.0% |
| [`no3ds_auto_capture_credit_card`](./scenarios/authorize/no3ds-auto-capture-credit-card.md) | card | credit | 3 | 3 | 0 | 100.0% |
| [`no3ds_auto_capture_debit_card`](./scenarios/authorize/no3ds-auto-capture-debit-card.md) | card | debit | 3 | 3 | 0 | 100.0% |
| [`no3ds_fail_payment`](./scenarios/authorize/no3ds-fail-payment.md) | card | credit | 3 | 1 | 2 | 33.3% |
| [`no3ds_manual_capture_credit_card`](./scenarios/authorize/no3ds-manual-capture-credit-card.md) | card | credit | 3 | 3 | 0 | 100.0% |
| [`no3ds_manual_capture_debit_card`](./scenarios/authorize/no3ds-manual-capture-debit-card.md) | card | debit | 3 | 3 | 0 | 100.0% |
| [`capture_full_amount`](./scenarios/capture/capture-full-amount.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`capture_partial_amount`](./scenarios/capture/capture-partial-amount.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`capture_with_merchant_order_id`](./scenarios/capture/capture-with-merchant-order-id.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`void_authorized_payment`](./scenarios/void/void-authorized-payment.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`void_with_amount`](./scenarios/void/void-with-amount.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`void_without_cancellation_reason`](./scenarios/void/void-without-cancellation-reason.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`refund_full_amount`](./scenarios/refund/refund-full-amount.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`refund_partial_amount`](./scenarios/refund/refund-partial-amount.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`refund_with_reason`](./scenarios/refund/refund-with-reason.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`sync_payment`](./scenarios/get/sync-payment.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`sync_payment_with_handle_response`](./scenarios/get/sync-payment-with-handle-response.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`refund_sync`](./scenarios/refund-sync/refund-sync.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`refund_sync_with_reason`](./scenarios/refund-sync/refund-sync-with-reason.md) | - | - | 3 | 3 | 0 | 100.0% |
| [`setup_recurring`](./scenarios/setup-recurring/setup-recurring.md) | card | credit | 3 | 3 | 0 | 100.0% |
| [`setup_recurring_with_order_context`](./scenarios/setup-recurring/setup-recurring-with-order-context.md) | card | credit | 3 | 3 | 0 | 100.0% |
| [`setup_recurring_with_webhook`](./scenarios/setup-recurring/setup-recurring-with-webhook.md) | card | credit | 3 | 3 | 0 | 100.0% |
| [`recurring_charge`](./scenarios/recurring-charge/recurring-charge.md) | - | - | 3 | 0 | 3 | 0.0% |
| [`recurring_charge_low_amount`](./scenarios/recurring-charge/recurring-charge-low-amount.md) | - | - | 3 | 0 | 3 | 0.0% |
| [`recurring_charge_with_order_context`](./scenarios/recurring-charge/recurring-charge-with-order-context.md) | - | - | 3 | 0 | 3 | 0.0% |

</details>

---

## Test Matrix

<details open>
<summary><strong>Show/Hide Test Matrix</strong></summary>

| Scenario | PM | PMT | authorizedotnet | paypal | stripe |
|:---------|:--:|:---:|:------:|:------:|:------:|
| [`create_access_token`](./scenarios/create-access-token/create-access-token.md) | - | - | - | [PASS](./scenarios/create-access-token/create-access-token.md#connector-paypal) | - |
| [`create_customer`](./scenarios/create-customer/create-customer.md) | - | - | [PASS](./scenarios/create-customer/create-customer.md#connector-authorizedotnet) | - | [PASS](./scenarios/create-customer/create-customer.md#connector-stripe) |
| [`no3ds_auto_capture_credit_card`](./scenarios/authorize/no3ds-auto-capture-credit-card.md) | card | credit | [PASS](./scenarios/authorize/no3ds-auto-capture-credit-card.md#connector-authorizedotnet) | [PASS](./scenarios/authorize/no3ds-auto-capture-credit-card.md#connector-paypal) | [PASS](./scenarios/authorize/no3ds-auto-capture-credit-card.md#connector-stripe) |
| [`no3ds_auto_capture_debit_card`](./scenarios/authorize/no3ds-auto-capture-debit-card.md) | card | debit | [PASS](./scenarios/authorize/no3ds-auto-capture-debit-card.md#connector-authorizedotnet) | [PASS](./scenarios/authorize/no3ds-auto-capture-debit-card.md#connector-paypal) | [PASS](./scenarios/authorize/no3ds-auto-capture-debit-card.md#connector-stripe) |
| [`no3ds_fail_payment`](./scenarios/authorize/no3ds-fail-payment.md) | card | credit | [FAIL](./scenarios/authorize/no3ds-fail-payment.md#connector-authorizedotnet) | [FAIL](./scenarios/authorize/no3ds-fail-payment.md#connector-paypal) | [PASS](./scenarios/authorize/no3ds-fail-payment.md#connector-stripe) |
| [`no3ds_manual_capture_credit_card`](./scenarios/authorize/no3ds-manual-capture-credit-card.md) | card | credit | [PASS](./scenarios/authorize/no3ds-manual-capture-credit-card.md#connector-authorizedotnet) | [PASS](./scenarios/authorize/no3ds-manual-capture-credit-card.md#connector-paypal) | [PASS](./scenarios/authorize/no3ds-manual-capture-credit-card.md#connector-stripe) |
| [`no3ds_manual_capture_debit_card`](./scenarios/authorize/no3ds-manual-capture-debit-card.md) | card | debit | [PASS](./scenarios/authorize/no3ds-manual-capture-debit-card.md#connector-authorizedotnet) | [PASS](./scenarios/authorize/no3ds-manual-capture-debit-card.md#connector-paypal) | [PASS](./scenarios/authorize/no3ds-manual-capture-debit-card.md#connector-stripe) |
| [`capture_full_amount`](./scenarios/capture/capture-full-amount.md) | - | - | [PASS](./scenarios/capture/capture-full-amount.md#connector-authorizedotnet) | [PASS](./scenarios/capture/capture-full-amount.md#connector-paypal) | [PASS](./scenarios/capture/capture-full-amount.md#connector-stripe) |
| [`capture_partial_amount`](./scenarios/capture/capture-partial-amount.md) | - | - | [PASS](./scenarios/capture/capture-partial-amount.md#connector-authorizedotnet) | [PASS](./scenarios/capture/capture-partial-amount.md#connector-paypal) | [PASS](./scenarios/capture/capture-partial-amount.md#connector-stripe) |
| [`capture_with_merchant_order_id`](./scenarios/capture/capture-with-merchant-order-id.md) | - | - | [PASS](./scenarios/capture/capture-with-merchant-order-id.md#connector-authorizedotnet) | [PASS](./scenarios/capture/capture-with-merchant-order-id.md#connector-paypal) | [PASS](./scenarios/capture/capture-with-merchant-order-id.md#connector-stripe) |
| [`void_authorized_payment`](./scenarios/void/void-authorized-payment.md) | - | - | [PASS](./scenarios/void/void-authorized-payment.md#connector-authorizedotnet) | [PASS](./scenarios/void/void-authorized-payment.md#connector-paypal) | [PASS](./scenarios/void/void-authorized-payment.md#connector-stripe) |
| [`void_with_amount`](./scenarios/void/void-with-amount.md) | - | - | [PASS](./scenarios/void/void-with-amount.md#connector-authorizedotnet) | [PASS](./scenarios/void/void-with-amount.md#connector-paypal) | [PASS](./scenarios/void/void-with-amount.md#connector-stripe) |
| [`void_without_cancellation_reason`](./scenarios/void/void-without-cancellation-reason.md) | - | - | [PASS](./scenarios/void/void-without-cancellation-reason.md#connector-authorizedotnet) | [PASS](./scenarios/void/void-without-cancellation-reason.md#connector-paypal) | [PASS](./scenarios/void/void-without-cancellation-reason.md#connector-stripe) |
| [`refund_full_amount`](./scenarios/refund/refund-full-amount.md) | - | - | [PASS](./scenarios/refund/refund-full-amount.md#connector-authorizedotnet) | [PASS](./scenarios/refund/refund-full-amount.md#connector-paypal) | [PASS](./scenarios/refund/refund-full-amount.md#connector-stripe) |
| [`refund_partial_amount`](./scenarios/refund/refund-partial-amount.md) | - | - | [PASS](./scenarios/refund/refund-partial-amount.md#connector-authorizedotnet) | [PASS](./scenarios/refund/refund-partial-amount.md#connector-paypal) | [PASS](./scenarios/refund/refund-partial-amount.md#connector-stripe) |
| [`refund_with_reason`](./scenarios/refund/refund-with-reason.md) | - | - | [PASS](./scenarios/refund/refund-with-reason.md#connector-authorizedotnet) | [PASS](./scenarios/refund/refund-with-reason.md#connector-paypal) | [PASS](./scenarios/refund/refund-with-reason.md#connector-stripe) |
| [`sync_payment`](./scenarios/get/sync-payment.md) | - | - | [PASS](./scenarios/get/sync-payment.md#connector-authorizedotnet) | [PASS](./scenarios/get/sync-payment.md#connector-paypal) | [PASS](./scenarios/get/sync-payment.md#connector-stripe) |
| [`sync_payment_with_handle_response`](./scenarios/get/sync-payment-with-handle-response.md) | - | - | [PASS](./scenarios/get/sync-payment-with-handle-response.md#connector-authorizedotnet) | [PASS](./scenarios/get/sync-payment-with-handle-response.md#connector-paypal) | [PASS](./scenarios/get/sync-payment-with-handle-response.md#connector-stripe) |
| [`refund_sync`](./scenarios/refund-sync/refund-sync.md) | - | - | [PASS](./scenarios/refund-sync/refund-sync.md#connector-authorizedotnet) | [PASS](./scenarios/refund-sync/refund-sync.md#connector-paypal) | [PASS](./scenarios/refund-sync/refund-sync.md#connector-stripe) |
| [`refund_sync_with_reason`](./scenarios/refund-sync/refund-sync-with-reason.md) | - | - | [PASS](./scenarios/refund-sync/refund-sync-with-reason.md#connector-authorizedotnet) | [PASS](./scenarios/refund-sync/refund-sync-with-reason.md#connector-paypal) | [PASS](./scenarios/refund-sync/refund-sync-with-reason.md#connector-stripe) |
| [`setup_recurring`](./scenarios/setup-recurring/setup-recurring.md) | card | credit | [PASS](./scenarios/setup-recurring/setup-recurring.md#connector-authorizedotnet) | [PASS](./scenarios/setup-recurring/setup-recurring.md#connector-paypal) | [PASS](./scenarios/setup-recurring/setup-recurring.md#connector-stripe) |
| [`setup_recurring_with_order_context`](./scenarios/setup-recurring/setup-recurring-with-order-context.md) | card | credit | [PASS](./scenarios/setup-recurring/setup-recurring-with-order-context.md#connector-authorizedotnet) | [PASS](./scenarios/setup-recurring/setup-recurring-with-order-context.md#connector-paypal) | [PASS](./scenarios/setup-recurring/setup-recurring-with-order-context.md#connector-stripe) |
| [`setup_recurring_with_webhook`](./scenarios/setup-recurring/setup-recurring-with-webhook.md) | card | credit | [PASS](./scenarios/setup-recurring/setup-recurring-with-webhook.md#connector-authorizedotnet) | [PASS](./scenarios/setup-recurring/setup-recurring-with-webhook.md#connector-paypal) | [PASS](./scenarios/setup-recurring/setup-recurring-with-webhook.md#connector-stripe) |
| [`recurring_charge`](./scenarios/recurring-charge/recurring-charge.md) | - | - | [FAIL](./scenarios/recurring-charge/recurring-charge.md#connector-authorizedotnet) | [FAIL](./scenarios/recurring-charge/recurring-charge.md#connector-paypal) | [FAIL](./scenarios/recurring-charge/recurring-charge.md#connector-stripe) |
| [`recurring_charge_low_amount`](./scenarios/recurring-charge/recurring-charge-low-amount.md) | - | - | [FAIL](./scenarios/recurring-charge/recurring-charge-low-amount.md#connector-authorizedotnet) | [FAIL](./scenarios/recurring-charge/recurring-charge-low-amount.md#connector-paypal) | [FAIL](./scenarios/recurring-charge/recurring-charge-low-amount.md#connector-stripe) |
| [`recurring_charge_with_order_context`](./scenarios/recurring-charge/recurring-charge-with-order-context.md) | - | - | [FAIL](./scenarios/recurring-charge/recurring-charge-with-order-context.md#connector-authorizedotnet) | [FAIL](./scenarios/recurring-charge/recurring-charge-with-order-context.md#connector-paypal) | [FAIL](./scenarios/recurring-charge/recurring-charge-with-order-context.md#connector-stripe) |

</details>
