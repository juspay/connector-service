# UCS Connector Test Report

> Generated: epoch 1773145197

## Summary

| Metric | Count |
|--------|------:|
| Connectors Tested | 1 |
| Total Scenarios | 21 |
| Passed | 12 |
| Failed | 9 |
| Pass Rate | 57.1% |

---

## Scenario Performance Matrix

| Scenario | Suite | Service | PM | PMT | Connectors Tested | Passed | Failed | Pass Rate |
|:---------|:------|:--------|:--:|:---:|------------------:|------:|------:|---------:|
| create_customer | create_customer | CustomerService/Create | - | - | 1 | 1 | 0 | 100.0% |
| no3ds_auto_capture_credit_card | authorize | PaymentService/Authorize | card | credit | 1 | 1 | 0 | 100.0% |
| no3ds_auto_capture_debit_card | authorize | PaymentService/Authorize | card | debit | 1 | 1 | 0 | 100.0% |
| no3ds_fail_payment | authorize | PaymentService/Authorize | card | credit | 1 | 0 | 1 | 0.0% |
| no3ds_manual_capture_credit_card | authorize | PaymentService/Authorize | card | credit | 1 | 1 | 0 | 100.0% |
| no3ds_manual_capture_debit_card | authorize | PaymentService/Authorize | card | debit | 1 | 1 | 0 | 100.0% |
| capture_full_amount | capture | PaymentService/Capture | - | - | 1 | 1 | 0 | 100.0% |
| capture_partial_amount | capture | PaymentService/Capture | - | - | 1 | 1 | 0 | 100.0% |
| void_authorized_payment | void | PaymentService/Void | - | - | 1 | 1 | 0 | 100.0% |
| void_without_cancellation_reason | void | PaymentService/Void | - | - | 1 | 1 | 0 | 100.0% |
| refund_full_amount | refund | PaymentService/Refund | - | - | 1 | 0 | 1 | 0.0% |
| refund_partial_amount | refund | PaymentService/Refund | - | - | 1 | 0 | 1 | 0.0% |
| refund_with_reason | refund | PaymentService/Refund | - | - | 1 | 0 | 1 | 0.0% |
| sync_payment | get | PaymentService/Get | - | - | 1 | 1 | 0 | 100.0% |
| sync_payment_with_handle_response | get | PaymentService/Get | - | - | 1 | 1 | 0 | 100.0% |
| refund_sync | refund_sync | RefundService/Get | - | - | 1 | 0 | 1 | 0.0% |
| refund_sync_with_reason | refund_sync | RefundService/Get | - | - | 1 | 0 | 1 | 0.0% |
| setup_recurring | setup_recurring | PaymentService/SetupRecurring | card | credit | 1 | 1 | 0 | 100.0% |
| setup_recurring_with_webhook | setup_recurring | PaymentService/SetupRecurring | card | credit | 1 | 0 | 1 | 0.0% |
| recurring_charge | recurring_charge | RecurringPaymentService/Charge | - | - | 1 | 0 | 1 | 0.0% |
| recurring_charge_low_amount | recurring_charge | RecurringPaymentService/Charge | - | - | 1 | 0 | 1 | 0.0% |

---

## Test Matrix

| Scenario | Suite | Service | PM | PMT | authorizedotnet |
|:---------|:------|:--------|:--:|:---:|:------:|
| create_customer | create_customer | CustomerService/Create | - | - | PASS |
| no3ds_auto_capture_credit_card | authorize | PaymentService/Authorize | card | credit | PASS |
| no3ds_auto_capture_debit_card | authorize | PaymentService/Authorize | card | debit | PASS |
| no3ds_fail_payment | authorize | PaymentService/Authorize | card | credit | FAIL |
| no3ds_manual_capture_credit_card | authorize | PaymentService/Authorize | card | credit | PASS |
| no3ds_manual_capture_debit_card | authorize | PaymentService/Authorize | card | debit | PASS |
| capture_full_amount | capture | PaymentService/Capture | - | - | PASS |
| capture_partial_amount | capture | PaymentService/Capture | - | - | PASS |
| void_authorized_payment | void | PaymentService/Void | - | - | PASS |
| void_without_cancellation_reason | void | PaymentService/Void | - | - | PASS |
| refund_full_amount | refund | PaymentService/Refund | - | - | FAIL |
| refund_partial_amount | refund | PaymentService/Refund | - | - | FAIL |
| refund_with_reason | refund | PaymentService/Refund | - | - | FAIL |
| sync_payment | get | PaymentService/Get | - | - | PASS |
| sync_payment_with_handle_response | get | PaymentService/Get | - | - | PASS |
| refund_sync | refund_sync | RefundService/Get | - | - | FAIL |
| refund_sync_with_reason | refund_sync | RefundService/Get | - | - | FAIL |
| setup_recurring | setup_recurring | PaymentService/SetupRecurring | card | credit | PASS |
| setup_recurring_with_webhook | setup_recurring | PaymentService/SetupRecurring | card | credit | FAIL |
| recurring_charge | recurring_charge | RecurringPaymentService/Charge | - | - | FAIL |
| recurring_charge_low_amount | recurring_charge | RecurringPaymentService/Charge | - | - | FAIL |
