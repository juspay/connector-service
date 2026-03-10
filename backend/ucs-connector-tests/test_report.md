# UCS Connector Test Report

> Generated: epoch 1773149674

## Summary

| Metric | Count |
|--------|------:|
| Connectors Tested | 3 |
| Total Scenarios | 22 |
| Passed | 43 |
| Failed | 11 |
| Pass Rate | 79.6% |

---

## Scenario Performance Matrix

| Scenario | Suite | Service | PM | PMT | Connectors Tested | Passed | Failed | Pass Rate |
|:---------|:------|:--------|:--:|:---:|------------------:|------:|------:|---------:|
| create_access_token | create_access_token | MerchantAuthenticationService/CreateAccessToken | - | - | 1 | 1 | 0 | 100.0% |
| create_customer | create_customer | CustomerService/Create | - | - | 1 | 1 | 0 | 100.0% |
| no3ds_auto_capture_credit_card | authorize | PaymentService/Authorize | card | credit | 3 | 3 | 0 | 100.0% |
| no3ds_auto_capture_debit_card | authorize | PaymentService/Authorize | card | debit | 3 | 3 | 0 | 100.0% |
| no3ds_fail_payment | authorize | PaymentService/Authorize | card | credit | 3 | 0 | 3 | 0.0% |
| no3ds_manual_capture_credit_card | authorize | PaymentService/Authorize | card | credit | 3 | 3 | 0 | 100.0% |
| no3ds_manual_capture_debit_card | authorize | PaymentService/Authorize | card | debit | 3 | 3 | 0 | 100.0% |
| capture_full_amount | capture | PaymentService/Capture | - | - | 3 | 3 | 0 | 100.0% |
| capture_partial_amount | capture | PaymentService/Capture | - | - | 3 | 3 | 0 | 100.0% |
| void_authorized_payment | void | PaymentService/Void | - | - | 3 | 3 | 0 | 100.0% |
| void_without_cancellation_reason | void | PaymentService/Void | - | - | 3 | 3 | 0 | 100.0% |
| refund_full_amount | refund | PaymentService/Refund | - | - | 3 | 2 | 1 | 66.7% |
| refund_partial_amount | refund | PaymentService/Refund | - | - | 3 | 2 | 1 | 66.7% |
| refund_with_reason | refund | PaymentService/Refund | - | - | 3 | 2 | 1 | 66.7% |
| sync_payment | get | PaymentService/Get | - | - | 3 | 3 | 0 | 100.0% |
| sync_payment_with_handle_response | get | PaymentService/Get | - | - | 3 | 3 | 0 | 100.0% |
| refund_sync | refund_sync | RefundService/Get | - | - | 3 | 2 | 1 | 66.7% |
| refund_sync_with_reason | refund_sync | RefundService/Get | - | - | 3 | 2 | 1 | 66.7% |
| setup_recurring | setup_recurring | PaymentService/SetupRecurring | card | credit | 1 | 1 | 0 | 100.0% |
| setup_recurring_with_webhook | setup_recurring | PaymentService/SetupRecurring | card | credit | 1 | 0 | 1 | 0.0% |
| recurring_charge | recurring_charge | RecurringPaymentService/Charge | - | - | 1 | 0 | 1 | 0.0% |
| recurring_charge_low_amount | recurring_charge | RecurringPaymentService/Charge | - | - | 1 | 0 | 1 | 0.0% |

---

## Test Matrix

| Scenario | Suite | Service | PM | PMT | authorizedotnet | paypal | stripe |
|:---------|:------|:--------|:--:|:---:|:------:|:------:|:------:|
| create_access_token | create_access_token | MerchantAuthenticationService/CreateAccessToken | - | - | - | PASS | - |
| create_customer | create_customer | CustomerService/Create | - | - | PASS | - | - |
| no3ds_auto_capture_credit_card | authorize | PaymentService/Authorize | card | credit | PASS | PASS | PASS |
| no3ds_auto_capture_debit_card | authorize | PaymentService/Authorize | card | debit | PASS | PASS | PASS |
| no3ds_fail_payment | authorize | PaymentService/Authorize | card | credit | FAIL | FAIL | FAIL |
| no3ds_manual_capture_credit_card | authorize | PaymentService/Authorize | card | credit | PASS | PASS | PASS |
| no3ds_manual_capture_debit_card | authorize | PaymentService/Authorize | card | debit | PASS | PASS | PASS |
| capture_full_amount | capture | PaymentService/Capture | - | - | PASS | PASS | PASS |
| capture_partial_amount | capture | PaymentService/Capture | - | - | PASS | PASS | PASS |
| void_authorized_payment | void | PaymentService/Void | - | - | PASS | PASS | PASS |
| void_without_cancellation_reason | void | PaymentService/Void | - | - | PASS | PASS | PASS |
| refund_full_amount | refund | PaymentService/Refund | - | - | FAIL | PASS | PASS |
| refund_partial_amount | refund | PaymentService/Refund | - | - | FAIL | PASS | PASS |
| refund_with_reason | refund | PaymentService/Refund | - | - | FAIL | PASS | PASS |
| sync_payment | get | PaymentService/Get | - | - | PASS | PASS | PASS |
| sync_payment_with_handle_response | get | PaymentService/Get | - | - | PASS | PASS | PASS |
| refund_sync | refund_sync | RefundService/Get | - | - | FAIL | PASS | PASS |
| refund_sync_with_reason | refund_sync | RefundService/Get | - | - | FAIL | PASS | PASS |
| setup_recurring | setup_recurring | PaymentService/SetupRecurring | card | credit | PASS | - | - |
| setup_recurring_with_webhook | setup_recurring | PaymentService/SetupRecurring | card | credit | FAIL | - | - |
| recurring_charge | recurring_charge | RecurringPaymentService/Charge | - | - | FAIL | - | - |
| recurring_charge_low_amount | recurring_charge | RecurringPaymentService/Charge | - | - | FAIL | - | - |
