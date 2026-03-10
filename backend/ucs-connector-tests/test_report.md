# UCS Connector Test Report

> Generated: epoch 1773148432

## Summary

| Metric | Count |
|--------|------:|
| Connectors Tested | 3 |
| Total Scenarios | 22 |
| Passed | 25 |
| Failed | 29 |
| Pass Rate | 46.3% |

---

## Scenario Performance Matrix

| Scenario | Suite | Service | PM | PMT | Connectors Tested | Passed | Failed | Pass Rate |
|:---------|:------|:--------|:--:|:---:|------------------:|------:|------:|---------:|
| create_access_token | create_access_token | MerchantAuthenticationService/CreateAccessToken | - | - | 1 | 0 | 1 | 0.0% |
| create_customer | create_customer | CustomerService/Create | - | - | 1 | 0 | 1 | 0.0% |
| no3ds_auto_capture_credit_card | authorize | PaymentService/Authorize | card | credit | 3 | 2 | 1 | 66.7% |
| no3ds_auto_capture_debit_card | authorize | PaymentService/Authorize | card | debit | 3 | 2 | 1 | 66.7% |
| no3ds_fail_payment | authorize | PaymentService/Authorize | card | credit | 3 | 0 | 3 | 0.0% |
| no3ds_manual_capture_credit_card | authorize | PaymentService/Authorize | card | credit | 3 | 2 | 1 | 66.7% |
| no3ds_manual_capture_debit_card | authorize | PaymentService/Authorize | card | debit | 3 | 2 | 1 | 66.7% |
| capture_full_amount | capture | PaymentService/Capture | - | - | 3 | 2 | 1 | 66.7% |
| capture_partial_amount | capture | PaymentService/Capture | - | - | 3 | 2 | 1 | 66.7% |
| void_authorized_payment | void | PaymentService/Void | - | - | 3 | 2 | 1 | 66.7% |
| void_without_cancellation_reason | void | PaymentService/Void | - | - | 3 | 2 | 1 | 66.7% |
| refund_full_amount | refund | PaymentService/Refund | - | - | 3 | 1 | 2 | 33.3% |
| refund_partial_amount | refund | PaymentService/Refund | - | - | 3 | 1 | 2 | 33.3% |
| refund_with_reason | refund | PaymentService/Refund | - | - | 3 | 1 | 2 | 33.3% |
| sync_payment | get | PaymentService/Get | - | - | 3 | 2 | 1 | 66.7% |
| sync_payment_with_handle_response | get | PaymentService/Get | - | - | 3 | 2 | 1 | 66.7% |
| refund_sync | refund_sync | RefundService/Get | - | - | 3 | 1 | 2 | 33.3% |
| refund_sync_with_reason | refund_sync | RefundService/Get | - | - | 3 | 1 | 2 | 33.3% |
| setup_recurring | setup_recurring | PaymentService/SetupRecurring | card | credit | 1 | 0 | 1 | 0.0% |
| setup_recurring_with_webhook | setup_recurring | PaymentService/SetupRecurring | card | credit | 1 | 0 | 1 | 0.0% |
| recurring_charge | recurring_charge | RecurringPaymentService/Charge | - | - | 1 | 0 | 1 | 0.0% |
| recurring_charge_low_amount | recurring_charge | RecurringPaymentService/Charge | - | - | 1 | 0 | 1 | 0.0% |

---

## Test Matrix

| Scenario | Suite | Service | PM | PMT | authorizedotnet | paypal | stripe |
|:---------|:------|:--------|:--:|:---:|:------:|:------:|:------:|
| create_access_token | create_access_token | MerchantAuthenticationService/CreateAccessToken | - | - | - | FAIL | - |
| create_customer | create_customer | CustomerService/Create | - | - | FAIL | - | - |
| no3ds_auto_capture_credit_card | authorize | PaymentService/Authorize | card | credit | PASS | FAIL | PASS |
| no3ds_auto_capture_debit_card | authorize | PaymentService/Authorize | card | debit | PASS | FAIL | PASS |
| no3ds_fail_payment | authorize | PaymentService/Authorize | card | credit | FAIL | FAIL | FAIL |
| no3ds_manual_capture_credit_card | authorize | PaymentService/Authorize | card | credit | PASS | FAIL | PASS |
| no3ds_manual_capture_debit_card | authorize | PaymentService/Authorize | card | debit | PASS | FAIL | PASS |
| capture_full_amount | capture | PaymentService/Capture | - | - | PASS | FAIL | PASS |
| capture_partial_amount | capture | PaymentService/Capture | - | - | PASS | FAIL | PASS |
| void_authorized_payment | void | PaymentService/Void | - | - | PASS | FAIL | PASS |
| void_without_cancellation_reason | void | PaymentService/Void | - | - | PASS | FAIL | PASS |
| refund_full_amount | refund | PaymentService/Refund | - | - | FAIL | FAIL | PASS |
| refund_partial_amount | refund | PaymentService/Refund | - | - | FAIL | FAIL | PASS |
| refund_with_reason | refund | PaymentService/Refund | - | - | FAIL | FAIL | PASS |
| sync_payment | get | PaymentService/Get | - | - | PASS | FAIL | PASS |
| sync_payment_with_handle_response | get | PaymentService/Get | - | - | PASS | FAIL | PASS |
| refund_sync | refund_sync | RefundService/Get | - | - | FAIL | FAIL | PASS |
| refund_sync_with_reason | refund_sync | RefundService/Get | - | - | FAIL | FAIL | PASS |
| setup_recurring | setup_recurring | PaymentService/SetupRecurring | card | credit | FAIL | - | - |
| setup_recurring_with_webhook | setup_recurring | PaymentService/SetupRecurring | card | credit | FAIL | - | - |
| recurring_charge | recurring_charge | RecurringPaymentService/Charge | - | - | FAIL | - | - |
| recurring_charge_low_amount | recurring_charge | RecurringPaymentService/Charge | - | - | FAIL | - | - |
