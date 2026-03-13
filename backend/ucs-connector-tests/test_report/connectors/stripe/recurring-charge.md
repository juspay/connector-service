# Connector `stripe` / Suite `recurring_charge`

- Service: `RecurringPaymentService/Charge`
- Pass Rate: `0.0%` (`0` / `3`)

[Back to Overview](../../test_overview.md)

## Scenario Matrix

| Scenario | PM | PMT | Result | Prerequisites |
|:---------|:--:|:---:|:------:|:--------------|
| [`recurring_charge`](./recurring-charge/recurring-charge.md) | - | - | `FAIL` | `create_customer(create_customer)` (PASS) -> `setup_recurring(setup_recurring)` (PASS) |
| [`recurring_charge_low_amount`](./recurring-charge/recurring-charge-low-amount.md) | - | - | `FAIL` | `create_customer(create_customer)` (PASS) -> `setup_recurring(setup_recurring)` (PASS) |
| [`recurring_charge_with_order_context`](./recurring-charge/recurring-charge-with-order-context.md) | - | - | `FAIL` | `create_customer(create_customer)` (PASS) -> `setup_recurring(setup_recurring)` (PASS) |

## Failed Scenarios

- [`recurring_charge`](./recurring-charge/recurring-charge.md) — assertion failed for field 'connector_transaction_id': expected field to exist
- [`recurring_charge_low_amount`](./recurring-charge/recurring-charge-low-amount.md) — assertion failed for field 'connector_transaction_id': expected field to exist
- [`recurring_charge_with_order_context`](./recurring-charge/recurring-charge-with-order-context.md) — assertion failed for field 'connector_transaction_id': expected field to exist
