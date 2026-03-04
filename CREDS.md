# Connector Credentials Configuration

This document explains how to configure connector credentials for testing.

## Overview

The smoke tests and other SDK tests require connector credentials to be provided in a JSON file. The credentials file (`creds.json`) contains authentication details for various payment connectors.

## File Structure

- **`creds.json`** - Your actual credentials file (not committed to git)
- **`creds_dummy.json`** - A template/reference file showing the expected structure

## Setting Up Credentials

1. Copy the dummy file to create your own credentials file:
   ```bash
   cp creds_dummy.json creds.json
   ```

2. Replace all `<REPLACE_WITH_YOUR_VALUE>` placeholders with your actual connector credentials.

3. Never commit `creds.json` to version control (it's already in `.gitignore`).

## Supported Connectors

The credentials file supports the following connectors (with their required fields):

### Single-Instance Connectors

These connectors have a single configuration object:

- **aci**: `api_key`, `entity_id`
- **adyen**: `api_key`, `merchant_account`, `review_key` (optional)
- **airwallex**: `api_key`, `client_id`
- **authorizedotnet**: `name`, `transaction_key`
- **bambora**: `merchant_id`, `api_key`
- **bamboraapac**: `username`, `password`, `account_number`
- **bankofamerica**: `api_key`, `merchant_account`, `api_secret`
- **billwerk**: `api_key`, `public_api_key`
- **bluesnap**: `username`, `password`
- **braintree**: `public_key`, `private_key`
- **checkout**: `api_key`, `api_secret`, `processing_channel_id`
- **cybersource**: `api_key`, `merchant_account`, `api_secret`
- **datatrans**: `merchant_id`, `password`
- **deutschebank**: `connector_account_details` object
- **elavon**: `ssl_merchant_id`, `ssl_user_id`, `ssl_pin`
- **fiserv**: `api_key`, `merchant_account`, `api_secret`
- **fiservemea**: `api_key`, `api_secret`
- **fiuu**: `merchant_id`, `verify_key`, `secret_key`
- **forte**: `api_access_id`, `organization_id`, `location_id`, `api_secret_key`
- **getnet**: `api_key`, `api_secret`, `seller_id`
- **globalpay**: `app_id`, `app_key`
- **gigadat**: `campaign_id`, `access_token`, `security_token`
- **helcim**: `api_key`
- **hipay**: `api_key`, `api_secret`
- **hyperpg**: `username`, `password`, `merchant_id`
- **iatapay**: `client_id`, `merchant_id`, `client_secret`
- **itaubank**: `connector_account_details` object
- **jpmorgan**: `client_id`, `client_secret`
- **moneris**: `api_key`, `store_id`
- **multisafepay**: `api_key`
- **nexinets**: `merchant_id`, `api_key`
- **nexixpay**: `api_key`
- **nmi**: `api_key`, `public_key` (optional)
- **noon**: `api_key`, `business_identifier`, `application_identifier`
- **novalnet**: `product_activation_key`, `payment_access_key`, `tariff_id`
- **nuvei**: `merchant_id`, `merchant_site_id`, `merchant_secret`
- **paybox**: `site`, `rank`, `key`, `merchant_id`
- **payload**: `auth_key_map` object
- **paypal**: `client_id`, `client_secret`, `payer_id` (optional)
- **payme**: `seller_payme_id`, `payme_client_key` (optional)
- **paytm**: `merchant_id`, `merchant_key`, `website`, `client_id` (optional)
- **payu**: `api_key`, `api_secret`
- **phonepe**: `merchant_id`, `salt_key`, `salt_index`
- **powertranz**: `power_tranz_id`, `power_tranz_password`
- **rapyd**: `access_key`, `secret_key`
- **redsys**: `merchant_id`, `terminal_id`, `sha256_pwd`
- **shift4**: `api_key`
- **silverflow**: `api_key`, `api_secret`, `merchant_acceptor_key`
- **square**: `connector_account_details` object
- **stax**: `api_key`
- **stripe**: `api_key` (single field)
- **trustpay**: `api_key`, `project_id`, `secret_key`
- **trustpayments**: `username`, `password`, `site_reference`
- **tsys**: `device_id`, `transaction_key`, `developer_id`
- **volt**: `username`, `password`, `client_id`, `client_secret`
- **wellsfargo**: `api_key`, `merchant_account`, `api_secret`
- **wise_payout**: `api_key`
- **worldpay**: `username`, `password`, `entity_id`
- **worldpayvantiv**: `user`, `password`, `merchant_id`
- **worldpayxml**: `api_username`, `api_password`, `merchant_code`
- **xendit**: `api_key`
- **zift**: `user_name`, `password`, `account_id`

### Multi-Instance Connectors

These connectors support multiple merchant accounts as an array:

- **cybersource**: Array of configurations
- **stripe**: Array of configurations (each with `api_key` and optional `metadata`)
- **trustpay**: Array of configurations

## Running Tests

Once your `creds.json` is configured, run the smoke tests:

### Python SDK
```bash
python3 sdk/python/smoke-test/test_smoke.py --all
python3 sdk/python/smoke-test/test_smoke.py --connectors stripe,aci
```

### JavaScript/TypeScript SDK
```bash
npx ts-node sdk/javascript/smoke-test/test_smoke.ts --all
npx ts-node sdk/javascript/smoke-test/test_smoke.ts --connectors stripe,aci
```

### Java/Kotlin SDK
```bash
./gradlew run --args="--all"
./gradlew run --args="--connectors stripe,aci"
```

### Via Make (All SDKs)
```bash
make -C sdk/python test-package
make -C sdk/javascript test-package
make -C sdk/java test-package
```

## Security Notes

- Never commit `creds.json` to version control
- Keep your credentials secure and rotate them regularly
- Use test/sandbox credentials for testing, never production credentials
- The smoke tests use `--dry-run` mode by default to avoid making actual API calls

## Troubleshooting

If you see "All tests skipped (no valid credentials found)":
- Ensure `creds.json` exists in the root directory
- Replace all `<REPLACE_WITH_YOUR_VALUE>` placeholders with actual values
- Check that the connector names match exactly (case-sensitive)
