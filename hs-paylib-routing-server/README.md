# hs-paylib Routing Server

Small FastAPI server that uses `hs-paylib` to route payments by currency:

- `USD` -> `stripe`
- `EUR` -> `adyen`

## Endpoints

- `GET /health`
- `GET /routing-rules`
- `POST /payments/authorize`
- `POST /payments/refund`

`/payments/refund` accepts the `payment_id` returned by `/payments/authorize`. For this demo app, payment state is stored in memory.

## Run

```bash
../venv/bin/python -m uvicorn app.main:app --app-dir hs-paylib-routing-server --reload
```

## Example Requests

Authorize a USD payment:

```bash
curl -X POST http://127.0.0.1:8000/payments/authorize \
  -H 'content-type: application/json' \
  -d '{"amount_minor":1000,"currency":"USD"}'
```

Authorize a EUR payment:

```bash
curl -X POST http://127.0.0.1:8000/payments/authorize \
  -H 'content-type: application/json' \
  -d '{"amount_minor":1000,"currency":"EUR"}'
```

Refund a previously authorized payment:

```bash
curl -X POST http://127.0.0.1:8000/payments/refund \
  -H 'content-type: application/json' \
  -d '{"payment_id":"<payment_id>"}'
```

## Live Validation

The live validation script uses real sandbox credentials and writes a markdown report:

```bash
PYTHONPATH=hs-paylib-routing-server ../venv/bin/python hs-paylib-routing-server/scripts/validate_live_flows.py \
  --creds-file /Users/amitsingh.tanwar/Documents/connector-service/connector-service-02/connector-service/.github/test/creds.json
```

Output file:

- `hs-paylib-routing-server/artifacts/live_validation_results.md`

## Notes

- Stripe refunds complete synchronously in this sandbox run.
- Adyen refunds are accepted asynchronously and return `REFUND_PENDING` on refund creation.
- The app intentionally keeps routing logic explicit instead of making it configuration-driven, so an AI agent can locate and modify it quickly.
