# NMI Cards-3ds Technical Specification

## Connector Information

| Attribute | Value |
|-----------|-------|
| **Connector Name** | NMI |
| **Payment Flow** | Cards-3ds |
| **Description** | 3D Secure card payment flow for NMI Direct API |

---

## Base URLs

| Environment | URL |
|-------------|-----|
| **Test** | `https://secure.networkmerchants.com` |
| **Live** | `https://secure.networkmerchants.com` |

---

## Authentication Details

| Method | Description |
|--------|-------------|
| **API Key** | Used in `security_key` field |

---

## Payment Flow: Cards-3ds

The Cards-3ds flow involves three main steps:

### 1. PreAuthenticate (3DS Method/Device Data Collection)

Initiates 3D Secure authentication by collecting device data.

| Attribute | Value |
|-----------|-------|
| **Endpoint URL** | `/api/transact.php` |
| **HTTP Method** | POST |
| **Content-Type** | application/x-www-form-urlencoded |

#### Request Fields

| Field | Required | Description |
|-------|----------|-------------|
| security_key | Yes | API authentication key |
| type | Yes | Transaction type (auth) |
| amount | Yes | Payment amount |
| currency | Yes | Currency code |
| orderid | Yes | Order identifier |
| ccnumber | Yes | Card number |
| ccexp | Yes | Card expiry (MMYY) |
| cvv | Yes | Card CVV |
| redirecturl | Yes | 3DS redirect URL |

#### Response Fields

| Field | Description |
|-------|-------------|
| response | Response code (1=approved, 2=declined, 3=error) |
| responsetext | Response message |
| transactionid | Transaction ID |
| authcode | Authorization code |
| orderid | Order ID |

### 2. Authenticate (3DS Verification)

Handles the 3DS challenge verification.

| Attribute | Value |
|-----------|-------|
| **Endpoint URL** | `/api/transact.php` |
| **HTTP Method** | POST |
| **Content-Type** | application/x-www-form-urlencoded |

### 3. PostAuthenticate (Post 3DS Authorization)

Completes the payment after 3DS verification.

| Attribute | Value |
|-----------|-------|
| **Endpoint URL** | `/api/transact.php` |
| **HTTP Method** | POST |
| **Content-Type** | application/x-www-form-urlencoded |

---

## Implementation Notes

1. NMI uses form-urlencoded requests
2. Response format is URL-encoded for transact endpoint
3. Transaction types:
   - `auth` - Authorization only
   - `sale` - Authorization + Capture
4. For 3DS flow, use `auth` type initially
5. Check `response` field for success (1=approved)

---

## Error Handling

| Response Code | Description |
|---------------|-------------|
| 1 | Approved |
| 2 | Declined |
| 3 | Error |

---

## Status Mapping

| NMI Status | AttemptStatus |
|------------|---------------|
| Complete | Charged |
| Pending | Authorized |
| Failed | Failure |
| InProgress | AuthenticationPending |
