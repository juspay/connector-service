# Authipay Payments API Documentation

## Connector Information

### Connector Name
Authipay Payments API

### Base URLs
- Production URL: `https://prod.emea.api.fiservapps.com/sandbox/ipp/payments-gateway/v2/payments`
- Base API Endpoint: `https://prod.emea.api.fiservapps.com/sandbox/ipp/payments-gateway/v2/payments`

## Authentication Details

### Authentication Method
Message Signature Authentication

### Authentication Parameters

#### Api-Key (required)
- **Description**: Key given to merchant after boarding associating their requests with the appropriate app in Apigee
- **Type**: String
- **Obtained from**: Developer Portal after merchant boarding
- **Usage**: Must be included in every API request header

#### Client-Request-Id (required)
- **Description**: A client-generated ID for request tracking and signature creation, unique per request
- **Type**: String
- **Format**: Recommended 128-bit UUID (e.g., "123e4567-e89b-12d3-a456-426614174000")
- **Purpose**: Used for idempotency control and request tracking
- **Note**: The same Client-Request-Id will be echoed back in the response as `clientRequestId`

#### Timestamp (required)
- **Description**: Epoch timestamp in milliseconds in the request from a client system
- **Type**: int64
- **Format**: Milliseconds since Unix Epoch (January 1, 1970 00:00:00 UTC)
- **Example**: 1640995200000
- **Validation**: Must be within 5 minutes of the server time
- **Purpose**: Used for Message Signature generation and preventing replay attacks

#### Message-Signature (required)
- **Description**: Used to ensure the request has not been tampered with during transmission
- **Type**: String (Base64 encoded)
- **Algorithm**: HMAC-SHA256
- **Secret Key**: API Secret obtained from Developer Portal (must be from the same application as your API Key)
- **Generation Process**: See "Message Signature Generation Process" section below

#### Message-Authentication-Value (optional)
- **Description**: Optional header only required for Card Present transactions or transactions originated from Terminals
- **Type**: String
- **Format**: `<Derivation Algo>;<Mac Algo>;<key index>[;<key name>][;<key version>]`

**Derivation Algorithms:**
- `DUKPT2009`: Derived Unique Key Per Transaction algorithm as defined by ANSI X9.24-2009 Annex A
- `AESDUKPT128ECB`: AES DUKPT ECB algorithm with a key length of 128 bits, as defined in ANSI X9.24-3-2017 Annex

**MAC Algorithms:**
- `RetailSHA256MAC`: Retail-CBC-MAC using SHA-256 (Secure Hash standard) with ASN.1 Object Identifier: id-retail-cbc-mac-sha-256
- `SHA256CMACwithAES128`: CMAC (Cipher-based Message Authentication Code) as defined by NIST 800-38B (May 2005). Uses AES block cipher with 128-bit cryptographic key (approved by FIPS 197). The CMAC algorithm is computed on the SHA-256 digest of the message.

**Additional Parameters:**
- `key index`: Index of the encryption key
- `key name`: (Optional) Name identifier for the key
- `key version`: (Optional) Version number of the key

**Example**:
```
DUKPT2009;RetailSHA256MAC;12345;MyTerminalKey;1
```

### Message Signature Generation Process
1. Create raw signature by concatenating: `API-Key + ClientRequestId + time + requestBody`
2. Generate HMAC using SHA256 algorithm with API Secret as key
3. Apply the HMAC to the raw signature
4. Finalize and stringify the computed hash using Base64 encoding

## Complete Endpoint Inventory

### 1. Generate a Primary Transaction
- **Endpoint URL**: `https://prod.emea.api.fiservapps.com/sandbox/ipp/payments-gateway/v2/payments`
- **HTTP Method**: POST
- **Headers**:
  - `Content-Type: application/json` (required)
  - `Client-Request-Id` (required)
  - `Api-Key` (required)
  - `Timestamp` (required)
  - `Message-Signature` (required)
  - `Message-Authentication-Value` (optional)
- **Request Body**: JSON object containing transaction details

#### Primary Transaction Request Types

**PaymentCardSaleTransaction** - Standard card payment (sale)
```json
{
  "requestType": "PaymentCardSaleTransaction",
  "transactionAmount": {
    "total": "13.00",
    "currency": "GBP"
  },
  "paymentMethod": {
    "paymentCard": {
      "number": "4012000000000001",
      "securityCode": "123",
      "expiryDate": {
        "month": "01",
        "year": "29"
      }
    }
  },
  "authenticationRequest": {
    "authenticationType": "Secure3D21AuthenticationRequest",
    "termURL": "https://yourserver.com/api/v1/payments/3ds",
    "challengeIndicator": "04"
  }
}
```

**PaymentCardPreAuthTransaction** - Pre-authorize an amount (requires completion via PostAuthTransaction)
```json
{
  "requestType": "PaymentCardPreAuthTransaction",
  "transactionAmount": {
    "total": "100.00",
    "currency": "GBP"
  },
  "paymentMethod": {
    "paymentCard": {
      "number": "4012000000000001",
      "securityCode": "123",
      "expiryDate": {
        "month": "01",
        "year": "29"
      }
    }
  }
}
```

**PaymentCardCreditTransaction** - Original credit (refund without reference to a previous sale)
```json
{
  "requestType": "PaymentCardCreditTransaction",
  "transactionAmount": {
    "total": "25.00",
    "currency": "GBP"
  },
  "paymentMethod": {
    "paymentCard": {
      "number": "4012000000000001",
      "securityCode": "123",
      "expiryDate": {
        "month": "01",
        "year": "29"
      }
    }
  }
}
```



#### Common Request Fields (applicable to most request types)

**transactionAmount** (required for most)
```json
{
  "total": "100.00",
  "currency": "GBP",
  "components": {
    "subtotal": "90.00",
    "vatAmount": "10.00"
  }
}
```

**order** (optional)
```json
{
  "orderId": "ORDER-12345",
  "billing": {
    "name": "John Doe",
    "address": {
      "street": "123 Main St",
      "city": "London",
      "postalCode": "SW1A 1AA",
      "country": "GB"
    }
  },
  "shipping": {
    "name": "Jane Doe",
    "address": {
      "street": "456 Oak Ave",
      "city": "Manchester",
      "postalCode": "M1 1AA",
      "country": "GB"
    }
  }
}

```


### Request Types (Primary Transactions)
- PaymentCardSaleTransaction
- PaymentCardCreditTransaction
- PaymentCardPreAuthTransaction
- PaymentTerminalSaleTransaction
- PaymentTerminalPreauthTransaction
- PaymentTerminalCreditTransaction
- PaymentTokenSaleTransaction
- PaymentTokenCreditTransaction
- PaymentTokenPreAuthTransaction
- SepaSaleTransaction
- SepaCreditTransaction
- WalletSaleTransaction
- WalletPreAuthTransaction
- ApmSaleTransaction
- ApmPreauthTransaction



### Supported Features
- 3D Secure authentication
- PCI DSS compliance requirements
- Order management
- Multiple payment methods
- Transaction inquiry
- Secondary transaction processing

### Security Requirements
- Message signature generation using HMAC-SHA256
- API key authentication
- Client request ID tracking
- Timestamp validation (5-minute window)

## Response Codes

### Success Response (200)

#### Core Response Fields
- **clientRequestId** (string): Echoes back the value in the request header for tracking
- **apiTraceId** (string): Request identifier in API, can be used to request logs from the support team
- **responseType** (string): The type of the response. Values: `BadRequest`, `Unauthenticated`, `Unauthorized`, `NotFound`, `GatewayDeclined`, `EndpointDeclined`, `ServerError`, `EndpointCommunicationError`, `UnsupportedMediaType`
- **type** (string): Request object name, used to discriminate which object the request body is resolved to
- **ipgTransactionId** (string): The response transaction ID
- **orderId** (string): Client Order ID if supplied by client. If not supplied by client, IPG will generate. The first 12 alphanumeric digits are passed down to Fiserv Enterprise reporting tool, Clientline and Data File Manager (DFM)
- **userId** (string, max length 128): This is the store's userID (not store-id) from where the product was purchased
- **transactionType** (string): Type of transaction to perform. Values: `SALE`, `PREAUTH`, `CREDIT`, `FORCED_TICKET`, `VOID`, `RETURN`, `POSTAUTH`, `PAYER_AUTH`, `DISBURSEMENT`

#### Payment Token Object
- **paymentToken** (object): Use this model to create a payment token
  - **value** (string): Client-supplied payment token value. Only applicable for DataVault tokenization scheme
  - **reusable** (boolean, default: true): If the token is reusable
  - **declineDuplicates** (boolean, default: false): Decline duplicate payment info if client token is supplied
  - **customWalletRegistration** (object): Container for wallet registration details
  - **last4** (string): The last 4 numbers of a payment card
  - **brand** (string): Card brand, only for tokenization with payment
  - **accountVerification** (boolean): If the account the token was created from has been verified
  - **type** (string): Indicates the type of tokenization source
  - **networkTokenProvisionStatus** (string): This field provides the status of the NetworkToken being provisioned for the supplied PAN. Values: `REQUESTED`, `PROVISIONED`, `QUEUED`

#### Transaction Details
- **transactionOrigin** (string): The source of the transaction. Values: `ECOM`, `MOTO`, `MAIL`, `PHONE`, `RETAIL`
- **terminalId** (string): The terminal that is processing the transaction
- **merchantId** (string, max length 30): The unique (on Acquirer level) merchant ID
- **merchantTransactionId** (string, max length 40): The unique merchant transaction ID from the request header, if supplied
- **transactionTime** (int64): The transaction time in seconds since epoch

#### Payment Method Details
- **paymentMethodDetails** (object): Provides details of the payment method used
  - **paymentCard** (object): Payment card model
  - **paymentCardEncrypted** (object): Encapsulates sensitive card data in encrypted format
  - **paymentMethodType** (string): Type of payment method. Values include: `PAYMENT_CARD`, `PAYMENT_TOKEN`, `PAYPAL`, `SEPA`, `WALLET`, `IDEAL`, `GIROPAY`, `KLARNA`, and many more
  - **paymentMethodBrand** (string): A list of all Payment Method Brands (extensive list including VISA, MASTERCARD, AMEX, etc.)

#### Account Verification Response
- **accountVerificationResponse** (object): Account Verification Response
  - **firstNameMatch** (string): Values: `MATCH`, `PARTIAL_MATCH`, `NO_MATCH`
  - **middleNameMatch** (string): Values: `MATCH`, `PARTIAL_MATCH`, `NO_MATCH`
  - **lastNameMatch** (string): Values: `MATCH`, `PARTIAL_MATCH`, `NO_MATCH`
  - **fullNameMatch** (string): Values: `MATCH`, `PARTIAL_MATCH`, `NO_MATCH`
  - **nameMatchIndicator** (string): Values: `PERFORMED`, `NOT_SUPPORTED`, `NOT_PERFORMED`
  - **country** (string): Country of the card issuer

#### Transaction Amount
- **approvedAmount** (object): Amount of the transaction
  - **total** (number, >= 0): Sub component values must add up to total amount
  - **currency** (string): ISO 4217 currency code
  - **components** (object): Transaction amounts with multiple components

- **transactionAmount** (object): Amount of the transaction
  - **total** (number, >= 0): Sub component values must add up to total amount
  - **currency** (string): ISO 4217 currency code
  - **components** (object): Transaction amounts with multiple components

#### Transaction Status
- **transactionStatus** (string, DEPRECATED - use transactionResult): Values: `APPROVED`, `WAITING`, `PARTIAL`, `VALIDATION_FAILED`, `PROCESSING_FAILED`, `DECLINED`
- **transactionResult** (string): This is the result of the operation. Values: `APPROVED`, `DECLINED`, `FAILED`, `WAITING`, `PARTIAL`, `FRAUD`
- **transactionState** (string): Shows the state of the current transaction. Values: `AUTHORIZED`, `CAPTURED`, `DECLINED`, `CHECKED`, `COMPLETED_GET`, `INITIALIZED`, `PENDING`, `READY`, `TEMPLATE`, `SETTLED`, `VOIDED`, `WAITING`
- **approvalCode** (string): Shows the transaction approval code
- **schemeResponseCode** (string): Shows the Scheme Response Code
- **errorMessage** (string): Shows the transaction error message
- **paymentAccountReferenceNumber** (string, max length 30): Payment Account Reference Number from response, if supplied



- **authenticationResponse** (object): Encapsulates 3DS authentication
#### Scheme Transaction Details
- **schemeTransactionId** (string, max length 40): The transaction ID received from schemes for the initial transaction of card on file flows
- **transactionLinkIdentifier** (string, max length 36): The unique Identifier sent from scheme to link all transactions for single order

#### Processor Response
- **processor** (object): Model for processor data
  - **referenceNumber** (string): Reference transaction ID
  - **authorizationCode** (string): Code returned to confirm transaction
  - **responseCode** (string): Response code from endpoints
  - **network** (string): Network used for transaction
  - **associationResponseCode** (string): Raw response code from issuer
  - **associationResponseMessage** (string): Indicates the processor association message
  - **responseMessage** (string): Message returned from endpoints
  - **avsResponse** (object): The processor address validation response for compliance
  - **cardholderInfoResponse** (object): The processor Cardholder Info Response
  - **securityCodeResponse** (string): Code returned for CVV. Values: `MATCHED`, `NOT_MATCHED`, `NOT_PROCESSED`, `NOT_PRESENT`, `NOT_CERTIFIED`, `NOT_CHECKED`
  - **merchantAdviceCodeIndicator** (string): Code to map merchant advice code to ISO specification
  - **merchantAdviceMessage** (string): Information about the merchant advice code
  - **paymentAccountReferenceNumber** (string): Information about the payment account Reference number
  - **responseIndicator** (string): Indicates whether the transaction was routed through the payment card's own network or through a different network
  - **debitReceiptNumber** (string): Receipt number from debit network provider
  - **transactionIntegrityClass** (string): MasterCard provided Transaction Integrity Class for Point of Sale (POS) transactions

#### Additional Response Data
- **receipts** (array of objects, length 1-2): Provides receipt response data, if it has been requested
  - **type** (string, required): Defines the consumer of the receipt. Values: `cardholder`, `merchant`
  - **data** (array of objects, required): Array of formatted lines that represents the actual receipt data
    - **endOfLine** (boolean, default: true): Flag to indicate if the text ends at the end of this receipt line
    - **text** (string, required): Text that represents a line of the actual receipt data

- **additionalResponseData** (object): Additional Response Data
  - **accountUpdaterResponse** (object): Details related to updated account information
    - **updatedCard** (string): Account updater replacement PAN or TransArmor token
    - **updatedToken** (string): Updated value of token
    - **updatedExpirationDate** (string): New account number expiration date in MMYY format
    - **updatedAccountStatus** (string): Status of the updated account
    - **updatedAccountErrorCode** (string): Code for the error encountered when updating account
  - **originalResponseCode** (string): Original Response Code for re-authorized (Optimized) transaction
  - **achResponse** (object): ACH TeleCheck response
  - **currencyConversionResponse** (object): Currency Conversion Response
    - **dccApplied** (boolean): Dynamic Currency Conversion Applied
    - **exchangeRateDetails** (object): Fields related to Currency Conversion Inquiry

- **additionalDetails** (object): Additional transaction details for transaction response
  - **comments** (string, max length 1024): Comment for the payment
  - **invoiceNumber** (string, max length 48): Invoice number
  - **purchaseOrderNumber** (string, max length 128): Purchase order number
  - **disbursementTransType** (string): The type of debit disbursement transaction. Values: `FUNDING`, `DISBURSEMENT`
  - **walletProvider** (string): The wallet provider type. Values: `GOOGLE_PAY`, `APPLE_PAY`, `SAMSUNG_PAY`, `CLICK_TO_PAY`

#### Network Token
- **networkToken** (object): Network Token Model
  - **value** (string, required): Token value
  - **expiryMonth** (string, required): Month of the token expiration date in MM format
  - **expiryYear** (string, required): Year of the card expiration date in YY format
  - **cardLast4** (string, max length 4): Last four digits of Card number
  - **brand** (string): Card brand. Values: `AMEX`, `DINERS/DISCOVER`, `EFTPOS`, `JCB`, `MAESTRO`, `MASTERCARD`, `RUPAY`, `VISA`
  - **cryptogram** (string): Cryptogram value
  - **authIndicator** (string): Authorization Indicator. Values: `P`, `T`
  - **tokenEligible** (string): Token Assurance Method Value
  - **emvData** (string, max length 10000): EMV data from the issuer response, Base64 encoded

#### Installment Plan
- **selectedInstallmentPlan** (object): Installment Plan Model
  - **installmentPlanId** (string, max length 36): Installment Plan Id
  - **installmentPlanInquiryId** (int64): Installment Plan Inquiry Id
  - **islamicPlan** (boolean): Indicates if the plan is Islamic
  - **provider** (string, max length 60): Provider
  - **tenure** (int32, >= 1): Tenure
  - **installmentFrequency** (string, max length 9): Installment Frequency
  - **interestRate** (number): Interest Rate
  - **currency** (string): ISO 4217 currency code
  - **interestAmount** (number, >= 0): Interest Amount
  - **installmentFee** (number, >= 0): Installment Fee
  - **totalFee** (number, >= 0): Total Fee
  - **amountPerInstallment** (number, >= 0): Amount Per Installment
  - **totalAmount** (number, >= 0): Total Amount
  - **termsAndConditionText** (string, max length 2048): Terms And Condition Text
  - **bankName** (string, max length 50): Bank Name
  - **bankCode** (string, max length 20): Bank Code

#### Required Actions
- **requiredActions** (object): Provides details which actions need to be performed to fulfill requirements of integration data
  - **requiredConsumerData** (array of objects): Consumer data details which need to be provided by the payer
    - **hint** (string, max length 2048): Description of required data
    - **validationExpression** (string, max length 2048): Regexp validation expression for requested data
    - **key** (string, max length 2048): Key for required data item
    - **options** (array of objects): Provides options to select a value from
  - **requiredIntegrationData** (array of objects): Provides details for data requested from the application
    - **hint** (string, max length 2048): Description of required integration data
    - **key** (string, max length 2048): Key for required data item
  - **requiredRedirectionData** (object): Redirection details provided to the payer

- **plannedDueDate** (string): Capture PlannedDueDate field sent for SEPA transactions

#### Error Object
- **error** (object): Error information
  - **code** (string): Uniquely identifies an error condition
  - **message** (string): A generic description of the error condition
  - **details** (array of objects): Detailed information about message format errors
    - **field** (string): The property or attribute associated with the error
    - **message** (string): Information specific to a property or attribute
  - **declineReasonCode** (string): Information about the decline reason

### Error Responses

All error responses follow the same structure:

#### Common Error Response Structure
```json
{
  "clientRequestId": "string",
  "apiTraceId": "string",
  "responseType": "string",
  "type": "string",
  "error": {
    "code": "string",
    "message": "string",
    "details": [
      {
        "field": "string",
        "message": "string"
      }
    ],
    "declineReasonCode": "string"
  }
}
```

#### Error Response Fields
- **clientRequestId** (string): Echoes back the value in the request header for tracking
- **apiTraceId** (string): Request identifier in API, can be used to request logs from the support team
- **responseType** (string): The type of the response. Values: `BadRequest`, `Unauthenticated`, `Unauthorized`, `NotFound`, `GatewayDeclined`, `EndpointDeclined`, `ServerError`, `EndpointCommunicationError`, `UnsupportedMediaType`
- **type** (string): Request object name, used to discriminate which object the request body is resolved to
- **error** (object): Error information
  - **code** (string): Uniquely identifies an error condition. Client applications need to read and handle errors based on this
  - **message** (string): A generic description of the error condition
  - **details** (array of objects): Detailed information about message format errors
    - **field** (string): The property or attribute associated with the error
    - **message** (string): Information specific to a property or attribute
  - **declineReasonCode** (string): Information about the decline reason

#### HTTP Status Codes

**400 Bad Request**
- Description: The request cannot be validated
- responseType: `BadRequest`
- Common causes: Invalid JSON format, missing required fields, invalid field values

**401 Unauthorized**
- Description: The request cannot be authenticated or was submitted with wrong credentials
- responseType: `Unauthenticated`
- Common causes: Invalid API key, incorrect message signature, expired timestamp

**403 Forbidden**
- Description: The request was unauthorized
- responseType: `Unauthorized`
- Common causes: API key doesn't have permission for the requested operation

**404 Not Found**
- Description: The requested resource doesn't exist
- responseType: `NotFound`
- Common causes: Invalid transaction ID, resource has been deleted

**409 Conflict**
- Description: The attempted action is not valid according to gateway rules
- responseType: `GatewayDeclined`
- Common causes: Duplicate order ID, transaction already processed, merchant not properly set up
- Additional response fields may include:
  - **ipgTransactionId** (string): The response transaction ID
  - **orderId** (string): Client Order ID
  - **userId** (string): Store's userID
  - **transactionType** (string): Type of transaction
  - **paymentToken** (object): Payment token information
  - All other transaction response fields

**415 Unsupported Media Type**
- Description: Format not supported by server for the HTTP method
- responseType: `UnsupportedMediaType`
- Common causes: Missing or incorrect Content-Type header, should be `application/json`

**422 Unprocessable Entity**
- Description: The processor declined the transaction
- responseType: `EndpointDeclined`
- Common causes: Insufficient funds, invalid card details, card declined by issuer
- Additional response fields include:
  - **ipgTransactionId** (string): The response transaction ID
  - **orderId** (string): Client Order ID
  - **userId** (string): Store's userID
  - **transactionType** (string): Type of transaction
  - **transactionOrigin** (string): Source of the transaction
  - **paymentMethodDetails** (object): Payment method used
  - **transactionStatus** (string): DECLINED status
  - **transactionResult** (string): DECLINED/FAILED
  - **transactionState** (string): DECLINED
  - **approvalCode** (string): May be present
  - **schemeResponseCode** (string): Decline reason from card scheme
  - **errorMessage** (string): Human readable error message
  - **processor** (object): Full processor response with decline details
  - All other transaction response fields

**500 Internal Server Error**
- Description: An unexpected internal server error occurred
- responseType: `ServerError`
- Common causes: Internal system error, temporary service disruption

**502 Bad Gateway**
- Description: There was a problem communicating with the endpoint
- responseType: `EndpointCommunicationError`
- Common causes: Downstream service unavailable, network timeout, processor communication error

## Complete Request/Response Examples

### Example 1: Successful Card Sale Transaction

**Request:**
```http
POST https://prod.emea.api.fiservapps.com/sandbox/ipp/payments-gateway/v2/payments
Content-Type: application/json
Client-Request-Id: 550e8400-e29b-41d4-a716-446655440000
Api-Key: your-api-key-here
Timestamp: 1640995200000
Message-Signature: base64-encoded-signature-here
```

```json
{
  "requestType": "PaymentCardSaleTransaction",
  "transactionAmount": {
    "total": "100.00",
    "currency": "GBP"
  },
  "paymentMethod": {
    "paymentCard": {
      "number": "4012000000000001",
      "securityCode": "123",
      "expiryDate": {
        "month": "12",
        "year": "25"
      }
    }
  },
  "order": {
    "orderId": "ORDER-12345",
    "billing": {
      "name": "John Doe",
      "customerId": "CUST-789"
    }
  }
}
```

**Response (200 OK):**
```json
{
  "clientRequestId": "550e8400-e29b-41d4-a716-446655440000",
  "apiTraceId": "rrt-0123456789abcdef0123456789abcdef",
  "ipgTransactionId": "84356531348",
  "orderId": "ORDER-12345",
  "transactionType": "SALE",
  "transactionResult": "APPROVED",
  "transactionState": "CAPTURED",
  "approvalCode": "Y:123456:4356531348:PPXX:4356123456",
  "transactionTime": 1640995200,
  "approvedAmount": {
    "total": 100.00,
    "currency": "GBP"
  },
  "processor": {
    "referenceNumber": "84356531348",
    "authorizationCode": "123456",
    "responseCode": "00",
    "responseMessage": "APPROVED",
    "securityCodeResponse": "MATCHED"
  },
  "paymentMethodDetails": {
    "paymentMethodType": "PAYMENT_CARD",
    "paymentMethodBrand": "VISA"
  }
}
```

### Example 2: Transaction Declined by Processor

**Request:**
```http
POST https://prod.emea.api.fiservapps.com/sandbox/ipp/payments-gateway/v2/payments
Content-Type: application/json
Client-Request-Id: 550e8400-e29b-41d4-a716-446655440001
Api-Key: your-api-key-here
Timestamp: 1640995300000
Message-Signature: base64-encoded-signature-here
```

```json
{
  "requestType": "PaymentCardSaleTransaction",
  "transactionAmount": {
    "total": "5000.00",
    "currency": "GBP"
  },
  "paymentMethod": {
    "paymentCard": {
      "number": "4012000000000001",
      "securityCode": "123",
      "expiryDate": {
        "month": "12",
        "year": "25"
      }
    }
  }
}
```

**Response (422 Unprocessable Entity):**
```json
{
  "clientRequestId": "550e8400-e29b-41d4-a716-446655440001",
  "apiTraceId": "rrt-0123456789abcdef0123456789abcde1",
  "responseType": "EndpointDeclined",
  "ipgTransactionId": "84356531349",
  "transactionType": "SALE",
  "transactionResult": "DECLINED",
  "transactionState": "DECLINED",
  "schemeResponseCode": "51",
  "errorMessage": "DECLINED - Insufficient funds",
  "processor": {
    "referenceNumber": "84356531349",
    "responseCode": "51",
    "responseMessage": "INSUFFICIENT_FUNDS",
    "associationResponseCode": "51"
  },
  "error": {
    "code": "TRANSACTION_DECLINED",
    "message": "The processor declined the transaction",
    "declineReasonCode": "51"
  }
}
```

### Example 3: Pre-Authorization and Completion Flow

**Step 1: Create Pre-Authorization**

Request:
```json
{
  "requestType": "PaymentCardPreAuthTransaction",
  "transactionAmount": {
    "total": "150.00",
    "currency": "GBP"
  },
  "paymentMethod": {
    "paymentCard": {
      "number": "4012000000000001",
      "securityCode": "123",
      "expiryDate": {
        "month": "12",
        "year": "25"
      }
    }
  },
  "order": {
    "orderId": "ORDER-PREAUTH-001"
  }
}
```

Response:
```json
{
  "clientRequestId": "550e8400-e29b-41d4-a716-446655440002",
  "apiTraceId": "rrt-0123456789abcdef0123456789abcde2",
  "ipgTransactionId": "84356531350",
  "orderId": "ORDER-PREAUTH-001",
  "transactionType": "PREAUTH",
  "transactionResult": "APPROVED",
  "transactionState": "AUTHORIZED",
  "approvalCode": "Y:123457:4356531350:PPXX:4356123457",
  "approvedAmount": {
    "total": 150.00,
    "currency": "GBP"
  }
}
```

**Step 2: Complete Pre-Authorization (PostAuth)**

Request:
```http
POST https://prod.emea.api.fiservapps.com/sandbox/ipp/payments-gateway/v2/payments/84356531350
```

```json
{
  "requestType": "PostAuthTransaction",
  "transactionAmount": {
    "total": "125.00",
    "currency": "GBP"
  }
}
```

Response:
```json
{
  "clientRequestId": "550e8400-e29b-41d4-a716-446655440003",
  "apiTraceId": "rrt-0123456789abcdef0123456789abcde3",
  "ipgTransactionId": "84356531351",
  "orderId": "ORDER-PREAUTH-001",
  "transactionType": "POSTAUTH",
  "transactionResult": "APPROVED",
  "transactionState": "CAPTURED",
  "approvedAmount": {
    "total": 125.00,
    "currency": "GBP"
  }
}
```