# Payment Methods Gap Analysis: Missing from Hyperswitch-Prism

**Generated:** April 2026  
**Purpose:** Track connectors and payment methods NOT implemented in Hyperswitch-Prism

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Connectors in Hyperswitch** | 114 |
| **Connectors Implemented in Prism** | 82 |
| **Connectors Missing from Prism** | 32 |
| **Connectors with Missing 3DS** | 9 |
| **Connectors Completely Missing** | 37 |

### Critical Gaps Summary

🔴 **37 connectors** completely missing from Prism (32.5% of total)
🔴 **9 connectors** missing 3DS implementation despite advertising support
🔴 **Complete absence** of:
- BNPL: Klarna, Affirm, Breadpay, Flexiti, Katapult, PayJustNow
- Crypto: BitPay, Coinbase, Coingate, OpenNode
- Wallets: AmazonPay, Boku, Hyperwallet
- Card Processors: Square, Worldline, Moneris, MPGS, GlobePay

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ❌ | **Not Implemented** - Feature exists in Hyperswitch but is **MISSING** in Prism (Gap!) |
| ➖ | **Not Supported** - Connector doesn't support this (not a gap) |

---

## Connectors Missing from Hyperswitch-Prism

### All 37 Missing Connectors

| # | Connector | Category | Impact |
|---|-----------|----------|:------:|
| 1 | **AFFIRM** | Pay Later/BNPL | 🔴 High |
| 2 | **AMAZONPAY** | Wallet | 🔴 High |
| 3 | **ARCHIPEL** | Card | 🟡 Medium |
| 4 | **BITPAY** | Crypto | 🟡 Medium |
| 5 | **BLACKHAWKNETWORK** | Gift Card | 🟢 Low |
| 6 | **BOKU** | Wallet | 🟡 Medium |
| 7 | **BREADPAY** | Pay Later | 🟡 Medium |
| 8 | **CHECKBOOK** | Bank Transfer | 🟡 Medium |
| 9 | **COINBASE** | Crypto | 🟡 Medium |
| 10 | **COINGATE** | Crypto | 🟡 Medium |
| 11 | **DEUTSCHEBANK** | Bank Transfer | 🟡 Medium |
| 12 | **DIGITALVIRGO** | Carrier Billing | 🟢 Low |
| 13 | **DWOLLA** | Bank Transfer | 🟡 Medium |
| 14 | **FACILITAPAY** | Alternative | 🟢 Low |
| 15 | **FLEXITI** | Pay Later | 🟡 Medium |
| 16 | **GLOBEPAY** | Card | 🟡 Medium |
| 17 | **GOCARDLESS** | Bank Debit | 🔴 High |
| 18 | **HYPERWALLET** | Wallet | 🟡 Medium |
| 19 | **INESPAY** | Bank Redirect | 🟢 Low |
| 20 | **KATAPULT** | Lease-to-Own | 🟢 Low |
| 21 | **KLARNA** | Pay Later/BNPL | 🔴 High |
| 22 | **MONERIS** | Card | 🟡 Medium |
| 23 | **MPGS** | Card | 🟡 Medium |
| 24 | **NORDEA** | Bank | 🟡 Medium |
| 25 | **OPENNODE** | Crypto | 🟡 Medium |
| 26 | **PAYJUSTNOW** | Pay Later | 🟢 Low |
| 27 | **PAYJUSTNOWINSTORE** | Pay Later | 🟢 Low |
| 28 | **PAYSTACK** | Card/Wallet | 🟡 Medium |
| 29 | **PROPHETPAY** | Alternative | 🟢 Low |
| 30 | **SANTANDER** | Bank | 🟡 Medium |
| 31 | **SQUARE** | Card | 🔴 High |
| 32 | **TESOURO** | Government | 🟢 Low |
| 33 | **TOKENIO** | Open Banking | 🟡 Medium |
| 34 | **WORLDLINE** | Card | 🔴 High |
| 35 | **WORLDPAYMODULAR** | Card | 🟡 Medium |
| 36 | **ZEN** | Alternative | 🟢 Low |
| 37 | **ZSL** | Alternative | 🟢 Low |

---

## Payment Methods Missing from Prism

### Card Networks (Missing from Prism)

| Card Network | ARCHIPEL | GLOBEPAY | MONERIS | MPGS | SQUARE | WORLDLINE | WORLDPAYMODULAR |
|--------------|:--------:|:--------:|:-------:|:----:|:------:|:---------:|:---------------:|
| American Express | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Cartes Bancaires | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Diners Club | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Discover | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Interac | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| JCB | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Maestro | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Mastercard | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| RuPay | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| UnionPay | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Visa | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

### Wallets (Missing from Prism)

| Wallet | AMAZONPAY | BOKU | HYPERWALLET |
|--------|:---------:|:----:|:-----------:|
| Amazon Pay SDK | ❌ | ➖ | ➖ |
| Amazon Pay Redirect | ❌ | ➖ | ➖ |
| Boku | ➖ | ❌ | ➖ |
| Hyperwallet | ➖ | ➖ | ❌ |

### Pay Later / BNPL (Missing from Prism)

| BNPL Provider | AFFIRM | BREADPAY | FLEXITI | KATAPULT | PAYJUSTNOW | PAYJUSTNOWINSTORE |
|---------------|:------:|:--------:|:-------:|:--------:|:----------:|:-----------------:|
| Affirm | ❌ | ➖ | ➖ | ➖ | ➖ | ➖ |
| Breadpay | ➖ | ❌ | ➖ | ➖ | ➖ | ➖ |
| Flexiti | ➖ | ➖ | ❌ | ➖ | ➖ | ➖ |
| Katapult | ➖ | ➖ | ➖ | ❌ | ➖ | ➖ |
| PayJustNow | ➖ | ➖ | ➖ | ➖ | ❌ | ➖ |
| PayJustNow In-Store | ➖ | ➖ | ➖ | ➖ | ➖ | ❌ |

### Bank Redirect (Missing from Prism)

| Bank Redirect | INESPAY | TOKENIO |
|---------------|:-------:|:-------:|
| Local Bank Redirect | ❌ | ❌ |
| Open Banking PIS | ➖ | ❌ |

### Bank Transfer (Missing from Prism)

| Bank Transfer | CHECKBOOK | DWOLLA | DEUTSCHEBANK | GOCARDLESS | NORDEA | SANTANDER |
|---------------|:---------:|:------:|:------------:|:----------:|:------:|:---------:|
| ACH Bank Transfer | ❌ | ❌ | ➖ | ➖ | ❌ | ❌ |
| SEPA Bank Transfer | ➖ | ➖ | ❌ | ❌ | ❌ | ❌ |
| Bacs Bank Transfer | ➖ | ➖ | ➖ | ❌ | ➖ | ➖ |
| Wire Transfer | ➖ | ➖ | ❌ | ➖ | ➖ | ❌ |

### Bank Debit (Missing from Prism)

| Bank Debit | GOCARDLESS | NORDEA | SANTANDER |
|------------|:----------:|:------:|:---------:|
| SEPA | ❌ | ❌ | ❌ |
| Bacs | ❌ | ➖ | ➖ |

### Crypto (Missing from Prism)

| Crypto | BITPAY | COINBASE | COINGATE | OPENNODE |
|--------|:------:|:--------:|:--------:|:--------:|
| Bitcoin | ❌ | ❌ | ❌ | ❌ |
| Ethereum | ❌ | ❌ | ❌ | ➖ |
| Altcoins | ❌ | ❌ | ❌ | ➖ |

### Gift Card (Missing from Prism)

| Gift Card | BLACKHAWKNETWORK |
|-----------|:----------------:|
| Gift Cards | ❌ |
| Prepaid Cards | ❌ |

### Voucher (Missing from Prism)

| Voucher | DIGITALVIRGO | PAYJUSTNOWINSTORE |
|---------|:------------:|:-----------------:|
| Carrier Billing | ❌ | ➖ |
| In-Store Voucher | ➖ | ❌ |

---

## 3DS Implementation Gaps

### Critical 3DS Gaps (9 Connectors)

These connectors advertise 3DS support in Hyperswitch but are missing implementation in Prism:

| # | Connector | Hyperswitch Status | Prism Status | Issue |
|---|-----------|-------------------|--------------|-------|
| 1 | **BAMBORA** | ✅ 3DS Supported | ❌ **NOT IMPLEMENTED** | Connector exists, no 3DS code |
| 2 | **MOLLIE** | ✅ 3DS Supported | ❌ **NOT IMPLEMENTED** | Connector exists, no 3DS code |
| 3 | **MULTISAFEPAY** | ✅ 3DS Supported | ❌ **NOT IMPLEMENTED** | Connector exists, no 3DS code |
| 4 | **NEXINETS** | ✅ 3DS Supported | ❌ **NOT IMPLEMENTED** | Connector exists, no 3DS code |
| 5 | **NOVALNET** | ✅ 3DS Supported | ❌ **NOT IMPLEMENTED** | Connector exists, no 3DS code |
| 6 | **NUVEI** | ✅ 3DS Supported | ❌ **NOT IMPLEMENTED** | Connector exists, no 3DS code |
| 7 | **PAYBOX** | ✅ 3DS Supported | ❌ **NOT IMPLEMENTED** | Connector exists, no 3DS code |
| 8 | **SHIFT4** | ✅ 3DS Supported | ❌ **NOT IMPLEMENTED** | Connector exists, no 3DS code |
| 9 | **PAYU** | ✅ 3DS Supported | ➖ **NOT SUPPORTED** | Partial gap |

### Missing Connectors with 3DS (2 Connectors)

These connectors advertise 3DS in Hyperswitch but are entirely missing from Prism:

| # | Connector | Hyperswitch Status | Prism Status |
|---|-----------|-------------------|--------------|
| 1 | **ARCHIPEL** | ✅ 3DS Supported | ❌ **CONNECTOR MISSING** |
| 2 | **WORLDLINE** | ✅ 3DS Supported | ❌ **CONNECTOR MISSING** |

### 3DS Implementation Summary

| Status | Count |
|--------|-------|
| ❌ Missing 3DS Code | 9 |
| ❌ Connector Missing | 2 |
| **Total 3DS Gaps** | **11** |

---

## Payment Method Implementation Gaps

These connectors advertise support for specific payment methods in Hyperswitch but the implementation is missing in Prism:

### Verified Implementation Gaps (6 Connectors)

| # | Connector | Payment Method | Hyperswitch Status | Prism Status | Issue |
|---|-----------|---------------|-------------------|--------------|-------|
| 1 | **MOLLIE** | Klarna | ✅ Supported | ❌ **NOT IMPLEMENTED** | BNPL method not coded |
| 2 | **MOLLIE** | iDEAL | ✅ Supported | ❌ **NOT IMPLEMENTED** | Bank redirect not coded |
| 3 | **BRAINTREE** | PayPal SDK | ✅ Supported | ❌ **NOT IMPLEMENTED** | Wallet SDK not coded |
| 4 | **DLOCAL** | PIX | ✅ Supported | ❌ **NOT IMPLEMENTED** | Local payment not coded |
| 5 | **PAYSAFE** | Skrill | ✅ Supported | ❌ **NOT IMPLEMENTED** | Wallet not coded |
| 6 | **PAYSAFE** | Neteller | ✅ Supported | ❌ **NOT IMPLEMENTED** | Wallet not coded |

### Payment Method Implementation Summary

| Status | Count |
|--------|-------|
| ❌ BNPL Methods Missing | 2 |
| ❌ Wallet Methods Missing | 3 |
| ❌ Local Payment Methods Missing | 1 |
| **Total Implementation Gaps** | **6** |

---


**Total Gaps:** 37 connectors missing + 9 connectors missing 3DS = **46 gaps to address**

*Document generated: April 2026*
