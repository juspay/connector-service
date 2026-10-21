import type { Json } from "../../../framework/config.js";

// Complete payment requests. The runner does not add its common payment defaults.
const card = {
  card_number: "4242424242424242",
  card_exp_month: "03",
  card_exp_year: "30",
  card_holder_name: "Test Buyer",
  card_cvc: "123",
};
const address = {
  first_name: "Test",
  last_name: "Buyer",
  line1: "1 Example Street",
  city: "San Francisco",
  state: "CA",
  zip: "94107",
  country: "US",
};
const browser = {
  accept_header:
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  language: "en-US",
  screen_height: 1080,
  screen_width: 1920,
  color_depth: 24,
  user_agent:
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
  time_zone: 0,
  java_enabled: false,
  ip_address: "192.0.2.1",
};
export function connectDirectPayment(): Json {
  return structuredClone({
    amount: 6000,
    currency: "USD",
    confirm: true,
    capture_method: "automatic",
    payment_method: "card",
    payment_method_data: { card },
    billing: { address, email: "ucs-e2e@example.com" },
    billing_descriptor: {},
    browser_info: browser,
    customer: {
      id: "customer_e2e",
      name: "Test Buyer",
      email: "ucs-e2e@example.com",
    },
    description: "Test checkout",
    merchant_order_reference_id: "test-order",
    metadata: Object.fromEntries(
      Array.from({ length: 15 }, (_, i) => [
        `fixture_field_${i + 1}`,
        `test-value-${i + 1}`,
      ]),
    ),
    partner_merchant_identifier_details: {
      merchant_details: { name: "Example Store", version: "1.0" },
      partner_details: {
        integrator: "Example Integrator",
        name: "Example Platform",
      },
    },
    payment_channel: "ecommerce",
    return_url: "https://example.com",
    shipping: { address: { ...address, line2: "Suite 1" } },
    split_payments: {
      stripe_split_payment: { charge_type: "direct", application_fees: 300 },
    },
  });
}
export function connectDetailedPayment(): Json {
  const request = connectDirectPayment();
  request.billing.phone = { number: "2025550100", country_code: "+1" };
  request.customer.phone = "2025550100";
  request.customer.phone_country_code = "+1";
  request.billing_descriptor.statement_descriptor_suffix = "E2E";
  request.frm_metadata = "test-fraud-context";
  request.metadata.fixture_field_16 = "test-value-16";
  return request;
}
