import type { Json } from "../../../support/config.js";

// Complete synthetic requests. The runner does not add its common payment defaults.
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
export function basicCardPayment(): Json {
  return structuredClone({
    amount: 6000,
    currency: "USD",
    confirm: false,
    capture_method: "automatic",
    authentication_type: "no_three_ds",
    payment_method: "card",
    payment_method_type: "credit",
    setup_future_usage: null,
    customer_acceptance: null,
    email: "ucs-e2e@example.com",
    return_url: "https://example.com",
    browser_info: browser,
    payment_method_data: { card },
    billing: { address },
  });
}
export function checkoutPayment(): Json {
  return {
    ...basicCardPayment(),
    confirm: true,
    description: "Synthetic checkout",
    merchant_order_reference_id: "synthetic-order",
    payment_channel: "ecommerce",
    customer: {
      name: "Test Buyer",
      email: "ucs-e2e@example.com",
      phone: "2025550100",
      phone_country_code: "+1",
    },
    billing: {
      address: structuredClone(address),
      email: "ucs-e2e@example.com",
      phone: { number: "2025550100", country_code: "+1" },
    },
    shipping: { address: structuredClone(address) },
    billing_descriptor: { statement_descriptor_suffix: "E2E" },
    metadata: { fixture_case: "checkout", order_reference: "synthetic-order" },
  };
}
export function clientPayment(): Json {
  return {
    amount: 6000,
    currency: "USD",
    confirm: false,
    capture_method: "automatic",
    authentication_type: "no_three_ds",
    setup_future_usage: null,
  };
}
export function clientConfirmation(): Json {
  const { card_holder_name: _holder, ...clientCard } = structuredClone(card);
  return {
    confirm: true,
    payment_method: "card",
    payment_type: "normal",
    payment_method_data: { card: { ...clientCard, card_network: "Visa" } },
    browser_info: {
      ...browser,
      accept_language: "en-US",
      java_enabled: true,
      java_script_enabled: true,
      device_model: "Example Device",
      os_type: "Linux",
      os_version: "1.0",
    },
    return_url: "https://example.com",
  };
}
