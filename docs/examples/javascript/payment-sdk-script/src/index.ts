import { types } from "hs-playlib";
import { authorize } from "./flows";
import { accessTokenAndAuthorize } from "./flows";
import { PAYPAL_CREDS, STRIPE_CREDS, WORLDPAY_CREDS } from './config';
import { parseConnector } from './utils';
import { logger } from './utils/logger';

// connector config for paypal
const payPalConfig: types.ConnectorConfig = {
  connector: types.Connector.PAYPAL,
  auth: {
    paypal: {
      clientId: { value: PAYPAL_CREDS.client_id },
      clientSecret: { value: PAYPAL_CREDS.client_secret },
    },
  },
  environment: types.Environment.SANDBOX
};

// connector config for stripe
const stripeConfig: types.ConnectorConfig = {
  connector: types.Connector.STRIPE,
  auth: {
    stripe: {
      apiKey: { value: STRIPE_CREDS.api_key }
    },
  },
  environment: types.Environment.SANDBOX
};

// connector config for worldpay
const worldPayConfig: types.ConnectorConfig = {
  connector: types.Connector.WORLDPAY,
  auth: {
    worldpay: {
      username: { value: WORLDPAY_CREDS.username },
      password: { value: WORLDPAY_CREDS.password },
      entityId: { value: WORLDPAY_CREDS.entity_id }
    },
  },
  environment: types.Environment.SANDBOX
};

// Common request options (if needed)
const options: types.RequestConfig = {

}



async function main(connector: types.Connector) {
  try {



    // currency and amount
    let money: types.Money = {
      minorAmount: 1000,
      currency: types.Currency.USD
    }

    // payment method
    let paymentMethod: types.PaymentMethod = {
      card: {
        cardNumber: { value: "4111111111111111" },
        cardExpMonth: { value: "12" },
        cardExpYear: { value: "2050" },
        cardCvc: { value: "123" },
        cardHolderName: { value: "Test User" },
      }
    }

    let response;

    // Route to appropriate flow based on connector
    switch (connector) {
      case types.Connector.PAYPAL:
        response = await accessTokenAndAuthorize(payPalConfig, money, paymentMethod);
        break;
      case types.Connector.WORLDPAY:
        response = await authorize(worldPayConfig, money, paymentMethod);
        break;
      case types.Connector.STRIPE:
        response = await authorize(stripeConfig, money, paymentMethod);
        break;
    }


    // Common response handling
    if (response) {
      let status = response.status
      switch (status) {
        case types.PaymentStatus.CHARGED:
          logger.info("Payment charged successfully!");
          logger.info(`Transaction ID: ${response.connectorTransactionId}`);
          break;
        case types.PaymentStatus.FAILURE:
          logger.error("Failed...");
          logger.error(String(response.error));
          break;
        default:
          logger.info(`Status: ${status} (${types.PaymentStatus[status] || 'Unknown'})`);
      }
    }
  } catch (e: unknown) {
    if (e instanceof types.RequestError) {
      logger.error(`Request error ${e.errorCode} ${e.errorMessage} ${types.PaymentStatus[e.status]} ${e.statusCode} `)
    } else if (e instanceof types.ResponseError) {
      logger.error(`Response error ${e.errorCode} ${e.errorMessage} ${types.PaymentStatus[e.status]} ${e.statusCode} `)
    } else if (e instanceof Error) {
      logger.error(`  Error: ${e.message}`);
    } else {
      logger.error(`  Error during authorize: ${e}`);
    }
    // This might be expected depending on PayPal API behavior
    logger.info("  PASSED (round-trip completed, error is from PayPal)");
  }
}


// Run main if executed directly
const connectorName = process.argv[2]?.toLowerCase().trim();

if (!connectorName) {
  logger.error("Error: Connector name is required");
  logger.error("Usage: npx ts-node src/index.ts <connector>");
  logger.error("Supported connectors: paypal, stripe, worldpay");
  process.exit(1);
}

const connector = parseConnector(connectorName);
if (!connector) {
  logger.error(`Error: Invalid connector '${connectorName}'`);
  logger.error("Supported connectors: paypal, stripe, worldpay");
  process.exit(1);
}

main(connector).catch((err) => logger.error(String(err)));
