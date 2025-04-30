import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'path';
import * as winston from 'winston';

// Logging setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ level, message, timestamp }) => `${timestamp} - ${level}: ${message}`)
  ),
  transports: [new winston.transports.Console()],
});

// Paths
const PROTO_DIR = path.resolve('../../backend/grpc-api-types/proto');
const PROTO_PATH = path.join(PROTO_DIR, 'payment.proto');

interface PaymentRequest {
  amount: number;
  currency: string;
  // connector: string;
  // auth_creds: Record<string, unknown>;
  payment_method: string;
  payment_method_data: Record<string, unknown>;
  address: Record<string, unknown>;
  auth_type: string;
  connector_request_reference_id: string;
  enrolled_for_3ds: boolean;
  request_incremental_authorization: boolean;
  minor_amount: number;
  email: string;
  browser_info: Record<string,unknown>;
  connector_customer: string;
  return_url: string;
}

async function main() {
  if (process.argv.length < 3) {
    logger.error(`Usage: ${process.argv[1]} <host_url>`);
    process.exit(1);
  }

  const url = process.argv[2];

  try {
    logger.info('Loading proto definitions...');
    const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });

    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;

    const paymentService = protoDescriptor.ucs.payments.PaymentService;

    if (!paymentService) {
      logger.error('PaymentService is not defined in proto descriptor');
      process.exit(1);
    }

    const client = new paymentService(url, grpc.credentials.createInsecure());

    const request: PaymentRequest = {
      amount: 1000,
      currency: 'USD',
      email: 'abc@gmail.com',
      // connector: 'ADYEN', // TODO: move to headers
      // auth_creds: { signature_key: { api_key: '', key1: '', api_secret: '' } }, // TODO: move to headers
      payment_method: 'CARD',
      payment_method_data: { card: { card_number: '4111111111111111', card_exp_month: '03', card_exp_year: '2030', card_cvc: '737' } },
      address: { billing: {phone: { number: 1234567890, country_code: "+1" }, email: "abc@gmail.com" }},
      auth_type: 'THREE_DS',
      connector_request_reference_id: 'ref_12345',
      enrolled_for_3ds: true,
      request_incremental_authorization: false,
      minor_amount: 1000,
      connector_customer: 'cus_1233',
      browser_info:{},
      return_url: 'www.google.com'
    };
    const metadata = new grpc.Metadata();
    metadata.add('x-connector', 'adyen');
    metadata.add('x-auth', 'body-key');
    if (process.env.API_KEY && process.env.KEY1) {
      metadata.add('x-api-key', process.env.API_KEY);
      metadata.add('x-key1', process.env.KEY1);
    } else {
      logger.error('API_KEY or KEY1 is not defined in environment variables');
      process.exit(1);
    }
    logger.info('Sending PaymentAuthorize request...');
    client.PaymentAuthorize(request, metadata, (error: grpc.ServiceError | null, response: any) => {
      if (error) {
        logger.error(`RPC error: ${error.code}: ${error.details}`);
        return;
      }
      logger.info(`Response: ${JSON.stringify(response)}`);
    });
  } catch (error: any) {
    logger.error(`Error: ${error.message}`);
    if (error.stack) {
      logger.debug(`Stack: ${error.stack}`);
    }
  }
}

main().catch((err) => {
  logger.error(`Uncaught error: ${err.message}`);
  process.exit(1);
});
