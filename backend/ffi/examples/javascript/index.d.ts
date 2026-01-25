/**
 * Type definitions for @connector-service/ffi
 */

export enum PaymentStatus {
  SUCCEEDED = 'succeeded',
  AUTHORIZED = 'authorized',
  PENDING = 'pending',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
  REQUIRES_ACTION = 'requires_action',
  UNKNOWN = 'unknown'
}

export interface CardPaymentMethod {
  type: 'card';
  number: string;
  exp_month: number;
  exp_year: number;
  cvc: string;
  holder_name?: string;
}

export interface WalletPaymentMethod {
  type: 'wallet';
  wallet_type: string;
  token: string;
}

export interface BankTransferPaymentMethod {
  type: 'banktransfer';
  bank_code?: string;
  account_number?: string;
}

export type PaymentMethodData = CardPaymentMethod | WalletPaymentMethod | BankTransferPaymentMethod;

export interface PaymentMethodFactory {
  card(params: {
    number: string;
    expMonth: number;
    expYear: number;
    cvc: string;
    holderName?: string;
  }): CardPaymentMethod;

  wallet(walletType: string, token: string): WalletPaymentMethod;

  bankTransfer(params?: {
    bankCode?: string;
    accountNumber?: string;
  }): BankTransferPaymentMethod;
}

export const PaymentMethod: PaymentMethodFactory;

export class PaymentResult {
  success: boolean;
  status: PaymentStatus;
  transactionId: string | null;
  amount: number | null;
  currency: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  redirectUrl: string | null;
  rawResponse: Record<string, any> | null;
  httpStatusCode: number | null;

  static error(code: string, message: string): PaymentResult;
}

export class ConnectorInfo {
  name: string;
  displayName: string;
  baseUrl: string;
  authType: string;
  authFields: string[];
  supportedFlows: string[];
  supportedCurrencies: string[];
  bodyFormat: string;
}

export interface AuthCredentials {
  api_key?: string;
  api_secret?: string;
  merchant_id?: string;
  [key: string]: string | undefined;
}

export interface ConnectorConfig {
  base_url?: string;
  [key: string]: any;
}

export interface HttpClientOptions {
  timeout?: number;
  rejectUnauthorized?: boolean;
}

export class HttpClient {
  constructor(options?: HttpClientOptions);

  request(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: string
  ): Promise<{
    statusCode: number;
    headers: Record<string, string>;
    body: string;
  }>;
}

export interface ConnectorClientOptions {
  config?: ConnectorConfig;
  httpClient?: HttpClient;
  libraryPath?: string;
}

export interface AuthorizeParams {
  amount: number;
  currency: string;
  paymentMethod?: PaymentMethodData;
  referenceId?: string;
  metadata?: Record<string, any>;
}

export interface CaptureParams {
  transactionId: string;
  amount?: number;
  currency?: string;
}

export interface VoidParams {
  transactionId: string;
  currency?: string;
}

export interface RefundParams {
  transactionId: string;
  amount: number;
  currency?: string;
  reason?: string;
}

export interface SyncParams {
  transactionId: string;
  currency?: string;
}

export class ConnectorClient {
  constructor(
    connector: string,
    auth: AuthCredentials,
    options?: ConnectorClientOptions
  );

  readonly info: ConnectorInfo;

  authorize(params: AuthorizeParams): Promise<PaymentResult>;
  capture(params: CaptureParams): Promise<PaymentResult>;
  void(params: VoidParams): Promise<PaymentResult>;
  refund(params: RefundParams): Promise<PaymentResult>;
  sync(params: SyncParams): Promise<PaymentResult>;
}

export function listConnectors(): string[];
export function listFlows(): string[];
export function getConnectorInfo(connector: string): ConnectorInfo | null;
export function version(): string;

// Low-level FFI access
export class NativeFFI {
  constructor(libraryPath?: string);
  transformRequest(request: Record<string, any>): Record<string, any>;
  transformResponse(response: Record<string, any>): Record<string, any>;
  listConnectors(): string[];
  listFlows(): string[];
  getConnectorInfo(connector: string): Record<string, any>;
  version(): string;
}

export class PureJSFFI {
  transformRequest(request: Record<string, any>): Record<string, any>;
  transformResponse(response: Record<string, any>): Record<string, any>;
  listConnectors(): string[];
  listFlows(): string[];
  getConnectorInfo(connector: string): Record<string, any>;
  version(): string;
}

export function getFFI(libraryPath?: string): NativeFFI | PureJSFFI;
