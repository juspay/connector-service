export interface ConnectorPaymentMethod {
  category: string;
  method: string;
  status: "supported" | "not_supported" | "not_implemented" | "error";
}

export interface ConnectorStats {
  total: number;
  supported: number;
  notImplemented: number;
  notSupported: number;
  error: number;
}

export interface Connector {
  name: string;
  filePath: string;
  paymentMethods: ConnectorPaymentMethod[];
  stats: ConnectorStats;
}

export interface NotImplementedItem {
  connector: string;
  category: string;
  method: string;
  filePath: string;
}
