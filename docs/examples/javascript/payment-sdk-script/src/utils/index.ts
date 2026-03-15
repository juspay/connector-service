import { types } from "hs-playlib";
export const parseConnector = (connectorName: string): types.Connector | null => {
    const mapping: { [key: string]: types.Connector } = {
        "paypal": types.Connector.PAYPAL,
        "stripe": types.Connector.STRIPE,
        "worldpay": types.Connector.WORLDPAY,
    };
    return mapping[connectorName.toLowerCase()] || null;
}