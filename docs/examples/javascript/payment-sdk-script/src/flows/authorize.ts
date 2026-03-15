import { PaymentClient, types } from "hs-playlib";
import { logger } from "../utils/logger";

export const authorize = async (
    connectorConfig: types.ConnectorConfig,
    amount: types.Money,
    paymentMethod: types.PaymentMethod
): Promise<types.PaymentServiceAuthorizeResponse> => {
    // Create a child logger with flow context
    const flowLogger = logger.child({
        flow: 'authorize',
        connector: types.Connector[connectorConfig.connector],
        transactionId: `txn_${Date.now()}`
    });

    try {
        const authorizeRequest: types.PaymentServiceAuthorizeRequest = {
            merchantTransactionId: `txn_${Date.now()}`,
            amount,
            paymentMethod,
            authType: types.AuthenticationType.NO_THREE_DS,
            address: {},
            orderDetails: [],
            connectorFeatureData: {
                value: "{ \"merchant_name\": \"Test Merchant\" }"
            }
        };

        // Log the authorize request with structured data
        flowLogger.info('Authorize request prepared', {
            request: authorizeRequest,
            amount: amount.minorAmount,
            currency: types.Currency[amount.currency]
        });

        const paymentClient = new PaymentClient(connectorConfig);
        const authorizeResponse = await paymentClient.authorize(authorizeRequest);

        flowLogger.info('Authorize request completed', {
            status: types.PaymentStatus[authorizeResponse.status],
            connectorTransactionId: authorizeResponse.connectorTransactionId
        });

        return authorizeResponse;
    } catch (error) {
        flowLogger.error('Authorize request failed', error);
        throw error;
    }
}
