import { MerchantAuthenticationClient, PaymentClient, types } from "hs-playlib";
import { logger } from "../utils/logger";

export const accessTokenAndAuthorize = async (
    connectorConfig: types.ConnectorConfig,
    amount: types.Money,
    paymentMethod: types.PaymentMethod
): Promise<types.PaymentServiceAuthorizeResponse> => {
    // Create a child logger with flow context
    const flowLogger = logger.child({
        flow: 'accessTokenAndAuthorize',
        connector: types.Connector[connectorConfig.connector],
        transactionId: `txn_${Date.now()}`
    });

    try {
        const authClient = new MerchantAuthenticationClient(connectorConfig);

        const accessTokenRequest: types.MerchantAuthenticationServiceCreateAccessTokenRequest = {
            merchantAccessTokenId: "access_token_test_" + Date.now(),
            connector: connectorConfig.connector,
            testMode: true,
        };

        // Log the access token request with structured data
        flowLogger.info('Creating access token', {
            merchantAccessTokenId: accessTokenRequest.merchantAccessTokenId,
            connector: types.Connector[accessTokenRequest.connector],
            testMode: accessTokenRequest.testMode
        });

        const tokenResponse: types.MerchantAuthenticationServiceCreateAccessTokenResponse = await authClient.createAccessToken(accessTokenRequest);
        const accessTokenValue = tokenResponse.accessToken?.value;
        const tokenTypeValue = tokenResponse.tokenType ?? "Bearer";

        flowLogger.info('Access token received', {
            tokenType: tokenTypeValue,
            tokenPreview: accessTokenValue ? `${accessTokenValue.substring(0, 10)}...` : undefined
        });

        const authorizeRequest: types.PaymentServiceAuthorizeRequest = {
            merchantTransactionId: `txn_${Date.now()}`,
            amount,
            paymentMethod,
            authType: types.AuthenticationType.NO_THREE_DS,
            state: {
                accessToken: {
                    token: { value: accessTokenValue },
                    tokenType: tokenTypeValue
                },
            },
            address: {},
            orderDetails: [],
        };

        // Log the authorize request with structured data
        flowLogger.info('Authorize request prepared', {
            merchantTransactionId: authorizeRequest.merchantTransactionId,
            amount: amount.minorAmount,
            currency: types.Currency[amount.currency],
            authType: types.AuthenticationType[authorizeRequest.authType]
        });

        const paymentClient = new PaymentClient(connectorConfig);
        const authorizeResponse = await paymentClient.authorize(authorizeRequest);

        flowLogger.info('Authorize request completed', {
            status: types.PaymentStatus[authorizeResponse.status],
            connectorTransactionId: authorizeResponse.connectorTransactionId
        });

        return authorizeResponse;
    } catch (error) {
        flowLogger.error('Access token and authorize flow failed', error);
        throw error;
    }
}
