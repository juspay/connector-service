---
paths:
  - backend/connector-integration/src/connectors/**/*.rs
---
# Transformer Patterns

## Request Transformer Structure

```rust
#[derive(Debug, Serialize)]
pub struct {ConnectorName}AuthorizeRequest<T> {
    pub amount: MinorUnit,           // Use amount converter
    pub currency: String,
    pub reference: String,           // From router_data
    pub payment_method: {ConnectorName}PaymentMethod<T>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for {ConnectorName}AuthorizeRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(router_data: &...) -> Result<Self, Self::Error> {
        let payment_method = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => {ConnectorName}PaymentMethod::Card(...),
            _ => return Err(ConnectorError::NotImplemented("...".into()).into()),
        };

        Ok(Self {
            amount: router_data.request.amount,
            currency: router_data.request.currency.to_string(),
            reference: router_data.connector_request_reference_id.clone(),  // CRITICAL
            payment_method,
        })
    }
}
```

## Response Transformer Structure

```rust
#[derive(Debug, Deserialize)]
pub struct {ConnectorName}AuthorizeResponse {
    pub id: String,
    pub status: {ConnectorName}PaymentStatus,
    pub amount: Option<i64>,
}

impl TryFrom<ResponseRouterData<{ConnectorName}AuthorizeResponse, ...>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    fn try_from(item: ...) -> Result<Self, Self::Error> {
        let status = match item.response.status {
            {ConnectorName}PaymentStatus::Succeeded => enums::AttemptStatus::Charged,
            {ConnectorName}PaymentStatus::Pending => enums::AttemptStatus::Pending,
            {ConnectorName}PaymentStatus::Failed => enums::AttemptStatus::Failure,
        };

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                connector_response_reference_id: Some(item.response.id),
                // ...
            }),
            ..item.router_data.clone()
        })
    }
}
```

## Auth Type Pattern

```rust
#[derive(Debug)]
pub struct {ConnectorName}AuthType {
    pub api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for {ConnectorName}AuthType {
    type Error = ConnectorError;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.clone(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType),
        }
    }
}
```

## Error Response Pattern

```rust
#[derive(Debug, Deserialize, Default)]
pub struct {ConnectorName}ErrorResponse {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_description: Option<String>,
}
```
