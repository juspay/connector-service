# Installation

Start by installing the library for the programming language of your choice.

## Install library

{% tabs %}

{% tab title="Node.js" %}

{% code title="Terminal" overflow="wrap" %}
```bash
npm install @juspay/connector-service-node
```
{% endcode %}

{% code title="index.js" overflow="wrap" lineNumbers="true" %}
```javascript
const { ConnectorClient } = require('@juspay/connector-service-node');

const client = new ConnectorClient({
    connectors: {
        stripe: { apiKey: process.env.STRIPE_API_KEY }
    }
});
```
{% endcode %}

{% endtab %}

{% tab title="Python" %}

{% code title="Terminal" overflow="wrap" %}
```bash
pip install connector-service-python
```
{% endcode %}

{% code title="main.py" overflow="wrap" lineNumbers="true" %}
```python
from connector_service import ConnectorClient

client = ConnectorClient(
    connectors={
        "stripe": {"api_key": os.environ["STRIPE_API_KEY"]}
    }
)
```
{% endcode %}

{% endtab %}

{% tab title="Java" %}

{% code title="pom.xml" overflow="wrap" %}
```xml
<dependency>
    <groupId>com.juspay</groupId>
    <artifactId>connector-service-java</artifactId>
    <version>1.2.0</version>
</dependency>
```
{% endcode %}

{% code title="Main.java" overflow="wrap" lineNumbers="true" %}
```java
ConnectorClient client = ConnectorClient.builder()
    .connector("stripe", StripeConfig.builder()
        .apiKey(System.getenv("STRIPE_API_KEY"))
        .build())
    .build();
```
{% endcode %}

{% endtab %}

{% tab title="PHP" %}

{% code title="Terminal" overflow="wrap" %}
```bash
composer require juspay/connector-service-php
```
{% endcode %}

{% code title="index.php" overflow="wrap" lineNumbers="true" %}
```php
<?php
require_once 'vendor/autoload.php';

use ConnectorService\ConnectorClient;

$client = new ConnectorClient([
    'connectors' => [
        'stripe' => ['api_key' => $_ENV['STRIPE_API_KEY']]
    ]
]);
```
{% endcode %}

{% endtab %}

{% endtabs %}

That would be all. The SDK handles native library loading automatically. Start building in the [Quick Start](./quick-start.md).

## Minimum version supported

The prerequisites are:
- **Node.js**: 16+ (FFI bindings require native compilation)
- **Python**: 3.9+ (uses `ctypes` for FFI)
- **Java**: 11+ (uses JNI bindings)
- **PHP**: 8.0+ (uses FFI extension)
