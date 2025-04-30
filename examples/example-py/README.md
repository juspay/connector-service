# Payment Service Python Client

This is a Python implementation of a client for interacting with a gRPC Payment Service.

## Prerequisites

- [Python](https://www.python.org/downloads/) 3.6 or higher
- pip (Python package manager)

## Project Structure

```
payment-client-python/
├── Makefile        # Contains commands for code generation and setup
├── main.py         # Main application code
└── generated/      # Directory for generated gRPC code (created during setup)
```

## Setup

1. Install the required dependencies:

```bash
make install-deps
```

This will install the gRPC Python packages needed for this project.

2. Generate the Python code from the proto files:

```bash
make generate
```

This command will:
- Create a `generated` directory
- Generate Python code from the proto files in the specified directory
- Create an `__init__.py` file to make the generated code importable

## Running the Application

To run the application, use:

```bash
python main.py <url>
```

Replace `<url>` with the actual URL of your Payment Service. For example:

```bash
python main.py localhost:50051
```

## Application Behavior

The application:

1. Connects to the specified gRPC Payment Service
2. Creates a payment authorization request with test credit card data
3. Sends the request to the service
4. Prints the response

## Authentication

**Important:** To get actual responses from the payment service, you need to replace the empty authentication values in the code:

```python
signature_key = SignatureKey(
    api_key="",      # Add your API key here
    key1="",         # Add your key1 here
    api_secret=""    # Add your API secret here
)
```

## Cleaning Up

To remove the generated code:

```bash
make clean
```

## Troubleshooting

- If you encounter import errors, make sure you've run `make generate` to create the necessary Python files
- Check that the proto file path in the Makefile is correct
- Ensure your gRPC server is running at the specified URL
- Look at the logging output for detailed error messages

## Notes

- This example uses a test credit card number (4111111111111111)
- The payment request is configured for USD currency and 3DS authentication
- The client uses an insecure gRPC channel - for production, consider using a secure channel
