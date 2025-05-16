# Payment Service Example

This is a simple Rust application that demonstrates how to interact with a gRPC Payment Service.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) (comes with Rust)

## Project Structure

```
example-rs/
├── Cargo.toml       # Project dependencies and metadata
├── Cargo.lock       # Lock file for dependencies
└── src/
    └── main.rs      # Main application code
```

## Dependencies

This project relies on:
- `tokio` - Asynchronous runtime for Rust
- `rust-grpc-client` - Custom library containing the Payment Service gRPC definitions

## Building the Application

To build the application, run:

```bash
cargo build
```

For a release build:

```bash
cargo build --release
```

## Running the Application

The application requires a URL for the gRPC Payment Service:

```bash
cargo run -- <url>
```

Replace `<url>` with the actual URL of your Payment Service. For example:

```bash
cargo run -- http://localhost:50051
```

## Application Behavior

The application:

1. Connects to the specified gRPC Payment Service
2. Creates a payment authorization request with test credit card data
3. Sends the request to the service
4. Prints the response

## Testing

You can verify the application is working correctly by ensuring that:

1. It connects to the specified service without errors
2. It successfully sends the payment authorization request
3. It receives and displays a valid response from the service

## Notes

- This example uses placeholder authentication credentials
- **Important:** To get actual responses from the payment service, you need to replace the empty authentication values in the code:
  ```rust
  auth_details: Some(payments::auth_type::AuthDetails::SignatureKey(
      payments::SignatureKey {
          api_key: "".to_string(),     // Add your API key here
          key1: "".to_string(),        // Add your key1 here
          api_secret: "".to_string()   // Add your API secret here
      },
  )),
  ```
- A test credit card number (4111111111111111) is used
- The payment request is configured for USD currency and 3DS authentication
