# Payment Service Haskell Client

This is a Haskell application that demonstrates how to interact with a gRPC Payment Service.

## Prerequisites

- [GHCup](https://www.haskell.org/ghcup/) - The Haskell toolchain installer
- GHC version 9.6.6 (can be installed via GHCup)
- Latest version of Cabal (can be installed via GHCup)
- [Proto-lens](https://github.com/google/proto-lens) installed for GHC 9.6.6

### Installing Prerequisites

1. Install GHCup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
```

2. Install GHC 9.6.6:
```bash
ghcup install ghc 9.6.6
ghcup set ghc 9.6.6
```

3. Install the latest Cabal:
```bash
ghcup install cabal latest
ghcup set cabal latest
```

4. Install proto-lens tools:
```bash
cabal install proto-lens-protoc
```
5. Command to convert Proto file to Haskell file:
```bash
 protoc \
  --plugin=protoc-gen-haskell=$(which proto-lens-protoc) \
  --proto_path=proto \
  --haskell_out=src \
  proto/payment.proto
```
## Project Structure

```
example-hs-grpc/
├── cabal.project      # Project configuration
├── example-hs-grpc.cabal   # Package description and dependencies
├── proto/             # Protocol buffer definitions
│   └── payment.proto  # Payment service proto definition
├── app/               # Application code
│   └── Client.hs      # Main client implementation
└── src/               # Library code
    └── Generated proto modules (auto-generated)
```

## Dependencies

This project relies on:
- `grapesy` - A lightweight gRPC client and server library for Haskell
- `proto-lens` - Protocol Buffers support for Haskell
- `lens-family` - Type-safe, lightweight Haskell lenses
- `text` handles the string/text processing
- `network` manages the actual network connections
- Various standard libraries for Haskell

## Building the Application

To build the application, run:

```bash
cabal update
cabal build
```

For a development build with optimization disabled:

```bash
cabal build --ghc-options="-O0"
```

## Running the Application

The application requires the address, port, and payment service details. You can run it using:

```bash
cabal run grpc_client -- <address> <paymentService>
```

Replace `<address>` with the hostname or IP address of your payment service, `<port>` with the port number, and `<paymentService>` with payment service name

For example:

```bash
cabal run grpc_client http://localhost:5051 "sync"
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
- **Important:** To get actual responses from the payment service, you need to replace the empty authentication values in the code
- A test credit card number is used for demonstration purposes
- The payment request is configured for USD currency

## Customizing the Authentication

To use with a real payment service, update the authentication details in the client code:

```haskell
authDetails = Just $ SignatureKey
  { _api_key = "<YOUR_API_KEY>"
  , _key1 = "<YOUR_KEY1>"
  , _api_secret = "<YOUR_API_SECRET>"
  }
```

## Troubleshooting

If you encounter issues:

1. Ensure GHC 9.6.6 is active: `ghc --version`
2. Verify proto-lens is installed properly
3. Check that the payment service is accessible at the specified address and port
4. Examine the cabal file to ensure all dependencies are properly specified