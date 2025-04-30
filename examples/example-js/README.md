# Payment Service TypeScript Client

This is a TypeScript implementation of a client for interacting with a gRPC Payment Service.

## Prerequisites

- [Node.js](https://nodejs.org/) (v12.10.0 or higher)
- npm (Node.js package manager)

## Project Structure

```
payment-client-typescript/
├── Makefile           # Contains commands for setup and cleanup
├── package.json       # Project configuration and dependencies
├── package-lock.json  # Locked versions of dependencies
├── tsconfig.json      # TypeScript configuration
└── src/
    ├── index.ts           # Main application code
    └── generate-proto.ts  # Code to validate proto files
```

## Setup

1. Install the required dependencies:

```bash
make install
```

Or manually with:

```bash
npm install
```

2. Build the TypeScript code:

```bash
npm run build
```

This will compile the TypeScript files to JavaScript in the `dist` directory.

## Validating Proto Files

You can validate the proto files using:

```bash
npm run generate
```

This will check if all proto files in the specified directory can be loaded correctly.

## Running the Application

To run the application, use:

```bash
npm start -- <url>
```

Or directly with Node:

```bash
node dist/index.js <url>
```

Replace `<url>` with the actual URL of your Payment Service. For example:

```bash
node dist/index.js localhost:50051
```

## Application Behavior

The application:

1. Connects to the specified gRPC Payment Service
2. Creates a payment authorization request with test credit card data
3. Sends the request to the service
4. Prints the response

## Authentication

**Important:** To get actual responses from the payment service, you need to replace the empty authentication values in the code:

```typescript
auth_creds: { 
  signature_key: { 
    api_key: '',      // Add your API key here
    key1: '',         // Add your key1 here
    api_secret: ''    // Add your API secret here
  } 
},
```

## Cleaning Up

To remove the installed dependencies:

```bash
make clean
```

To remove the compiled code:

```bash
npm run clean
```

## Troubleshooting

- If you encounter import errors, ensure you've run `npm install` and `npm run build`
- Check that the proto file path in your code is correct
- Ensure your gRPC server is running at the specified URL
- Look at the logging output for detailed error messages

## Notes

- This client uses Winston for logging to provide detailed information during execution
- The implementation uses dynamic loading of protocol buffers with `@grpc/proto-loader`
- The client uses an insecure gRPC channel - for production, consider using a secure channel
- A test credit card number (4111111111111111) is used for demonstration purposes
- The payment request is configured for USD currency and 3DS authentication
