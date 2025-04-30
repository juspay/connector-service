// generate-proto.js
/**
 * Script to generate JavaScript code from proto files.
 * Unlike Python, Node.js doesn't need code generation ahead of time
 * as proto-loader dynamically loads the protobuf definitions.
 * 
 * This script can be used to validate proto files.
 */

const path = require('path');
const fs = require('fs');
const protoLoader = require('@grpc/proto-loader');

// Define path to proto files
const PROTO_DIR = '../../backend/grpc-api-types/proto';

// Check if proto directory exists
if (!fs.existsSync(PROTO_DIR)) {
  console.error(`Proto directory not found: ${PROTO_DIR}`);
  process.exit(1);
}

// Get all proto files
const protoFiles = fs.readdirSync(PROTO_DIR)
  .filter(file => file.endsWith('.proto'))
  .map(file => path.join(PROTO_DIR, file));

if (protoFiles.length === 0) {
  console.error(`No .proto files found in ${PROTO_DIR}`);
  process.exit(1);
}

console.log('Validating proto files...');

// Try to load each proto file to validate it
protoFiles.forEach(protoFile => {
  try {
    const packageDefinition = protoLoader.loadSync(protoFile, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true
    });
    
    console.log(`✅ Successfully validated ${path.basename(protoFile)}`);
  } catch (error) {
    console.error(`❌ Error validating ${path.basename(protoFile)}: ${error.message}`);
    process.exit(1);
  }
});

console.log('All proto files validated successfully!');
