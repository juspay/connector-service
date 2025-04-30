import * as fs from 'fs';
import * as path from 'path';
import * as protoLoader from '@grpc/proto-loader';

const PROTO_DIR = path.resolve('../../backend/grpc-api-types/proto');

if (!fs.existsSync(PROTO_DIR)) {
  console.error(`Proto directory not found: ${PROTO_DIR}`);
  process.exit(1);
}

const protoFiles = fs
  .readdirSync(PROTO_DIR)
  .filter((file) => file.endsWith('.proto'))
  .map((file) => path.join(PROTO_DIR, file));

if (protoFiles.length === 0) {
  console.error(`No .proto files found in ${PROTO_DIR}`);
  process.exit(1);
}

console.log('Validating proto files...');
protoFiles.forEach((protoFile) => {
  try {
    protoLoader.loadSync(protoFile, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });
    console.log(`✅ Successfully validated ${path.basename(protoFile)}`);
  } catch (error: any) {
    console.error(`❌ Error validating ${path.basename(protoFile)}: ${error.message}`);
    process.exit(1);
  }
});
console.log('All proto files validated successfully!');
