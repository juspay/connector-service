/**
 * TypeScript wrapper for connector-service-node-ffi
 * 
 * This module provides typed interfaces and convenient wrappers
 * for the native Rust FFI bindings.
 * 
 * Build the native binary first:
 *   cd backend/ffi && cargo build --release
 * 
 * Then run the build script to copy the binary to artifacts/:
 *   npm run build
 */

export * from './payment';