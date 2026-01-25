//! Build script for UniFFI binding generation.
//!
//! This script generates the Rust scaffolding from the UDL file.

fn main() {
    uniffi::generate_scaffolding("src/connector_ffi.udl").expect("Failed to generate scaffolding");
}
