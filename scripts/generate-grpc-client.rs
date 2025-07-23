#!/usr/bin/env -S cargo +nightly -Zscript
//! ```cargo
//! [dependencies]
//! tonic-build = "0.13.0"
//! prost-build = "0.13.4"
//! heck = "0.5.0"
//! g2h = { git = "https://github.com/NishantJoshi00/g2h", branch = "fixing-response-serializing" }
//! ```

use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let script_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let project_root = script_dir.parent().unwrap();
    let proto_dir = project_root.join("backend/grpc-api-types/proto");
    let out_dir = project_root.join("sdk/rust-grpc-client/src/generated");
    
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&out_dir)?;
    
    println!("Generating gRPC client files...");
    println!("Proto directory: {:?}", proto_dir);
    println!("Output directory: {:?}", out_dir);
    
    // Configure and run code generation
    g2h::BridgeGenerator::with_tonic_build()
        .with_string_enums()
        .out_dir(&out_dir)
        .file_descriptor_set_path(out_dir.join("connector_service_descriptor.bin"))
        .compile_protos(
            &[
                proto_dir.join("services.proto").to_str().unwrap(),
                proto_dir.join("health_check.proto").to_str().unwrap(),
                proto_dir.join("payment.proto").to_str().unwrap(),
                proto_dir.join("payment_methods.proto").to_str().unwrap(),
            ],
            &[proto_dir.to_str().unwrap()],
        )?;
    
    // Create a mod.rs file to export the generated modules
    let mod_content = r#"#![allow(clippy::large_enum_variant)]
#![allow(clippy::uninlined_format_args)]

pub const FILE_DESCRIPTOR_SET: &[u8] = 
    include_bytes!("connector_service_descriptor.bin");

pub mod payments {
    include!("ucs.v2.rs");
}

pub mod health_check {
    include!("grpc.health.v1.rs");
}
"#;
    
    std::fs::write(out_dir.join("mod.rs"), mod_content)?;
    
    println!("Generated files successfully!");
    
    Ok(())
}