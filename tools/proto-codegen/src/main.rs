use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;

#[derive(Parser, Debug)]
#[command(name = "proto-codegen")]
#[command(about = "Generate pre-compiled gRPC client code from proto files", long_about = None)]
struct Args {
    /// Output directory for generated SDK
    #[arg(short, long)]
    output: PathBuf,
    
    /// Clean output directory before generating
    #[arg(short, long, default_value_t = false)]
    clean: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Get the project root directory
    let manifest_dir = std::env::current_dir()
        .context("Failed to get current directory")?;
    
    // Find project root by looking for Cargo.toml with workspace
    let project_root = find_workspace_root(&manifest_dir)?;

    // Clean output directory if requested
    if args.clean && args.output.exists() {
        println!("Cleaning output directory: {:?}", args.output);
        std::fs::remove_dir_all(&args.output)
            .context("Failed to clean output directory")?;
    }
    
    // Create output directories
    let src_dir = args.output.join("src");
    let gen_dir = src_dir.join("gen");
    
    std::fs::create_dir_all(&gen_dir)
        .context("Failed to create gen directory")?;

    println!("Generating pre-compiled gRPC client SDK...");
    println!("Project root: {:?}", project_root);
    println!("Output directory: {:?}", args.output);

    // Create a temporary directory for proto compilation
    let temp_dir = TempDir::new()?;
    let temp_out_dir = temp_dir.path().to_path_buf();
    
    // Set up proto paths
    let proto_dir = project_root.join("backend/grpc-api-types/proto");
    
    // Configure tonic-build to generate only client code
    tonic_build::configure()
        .build_server(false)  // Don't generate server code
        .build_client(true)   // Only generate client code
        .out_dir(&temp_out_dir)
        .file_descriptor_set_path(temp_out_dir.join("connector_service_descriptor.bin"))
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[serde(rename_all = \"snake_case\")]")
        .compile(
            &[
                proto_dir.join("services.proto"),
                proto_dir.join("health_check.proto"),
                proto_dir.join("payment.proto"),
                proto_dir.join("payment_methods.proto"),
            ],
            &[proto_dir],
        )
        .context("Failed to compile proto files")?;
    
    println!("Proto compilation completed successfully!");
    
    // Copy generated files to the SDK
    for entry in fs::read_dir(&temp_out_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let source = entry.path();
        let dest = gen_dir.join(&file_name);
        
        fs::copy(&source, &dest)
            .with_context(|| format!("Failed to copy {:?} to {:?}", source, dest))?;
        
        println!("  Copied: {}", file_name.to_string_lossy());
    }
    
    // Create gen/mod.rs
    create_gen_mod_rs(&gen_dir)?;
    
    // Create Cargo.toml
    create_cargo_toml(&args.output)?;
    
    // Create lib.rs
    create_lib_rs(&src_dir)?;
    
    println!("\nPre-compiled SDK generated successfully!");
    println!("No build.rs needed - all code is pre-generated.");
    
    Ok(())
}

fn find_workspace_root(start_dir: &PathBuf) -> Result<PathBuf> {
    let mut current = start_dir.clone();
    
    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = fs::read_to_string(&cargo_toml)?;
            if content.contains("[workspace]") {
                return Ok(current);
            }
        }
        
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => return Ok(start_dir.clone()),
        }
    }
}

fn create_gen_mod_rs(gen_dir: &PathBuf) -> Result<()> {
    let mod_rs_content = r#"//! Generated code from proto files

#![allow(clippy::all)]
#![allow(warnings)]

pub const FILE_DESCRIPTOR_SET: &[u8] = 
    include_bytes!("connector_service_descriptor.bin");

pub mod payments {
    include!("ucs.v2.rs");
}

pub mod health_check {
    include!("grpc.health.v1.rs");
}
"#;

    fs::write(gen_dir.join("mod.rs"), mod_rs_content)
        .context("Failed to write gen/mod.rs")?;
    
    println!("Created gen/mod.rs");
    Ok(())
}

fn create_cargo_toml(output_dir: &PathBuf) -> Result<()> {
    let cargo_toml_content = r#"[package]
name = "connector-service-client"
version = "0.1.0"
edition = "2021"
description = "Pre-compiled gRPC client for Connector Service"
license = "MIT"

[dependencies]
tonic = "0.11"
prost = "0.12"
prost-types = "0.12"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[features]
default = []
"#;

    fs::write(output_dir.join("Cargo.toml"), cargo_toml_content)
        .context("Failed to write Cargo.toml")?;
    
    println!("Created Cargo.toml");
    Ok(())
}

fn create_lib_rs(src_dir: &PathBuf) -> Result<()> {
    let lib_rs_content = r#"//! Pre-compiled gRPC client for Connector Service
//! 
//! This crate provides a type-safe client for interacting with the Connector Service.
//! All code is pre-generated, no build-time proto compilation needed.

#![allow(clippy::large_enum_variant)]
#![allow(clippy::derive_partial_eq_without_eq)]

pub mod gen;

// Re-export commonly used types
pub use gen::payments::*;
pub use gen::health_check::*;

// Re-export tonic for convenience
pub use tonic;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::gen::payments::payment_service_client::PaymentServiceClient;
    pub use crate::gen::payments::refund_service_client::RefundServiceClient;
    pub use crate::gen::payments::dispute_service_client::DisputeServiceClient;
    pub use crate::gen::health_check::health_client::HealthClient;  
    pub use tonic::transport::{Channel, Endpoint};
}
"#;

    fs::write(src_dir.join("lib.rs"), lib_rs_content)
        .context("Failed to write lib.rs")?;
    
    println!("Created lib.rs");
    Ok(())
}