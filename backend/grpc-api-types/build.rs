use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    let generator = tonic_build::configure().service_generator();
    let web_generator = g2h::BridgeGenerator::new(generator);

    // Configure validation-enabled builder with service generation
    let mut config = prost_build::Config::new();
    config
        .service_generator(Box::new(web_generator))
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[allow(clippy::large_enum_variant)]");

    prost_validate_build::Builder::new()
        .file_descriptor_set_path(out_dir.join("connector_service_descriptor.bin"))
        .compile_protos_with_config(
            config,
            &[
                "proto/services.proto",
                "proto/health_check.proto",
                "proto/payment.proto",
                "proto/payment_methods.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
