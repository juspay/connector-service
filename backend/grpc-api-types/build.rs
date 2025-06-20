use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    let generator = tonic_build::configure().service_generator();
    let web_generator = g2h::BridgeGenerator::new(generator);

    prost_build::Config::new()
        .service_generator(Box::new(web_generator))
        .file_descriptor_set_path(out_dir.join("connector_service_descriptor.bin"))
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
            &["proto/payment.proto", "proto/health_check.proto"],
            &["proto"],
        )?;

    Ok(())
}
