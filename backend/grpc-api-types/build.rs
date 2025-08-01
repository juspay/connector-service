use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    let bridge_generator = g2h::BridgeGenerator::with_tonic_build()
        .with_string_enums()
        .file_descriptor_set_path(out_dir.join("connector_service_descriptor.bin"));

    let mut config = bridge_generator.build_prost_config();

    config.extern_path(".ucs.v2.CardNumberType", "::cards::CardNumber");

    config
        .file_descriptor_set_path(out_dir.join("connector_service_descriptor.bin"))
        .compile_protos(
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
