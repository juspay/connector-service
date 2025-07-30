use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // Create the bridge generator and get the underlying prost config
    let bridge_generator = g2h::BridgeGenerator::with_tonic_build()
        .with_string_enums()
        .file_descriptor_set_path(out_dir.join("connector_service_descriptor.bin"));

    // Build the prost config so we can customize it
    let mut config = bridge_generator.build_prost_config();

    // Map CardNumberType to your custom CardNumber type
    // Adjust the path based on your proto package structure
    config.extern_path(".ucs.v2.CardNumberType", "::cards::CardNumber");

    // If your CardNumberType is in a specific package, use the full path:
    // config.extern_path(".your_package.CardNumberType", "crate::CardNumber");
    // For example:
    // config.extern_path(".payment.v1.CardNumberType", "crate::CardNumber");

    // Compile the protos with the custom type mapping
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
