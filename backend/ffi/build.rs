use std::env;

fn main() {
    // Check if napi feature is enabled via environment variable
    // Cargo sets CARGO_FEATURE_<NAME> for each enabled feature
    if env::var("CARGO_FEATURE_NAPI").is_ok() {
        napi_build::setup();
    }
}
