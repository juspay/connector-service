//! UniFFI binding generator binary.
//!
//! This binary wraps the `uniffi-bindgen` CLI tool for generating
//! language bindings from the compiled library.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin uniffi-bindgen -- generate \
//!     --library target/release/libconnector_ffi_uniffi.so \
//!     --language python \
//!     --out-dir bindings/python
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
