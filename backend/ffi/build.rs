use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    if env::var("CARGO_FEATURE_NAPI").is_ok() {
        napi_build::setup();
        // generate_napi_types();
    }
}

fn generate_napi_types() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let proto_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../grpc-api-types/proto");

    let bridge_generator = g2h::BridgeGenerator::with_tonic_build()
        .with_string_enums()
        .file_descriptor_set_path(out_dir.join("connector_ffi_service_descriptor.bin"));

    let mut config = prost_build::Config::new();

    // External type mappings
    // config.extern_path(".ucs.v2.CardNumberType", "::i64");
    // config.extern_path(".ucs.v2.NetworkTokenType", "::i64");
    config.extern_path(".ucs.v2.SecretString", "::String");

    let _ = bridge_generator.compile_protos_with_config(
        config,
        &[
            "proto/services.proto",
            "proto/health_check.proto",
            "proto/payment.proto",
            "proto/payment_methods.proto",
        ],
        &[proto_dir.to_str().unwrap()],
    );

    post_process_generated_files(&out_dir);
}

fn post_process_generated_files(out_dir: &PathBuf) {
    if !out_dir.exists() {
        return;
    }

    let entries = match fs::read_dir(out_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rewritten = rewrite_file(&content);

        if rewritten != content {
            let _ = fs::write(&path, rewritten);
            println!("cargo:warning=Applied FFI + napi to {}", path.display());
        }
    }
}

fn rewrite_file(content: &str) -> String {
    let mut output = String::new();

    for line in content.lines() {
        if let Some(struct_name) = extract_struct_name(line) {
            output.push_str("#[napi_derive::napi(object)]\n");
            output.push_str(&line.replace(
                &format!("pub struct {}", struct_name),
                &format!("pub struct FFI_{}", struct_name),
            ));
            output.push('\n');
        } else {
            output.push_str(&rewrite_type_references(line));
            output.push('\n');
        }
    }

    output
}

fn extract_struct_name(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.starts_with("pub struct ") {
        line.split_whitespace().nth(2)
    } else {
        None
    }
}

fn rewrite_type_references(line: &str) -> String {
    let mut out = String::new();
    let mut token = String::new();

    for ch in line.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            token.push(ch);
        } else {
            out.push_str(&rewrite_token(&token));
            token.clear();
            out.push(ch);
        }
    }

    out.push_str(&rewrite_token(&token));
    out
}

fn rewrite_token(token: &str) -> String {
    if token.is_empty() {
        return String::new();
    }

    // JS-safe numeric conversions (CRITICAL FIX)
    match token {
        "u64" | "usize" => return "i64".to_string(),

        // Allowed NAPI-compatible types
        "i64" | "f64" | "bool" | "String" | "Vec" | "Option" | "Result" | "Box" | "serde"
        | "prost" | "std" => return token.to_string(),

        _ => {}
    }

    // Already rewritten
    if token.starts_with("FFI_") {
        return token.to_string();
    }

    // Rename PascalCase identifiers (proto structs)
    if token
        .chars()
        .next()
        .map(|c| c.is_uppercase())
        .unwrap_or(false)
    {
        format!("FFI_{}", token)
    } else {
        token.to_string()
    }
}
