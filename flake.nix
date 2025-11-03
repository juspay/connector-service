{
  description = "Rust development environment";

  # Inputs are external dependencies/sources your flake depends on
  inputs = {
    # nixpkgs contains all the packages (like a package repository)
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    
    # flake-utils provides helper functions for multi-system support
    flake-utils.url = "github:numtide/flake-utils";
    
    # rust-overlay provides up-to-date Rust toolchains
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  # Outputs define what your flake provides
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Create a package set with rust-overlay applied
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Define the Rust toolchain you want to use
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" "rust-analyzer" ];
        };

      in
      {
        # Development shell - what you get when you run `nix develop`
        devShells.default = pkgs.mkShell {
          # Build inputs are available in the shell environment
          buildInputs = with pkgs; [
            rustToolchain
            
            # Additional development tools
            cargo-watch    # Auto-rebuild on file changes
            cargo-edit     # Commands like cargo add, cargo rm
            cargo-audit    # Security vulnerability scanner
            
            # System dependencies that some Rust crates might need
            pkg-config
            openssl

            # protobuf stuff
            protoc-gen-rust-grpc
            grpc-tools
            grpcurl
            
            # Optional: database tools if you're building web apps
            # postgresql
            # sqlite
            
            # Optional: if you need to link against system libraries
            # gcc
            # libiconv  # On macOS
          ];

          # Environment variables
          shellHook = ''
            echo "🦀 Rust development environment loaded!"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
            
            # Optional: set environment variables
            export RUST_BACKTRACE=1
            export RUST_LOG=debug
          '';
        };
      }
    );
}
