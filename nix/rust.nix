{ inputs, ... }:
{
  debug = true;
  perSystem = { config, self', inputs', pkgs, system, ... }:
    let
      craneLib = inputs.rust-flake.lib.${system}.craneLib;
      commonArgs = {
        src = craneLib.cleanCargoSource (craneLib.path ../.);
        strictDeps = true;
        buildInputs = with pkgs; [
          openssl
          pkg-config
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          pkgs.darwin.apple_sdk.frameworks.CoreFoundation
          pkgs.darwin.apple_sdk.frameworks.Security
        ];
        nativeBuildInputs = with pkgs; [
          pkg-config
          protobuf
          buf
        ];
      };
      commonClippyArgs = commonArgs // {
        cargoClippyExtraArgs = "--all-targets -- --deny warnings";
      };
    in
    {
      rust-project = {
        craneLib = craneLib;
        src = craneLib.cleanCargoSource (craneLib.path ../.);
        crane = {
          args = commonArgs;
          clippyExtraArgs = "--all-targets -- --deny warnings";
        };
        
        localPackages = {
          grpc-api-types = {
            crane.args = commonArgs // {
              pname = "grpc-api-types";
              cargoExtraArgs = "-p grpc-api-types";
            };
          };
          
          connector-integration = {
            crane.args = commonArgs // {
              pname = "connector-integration"; 
              cargoExtraArgs = "-p connector-integration";
            };
          };
          
          external-services = {
            crane.args = commonArgs // {
              pname = "external-services";
              cargoExtraArgs = "-p external-services";
            };
          };
          
          grpc-server = {
            crane.args = commonArgs // {
              pname = "grpc-server";
              cargoExtraArgs = "-p grpc-server";
            };
            meta.mainProgram = "grpc-server";
          };
          
          rust-grpc-client = {
            crane.args = commonArgs // {
              pname = "rust-grpc-client";
              cargoExtraArgs = "-p rust-grpc-client";
            };
          };
          
          common-enums = {
            crane.args = commonArgs // {
              pname = "common-enums";
              cargoExtraArgs = "-p common_enums";
            };
          };
          
          common-utils = {
            crane.args = commonArgs // {
              pname = "common-utils";
              cargoExtraArgs = "-p common_utils";
            };
          };
          
          interfaces = {
            crane.args = commonArgs // {
              pname = "interfaces";
              cargoExtraArgs = "-p interfaces";
            };
          };
          
          domain-types = {
            crane.args = commonArgs // {
              pname = "domain-types";
              cargoExtraArgs = "-p domain_types";
            };
          };
          
          cards = {
            crane.args = commonArgs // {
              pname = "cards";
              cargoExtraArgs = "-p cards";
            };
          };
        };
      };
    };
}
