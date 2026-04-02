import os
import re
import json

def analyze_mappings(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()

    mappings = {}
    current_impl = None
    
    for i, line in enumerate(lines):
        # Identify the start of a ForeignTryFrom implementation
        # e.g., impl ForeignTryFrom<(PaymentServiceAuthorizeRequest, ...)> for PaymentFlowData
        impl_match = re.search(r'impl.*ForeignTryFrom<.*(PaymentService\w+Request|RefundService\w+Request|DisputeService\w+Request|MerchantAuthenticationService\w+Request|PaymentMethodService\w+Request).*>\s+for\s+(\w+)', line)
        if impl_match:
            current_impl = impl_match.group(1).strip()
            if current_impl not in mappings:
                mappings[current_impl] = {"target": impl_match.group(2), "fields": {}}
            continue

        if current_impl:
            # Look for field assignments within the block
            # Matches: field_name: value.proto_field_name
            field_match = re.search(r'(\w+)\s*:\s*value\.(\w+)', line)
            if field_match:
                mappings[current_impl]["fields"][field_match.group(1)] = field_match.group(2)
            
            # Matches: let field_name = value.proto_field_name
            let_match = re.search(r'let\s+(\w+)\s*=\s*value\.(\w+)', line)
            if let_match:
                mappings[current_impl]["fields"][let_match.group(1)] = let_match.group(2)

            # End of block (rudimentary check for '}')
            if line.strip() == "}":
                # We don't reset immediately because some impls are nested, 
                # but for types.rs this usually works for top-level blocks.
                pass
    return mappings

def analyze_connectors(base_path):
    connector_usage = {}
    
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.endswith(".rs"):
                path = os.path.join(root, file)
                connector_name = os.path.basename(root) if os.path.basename(root) != 'connectors' else file.replace(".rs", "")
                
                if connector_name not in connector_usage:
                    connector_usage[connector_name] = {"fields": set(), "structs": []}

                with open(path, 'r') as f:
                    content = f.read()
                    
                    # Search for domain field access
                    if "connector_meta_data" in content:
                        connector_usage[connector_name]["fields"].add("connector_meta_data (Underscore)")
                    if "connector_metadata" in content:
                        connector_usage[connector_name]["fields"].add("connector_metadata (No Underscore)")
                    if "metadata" in content:
                        connector_usage[connector_name]["fields"].add("metadata")

                    # Extract metadata structs to see JSON structure
                    struct_matches = re.findall(r'pub struct (\w+Meta(?:data)?) \{([\s\S]*?)\}', content)
                    for struct_name, fields in struct_matches:
                        clean_fields = [f.strip() for f in fields.split("\n") if ":" in f]
                        connector_usage[connector_name]["structs"].append({struct_name: clean_fields})

    return connector_usage

def main():
    print("--- UCS METADATA DETERMINISTIC ANALYSIS ---")
    
    # 1. Analyze Mappings in types.rs
    types_path = "backend/domain_types/src/types.rs"
    mappings = analyze_mappings(types_path)
    
    print("\n[PART 1: DOMAIN MAPPINGS (Proto -> Domain)]")
    for req, data in mappings.items():
        if "connector_meta" in str(data["fields"]) or "metadata" in str(data["fields"]):
            print(f"\nRequest: {req} -> {data['target']}")
            for target_f, proto_f in data["fields"].items():
                if "metadata" in target_f or "connector_meta" in target_f:
                    print(f"  - Domain.{target_f} = Proto.{proto_f}")

    # 2. Analyze Connector Usage
    connectors_path = "backend/connector-integration/src/connectors/"
    usage = analyze_connectors(connectors_path)
    
    print("\n\n[PART 2: CONNECTOR FIELD USAGE]")
    for conn, data in usage.items():
        if data["fields"]:
            print(f"\nConnector: {conn}")
            print(f"  - Uses Domain Fields: {', '.join(data['fields'])}")
            if data["structs"]:
                print(f"  - Expected JSON Structures:")
                for s in data["structs"]:
                    for name, fields in s.items():
                        print(f"    * {name}: {fields}")

if __name__ == "__main__":
    main()
