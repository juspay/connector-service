import os
import re

def get_mappings():
    path = "backend/domain_types/src/types.rs"
    with open(path, 'r') as f:
        content = f.read()

    # Split into ForeignTryFrom blocks more aggressively
    blocks = re.findall(r'impl.*ForeignTryFrom<([\s\S]+?)>[\s\S]+?for\s+(\w+)[\s\S]+?fn foreign_try_from\([\s\S]+?\{([\s\S]+?)\n    \}', content)
    
    report = {}
    for source, target, body in blocks:
        # Get the request name
        req_match = re.search(r'(PaymentService\w+Request|RefundService\w+Request|DisputeService\w+Request|MerchantAuthenticationService\w+Request|PaymentMethodService\w+Request)', source)
        if not req_match: continue
        req_name = req_match.group(1)
        
        # Initialize if new
        if req_name not in report:
            report[req_name] = {"Domain.connector_meta_data": "NOT MAPPED", "Domain.connector_metadata": "NOT MAPPED", "Domain.metadata": "NOT MAPPED"}

        # Precise line-by-line check within body
        for line in body.split('\n'):
            line = line.strip()
            
            # Check for direct struct initialization: field: value.proto_field
            if 'connector_meta_data' in line and 'value.' in line:
                m = re.search(r'connector_meta_data.*value\.(\w+)', line)
                if m: report[req_name]["Domain.connector_meta_data"] = m.group(1)
            
            if 'connector_metadata' in line and 'value.' in line:
                m = re.search(r'connector_metadata.*value\.(\w+)', line)
                if m: report[req_name]["Domain.connector_metadata"] = m.group(1)

            if 'metadata' in line and 'value.' in line and 'connector_meta' not in line:
                m = re.search(r'metadata.*value\.(\w+)', line)
                if m: report[req_name]["Domain.metadata"] = m.group(1)

            # Check for let bindings: let x = value.field
            if 'let connector_meta_data' in line and 'value.' in line:
                m = re.search(r'let\s+connector_meta_data\s*=\s*value\.(\w+)', line)
                if m: report[req_name]["Domain.connector_meta_data"] = m.group(1)

    return report

def get_connector_usage():
    base = "backend/connector-integration/src/connectors/"
    usage = {}
    for root, dirs, files in os.walk(base):
        for file in files:
            if file.endswith(".rs"):
                c_name = os.path.basename(root) if os.path.basename(root) != 'connectors' else file.replace(".rs", "")
                if c_name not in usage: usage[c_name] = {"und": False, "no_und": False, "meta": False}
                
                with open(os.path.join(root, file), 'r') as f:
                    text = f.read()
                    if "connector_meta_data" in text: usage[c_name]["und"] = True
                    if "connector_metadata" in text: usage[c_name]["no_und"] = True
                    if ".metadata" in text: usage[c_name]["meta"] = True
    return usage

def main():
    mappings = get_mappings()
    usage = get_connector_usage()

    print("# UCS METADATA GROUND TRUTH REPORT\n")
    print("## 1. Proto -> Domain Mappings")
    print("| Proto Request | Domain.connector_meta_data (Underscore) | Domain.connector_metadata (No Underscore) | Domain.metadata |")
    print("| :--- | :--- | :--- | :--- |")
    for req in sorted(mappings.keys()):
        f = mappings[req]
        print(f"| {req} | {f['Domain.connector_meta_data']} | {f['Domain.connector_metadata']} | {f['Domain.metadata']} |")

    print("\n## 2. Connector Usage")
    print("| Connector | Uses connector_meta_data (Underscore) | Uses connector_metadata (No Underscore) | Uses metadata |")
    print("| :--- | :---: | :---: | :---: |")
    for conn in sorted(usage.keys()):
        f = usage[conn]
        if f['und'] or f['no_und'] or f['meta']:
            print(f"| {conn} | {'✅' if f['und'] else '-'} | {'✅' if f['no_und'] else '-'} | {'✅' if f['meta'] else '-'} |")

if __name__ == "__main__":
    main()
