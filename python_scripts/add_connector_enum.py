#!/usr/bin/env python3
"""
Automates the first 6 steps of adding a new connector
as described in connector-service/memory-bank/connectorImplementationGuide.md.
"""

import sys
import re
from pathlib import Path

# --- Helpers ---

def pascal_to_snake(name: str) -> str:
    """Convert PascalCase -> snake_case"""
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()

def update_file(path: Path, transform_fn):
    """Read a file, transform its lines, and overwrite it"""
    lines = path.read_text().splitlines()
    new_lines = transform_fn(lines)
    path.write_text("\n".join(new_lines) + "\n")

# --- CLI Input ---

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <NewConnectorName>")
    print(f"Example: {sys.argv[0]} MyAwesomeConnector")
    sys.exit(1)

CONNECTOR_PASCAL = sys.argv[1]
CONNECTOR_SNAKE = pascal_to_snake(CONNECTOR_PASCAL)
CONNECTOR_UPPER_SNAKE = CONNECTOR_SNAKE.upper()

print(f"Automating connector enum addition for: {CONNECTOR_PASCAL}")
print(f"Snake case: {CONNECTOR_SNAKE}")
print(f"Upper snake case: {CONNECTOR_UPPER_SNAKE}")

# --- File paths ---
CONNECTOR_TYPES_RS = Path("backend/domain_types/src/connector_types.rs")
TYPES_RS = Path("backend/domain_types/src/types.rs")
INTEGRATION_TYPES_RS = Path("backend/connector-integration/src/types.rs")
CONNECTORS_RS = Path("backend/connector-integration/src/connectors.rs")

# --- Step 1: Add to ConnectorEnum ---
def step1(lines):
    out, in_enum = [], False
    for line in lines:
        if "pub enum ConnectorEnum {" in line:
            in_enum = True
        if in_enum and line.strip() == "}":
            out.append(f"    {CONNECTOR_PASCAL},")
            in_enum = False
        out.append(line)
    return out

print(f"Step 1: Adding '{CONNECTOR_PASCAL}' to ConnectorEnum in {CONNECTOR_TYPES_RS}")
update_file(CONNECTOR_TYPES_RS, step1)

# --- Step 2: Add Match Arm in ForeignTryFrom ---
def step2(lines):
    out = []
    for line in lines:
        if "grpc_api_types::payments::Connector::Unspecified" in line:
            out.append(f"            grpc_api_types::payments::Connector::{CONNECTOR_PASCAL} => Ok(Self::{CONNECTOR_PASCAL}),")
        out.append(line)
    return out

print(f"Step 2: Adding match arm for '{CONNECTOR_PASCAL}' in {CONNECTOR_TYPES_RS}")
update_file(CONNECTOR_TYPES_RS, step2)

# --- Step 3: Add to Connectors struct ---
def step3(lines):
    out, in_struct = [], False
    for line in lines:
        if "pub struct Connectors {" in line:
            in_struct = True
        if in_struct and line.strip() == "}":
            out.append(f"    pub {CONNECTOR_SNAKE}: ConnectorParams,")
            in_struct = False
        out.append(line)
    return out

print(f"Step 3: Adding '{CONNECTOR_SNAKE}' to Connectors struct in {TYPES_RS}")
update_file(TYPES_RS, step3)

# --- Step 4: Add use statement ---
def step4(lines):
    out, in_use = [], False
    for line in lines:
        if "use crate::connectors::{" in line:
            in_use = True
        if in_use and line.strip() == "};":
            out.append(f"    {CONNECTOR_PASCAL},")
            in_use = False
        out.append(line)
    return out

print(f"Step 4: Adding use statement for '{CONNECTOR_PASCAL}' in {INTEGRATION_TYPES_RS}")
update_file(INTEGRATION_TYPES_RS, step4)

# --- Step 5: Add match arm in convert_connector ---
def step5(lines):
    out, in_func, in_match = [], False, False
    for line in lines:
        if "fn convert_connector(connector_name: ConnectorEnum)" in line:
            in_func = True
        if in_func and "match connector_name {" in line:
            in_match = True
        if in_match and line.strip() == "}":
            out.append(f"            ConnectorEnum::{CONNECTOR_PASCAL} => Box::new({CONNECTOR_PASCAL}::new()),")
            in_match = False
        out.append(line)
    return out

print(f"Step 5: Adding match arm for '{CONNECTOR_PASCAL}' in {INTEGRATION_TYPES_RS}")
update_file(INTEGRATION_TYPES_RS, step5)

# --- Step 6: Add module and use in connectors.rs ---
def step6(lines):
    out = list(lines)
    out.append("")
    out.append(f"pub mod {CONNECTOR_SNAKE};")
    out.append(f"pub use self::{CONNECTOR_SNAKE}::{CONNECTOR_PASCAL};")
    return out

print(f"Step 6: Adding module for '{CONNECTOR_SNAKE}' in {CONNECTORS_RS}")
update_file(CONNECTORS_RS, step6)

print(f"Successfully automated the first 6 steps for connector '{CONNECTOR_PASCAL}'.")
