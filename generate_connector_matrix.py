#!/usr/bin/env python3
"""
Generate connector-to-flows matrix table for UCS
"""

import re
import subprocess
from collections import defaultdict
from typing import Dict, List, Set

def get_flow_data() -> str:
    """Read flow information from pre-generated file."""
    try:
        with open('flow_data.txt', 'r') as f:
            return f.read()
    except FileNotFoundError:
        # Fallback to grep command
        cmd = [
            'grep',
            '-r',
            '--include=*.rs',
            r'^\s\+flow:\s\+\w\+,',
            'backend/connector-integration/src/connectors/'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd='.')
        return result.stdout

def parse_flow_data(grep_output: str) -> Dict[str, Set[str]]:
    """Parse grep output to extract connector -> flows mapping."""
    connector_flows = defaultdict(set)

    # Pattern: backend/connector-integration/src/connectors/connector_name.rs:            flow: FlowName,
    # Can have optional line number: connector_name.rs:123:
    pattern = r'/connectors/([^/]+?)\.rs(?::\d+)?:\s+flow:\s+(\w+),'

    for line in grep_output.strip().split('\n'):
        if not line:
            continue
        match = re.search(pattern, line)
        if match:
            connector_name = match.group(1)
            flow_name = match.group(2)

            # Skip certain files
            if connector_name in ['macros', 'finix']:
                continue

            # Skip if it's in a subdirectory (transformers.rs)
            if '/transformers.rs' in line or '/' in connector_name:
                continue

            connector_flows[connector_name].add(flow_name)

    return dict(connector_flows)

def get_all_flows(connector_flows: Dict[str, Set[str]]) -> List[str]:
    """Get all unique flows across all connectors, sorted."""
    all_flows = set()
    for flows in connector_flows.values():
        all_flows.update(flows)

    # Exclude unstable dispute flows
    excluded_flows = {'Accept', 'DefendDispute', 'SubmitEvidence'}
    all_flows = all_flows - excluded_flows

    # Define a custom sort order for common flows
    flow_order = [
        'Authorize',
        'PSync',
        'Capture',
        'Void',
        'Refund',
        'RSync',
        'SetupMandate',
        'RepeatPayment',
        'CreateOrder',
        'CreateSessionToken',
        'CreateAccessToken',
        'PaymentMethodToken',
        'CreateConnectorCustomer',
        'PreAuthenticate',
        'Authenticate',
        'PostAuthenticate',
    ]

    # Sort flows: known flows first in order, then alphabetically
    sorted_flows = []
    for flow in flow_order:
        if flow in all_flows:
            sorted_flows.append(flow)
            all_flows.remove(flow)

    # Add remaining flows alphabetically
    sorted_flows.extend(sorted(all_flows))

    return sorted_flows

def generate_markdown_table(connector_flows: Dict[str, Set[str]], all_flows: List[str]) -> str:
    """Generate markdown table for the connector-flow matrix."""

    # Pipeline connectors to mark with 🚧
    pipeline_connectors = {'chase', 'paypal', 'ebanx'}

    # Sort connectors alphabetically
    connectors = sorted(connector_flows.keys())

    # Build table header
    table = []
    table.append('| Connector | ' + ' | '.join(all_flows) + ' |')
    table.append('|-----------|' + '|'.join(['---' for _ in all_flows]) + '|')

    # Build table rows
    for connector in connectors:
        flows = connector_flows[connector]
        # Capitalize first letter of connector name for display
        display_name = connector.replace('_', ' ').title()

        # Add pipeline marker if applicable
        if connector in pipeline_connectors:
            display_name += ' 🚧'

        row = f'| {display_name} |'
        for flow in all_flows:
            if flow in flows:
                row += ' ✓ |'
            else:
                row += ' |'
        table.append(row)

    return '\n'.join(table)

def generate_summary_stats(connector_flows: Dict[str, Set[str]], all_flows: List[str]) -> str:
    """Generate summary statistics."""
    pipeline_connectors = {'chase', 'paypal', 'ebanx'}

    # Count only implemented connectors (exclude pipeline)
    implemented_connectors = {k: v for k, v in connector_flows.items()
                              if k not in pipeline_connectors}
    total_implemented = len(implemented_connectors)
    total_connectors = len(connector_flows)
    total_flows = len(all_flows)

    # Count implementations per flow (only from implemented connectors)
    flow_counts = defaultdict(int)
    for connector, flows in connector_flows.items():
        if connector not in pipeline_connectors:
            for flow in flows:
                flow_counts[flow] += 1

    summary = [
        f"\n## Summary Statistics\n",
        f"- **Total Connectors**: {total_connectors} ({total_implemented} implemented, {len(pipeline_connectors)} in pipeline)",
        f"- **Total Unique Flows**: {total_flows}",
        f"\n### Most Implemented Flows\n"
    ]

    # Top 10 most implemented flows
    sorted_flow_counts = sorted(flow_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for flow, count in sorted_flow_counts:
        percentage = (count / total_implemented) * 100 if total_implemented > 0 else 0
        summary.append(f"- **{flow}**: {count}/{total_implemented} connectors ({percentage:.1f}%)")

    return '\n'.join(summary)

def main():
    print("Extracting flow data from connector files...")
    grep_output = get_flow_data()

    print("Parsing flow data...")
    connector_flows = parse_flow_data(grep_output)

    # Add connectors that don't use api: macro pattern but are fully implemented
    # Razorpay uses direct trait implementations instead of api: macro
    manual_connectors = {
        'razorpay': {'Authorize', 'PSync', 'CreateOrder', 'Void', 'Refund', 'RSync', 'Capture', 'CreateSessionToken', 'CreateAccessToken', 'CreateConnectorCustomer'},
        'razorpayv2': {'Authorize', 'PSync', 'CreateOrder', 'Void', 'Refund', 'RSync', 'Capture'},
    }

    # Add pipeline connectors (Nov'25 roadmap)
    pipeline_connectors = {
        'chase': set(),  # Highest priority - Orbital and other flavours
        'paypal': set(),  # In pipeline
        'ebanx': set(),  # Strategic expansion
    }

    # Merge manual connectors
    for connector, flows in manual_connectors.items():
        if connector not in connector_flows:
            connector_flows[connector] = flows

    # Merge pipeline connectors
    for connector, flows in pipeline_connectors.items():
        if connector not in connector_flows:
            connector_flows[connector] = flows

    print(f"Found {len(connector_flows)} connectors (including {len(manual_connectors)} manual + {len(pipeline_connectors)} in pipeline)")

    print("Getting all unique flows...")
    all_flows = get_all_flows(connector_flows)

    print(f"Found {len(all_flows)} unique flows")

    print("Generating markdown table...")
    table = generate_markdown_table(connector_flows, all_flows)

    print("Generating summary statistics...")
    summary = generate_summary_stats(connector_flows, all_flows)

    # Create the full content
    content = [
        "# UCS Connector Flow Matrix\n",
        "This table shows which flows are implemented for each connector in the Universal Connector Service (UCS).\n",
        "\n> **Note:** Connectors marked with 🚧 are in the pipeline for November 2025.\n",
        "\n## Flow Implementations by Connector\n",
        table,
        summary,
        "\n## Pipeline Connectors (Nov'25)\n",
        "The following connectors are currently in development:\n",
        "- **Chase (Orbital and other flavours)** - Highest priority\n",
        "- **PayPal** - In development\n",
        "- **Ebanx** - Strategic expansion\n",
        "\n---\n",
        "*Last updated: Auto-generated from codebase*\n"
    ]

    output_file = 'CONNECTOR_FLOWS.md'
    with open(output_file, 'w') as f:
        f.write('\n'.join(content))

    print(f"\n✓ Matrix generated successfully: {output_file}")
    print(f"✓ {len(connector_flows)} connectors analyzed")
    print(f"✓ {len(all_flows)} unique flows found")

if __name__ == '__main__':
    main()
