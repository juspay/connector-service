# Connector Service Memory Bank

This Memory Bank serves as a comprehensive knowledge repository for the Connector Service project. It contains structured documentation about the project's purpose, architecture, implementation details, and current status.

## Purpose

The Memory Bank is designed to:

1. Provide a complete understanding of the Connector Service project
2. Serve as a reference for developers working on the project
3. Maintain continuity of knowledge across development sessions
4. Document key decisions, patterns, and implementation details

## Structure

The Memory Bank is organized into the following components:

### Core Files

- **[projectbrief.md](./projectbrief.md)**: Foundation, core requirements, and goals of the project
- **[productContext.md](./productContext.md)**: Project purpose, solved problems, user experience goals
- **[activeContext.md](./activeContext.md)**: Current work focus, recent changes, next steps
- **[systemPatterns.md](./systemPatterns.md)**: Architecture, key technical decisions, patterns, component relationships
- **[techContext.md](./techContext.md)**: Technologies, development setup, constraints, dependencies
- **[progress.md](./progress.md)**: Current status, known issues, project evolution
- **[.clinerules](./.clinerules)**: Project intelligence, patterns, preferences, and best practices

### Thematic Folders

- **[thematic/connectors/](./thematic/connectors/)**: Detailed documentation for individual payment connectors
  - [adyen.md](./thematic/connectors/adyen.md): Documentation for the Adyen connector
  
- **[thematic/flows/](./thematic/flows/)**: Documentation for payment flows
  - [payment_flows.md](./thematic/flows/payment_flows.md): Detailed explanation of payment flows
  
- **[thematic/api/](./thematic/api/)**: API contract details and usage examples
  - [grpc_contract.md](./thematic/api/grpc_contract.md): Documentation for the gRPC API contract

### Archive Folder

- **[archive/](./archive/)**: Storage for outdated or historical contexts

## How to Use This Memory Bank

### For New Developers

1. Start with the [projectbrief.md](./projectbrief.md) to understand the project's purpose and goals
2. Read [productContext.md](./productContext.md) to understand the problems the project solves
3. Review [systemPatterns.md](./systemPatterns.md) to understand the architecture
4. Explore [techContext.md](./techContext.md) to understand the technologies used
5. Check [activeContext.md](./activeContext.md) to see the current focus areas
6. Dive into the thematic folders for more detailed information on specific aspects

### For Ongoing Development

1. Refer to [activeContext.md](./activeContext.md) for current work focus and next steps
2. Check [progress.md](./progress.md) for the current status and known issues
3. Use the thematic folders for detailed information on specific components
4. Consult [.clinerules](./.clinerules) for project patterns and best practices

### For Adding New Connectors

1. Review [systemPatterns.md](./systemPatterns.md) to understand the connector integration pattern
2. Study [thematic/connectors/adyen.md](./thematic/connectors/adyen.md) as an example implementation
3. Refer to [thematic/flows/payment_flows.md](./thematic/flows/payment_flows.md) for the payment flows to implement
4. Check [.clinerules](./.clinerules) for implementation patterns and best practices

## Maintaining the Memory Bank

To keep the Memory Bank useful and up-to-date:

1. **Update Regularly**: Update the Memory Bank when making significant changes to the project
2. **Keep Core Files Current**: Ensure the core files reflect the current state of the project
3. **Add Detailed Documentation**: Add detailed documentation for new components in the thematic folders
4. **Archive Outdated Information**: Move outdated information to the archive folder
5. **Follow Structure**: Maintain the established structure for consistency

## Key Information Sources

The Memory Bank was created based on the following sources:

1. Project codebase analysis
2. README.md and other documentation
3. Code structure and patterns
4. Implementation details of existing connectors
5. API definitions and contracts

## Memory Bank Optimization

The Memory Bank follows these optimization techniques:

1. **Hierarchical Structuring**: Core files contain essential information, with details in thematic folders
2. **Summary-Detail Pattern**: Brief essential points upfront, deeper detail subsequently
3. **Cross-Linking**: References between related documents to reduce redundancy
4. **Progressive Disclosure**: General information first, specific details as needed
5. **Regular Cleanup**: Periodic review to remove redundant content and merge overlaps
