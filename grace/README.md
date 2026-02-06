# Grace CLI

Intelligent research and technical specification generator using LangGraph workflows.

## Features

- **Techspec Workflow**: Automated connector code generation with validation and documentation
- **LangGraph Integration**: State-based workflow orchestration with parallel processing
- **Rich Output**: Multiple formats (Markdown, JSON, Text) with comprehensive metadata

## Requirements

- Python 3.9+ (Required for LangGraph compatibility)
- uv or pip for package management

## Installation

### Using uv (Recommended)
```bash
# Install from source
cd grace
uv sync

# Or install specific feature groups
uv sync --extra dev --extra ai --extra scraping
```

### Using pip with uv
```bash
# Install in development mode
uv pip install -e .

# Or with optional dependencies
uv pip install -e ".[dev,ai,scraping,nlp]"
```

## Quick Start

### Techspec Workflow
```bash
# Generate connector for a payment processor
source .venv/bin/activate # to use grace from outside folders as well
# move the grace/.env.example to .env -> and update Techspec output path and API keys if needed

grace techspec
```

## LangGraph Workflow Architecture

workflows use LangGraph for sophisticated state management and parallel processing:


### Techspec Workflow States
```
API Analysis -> Schema Extract -> Code Generation
                                       |
Finalize Output <- Generate Docs <- Validate Code
```

## Usage Examples


### Techspec Examples
```bash
# Payment processor connector
grace techspec adyen

grace techspec shopify --verbose
```

## Development

### Setup
```bash
git clone <repository-url>
cd grace
uv sync --extra dev
```


### Code Formatting
```bash
uv run black src/
uv run mypy src/
```

## Troubleshooting

### Dependency Resolution
If you get Python version conflicts:
```bash
# Check Python version
python --version  # Should be 3.9+

# Clear cache and reinstall
uv cache clean
uv sync
```

### Import Errors
If LangGraph imports fail:
```bash
# Install core dependencies
uv add langgraph langchain langchain-core
```
