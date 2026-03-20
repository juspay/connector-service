#!/bin/bash

# Script to extract Source URLs and save them by connector base URL
# This script runs from the grace folder but creates output in connector-service/urls/

# Get the absolute path of the grace folder's parent (connector-service)
CONNECTOR_SERVICE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URLS_DIR="$CONNECTOR_SERVICE_DIR/urls"
MARKDOWN_DIR="$(dirname "${BASH_SOURCE[0]}")/output/markdown"

# Create urls folder in connector service if it doesn't exist
mkdir -p "$URLS_DIR"

# Create a temporary file to store all URLs
temp_file=$(mktemp)

# Extract all Source URLs from all markdown files
grep -h "Source URL:" "$MARKDOWN_DIR"/*.md 2>/dev/null | sed 's/.*Source URL: *//' | sed 's/^\*\* *//' | sed 's/^[[:space:]]*//' | grep "^https" | sort | uniq > "$temp_file"

# Extract unique base URLs (up to the domain) and process each one
awk -F'/' '{print $1"//"$3}' "$temp_file" | sort | uniq | while read -r base_url; do
    # Create connector name from base URL
    connector_name=$(echo "$base_url" | sed 's|^https://||' | sed 's|^http://||' | sed 's|\.|_|g')

    # Skip if base_url is empty
    if [ -z "$base_url" ] || [ "$base_url" = "//" ]; then
        continue
    fi

    # Create output file path
    output_file="$URLS_DIR/${connector_name}_urls.md"

    # Start the markdown file with header
    cat > "$output_file" << EOF
# Source URLs for $connector_name

## Base URL: $base_url

### URLs:
EOF

    # Add all URLs that start with this base URL
    grep "^$base_url" "$temp_file" | while read -r url; do
        echo "- $url" >> "$output_file"
    done

    echo "" >> "$output_file"

done

# Clean up
rm "$temp_file"

echo "URL files have been created in $URLS_DIR"