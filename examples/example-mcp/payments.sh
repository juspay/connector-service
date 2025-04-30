#!/bin/sh
# Change to the script directory
cd "$(dirname "$0")"
PYTHONPATH=. uv run payments.py