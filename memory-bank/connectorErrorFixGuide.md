# Connector Error Fix Guide

This guide provides step-by-step instructions for fixing errors for a new connector in the connector service.

### File: backend/connector-integration/src/connectors/new_connector/transformers.rs

1. Replace all "enums" with "common_enums"

2. Replace all "Box::new(None)" with "None"

