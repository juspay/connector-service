"""Architecture compliance rules.

Ensures code uses the V2 traits and types (not legacy V1),
imports from the correct crates, and follows the layered architecture.
"""

from __future__ import annotations

from pr_review.rules.base import (
    Rule,
    RegexLineRule,
    Severity,
    Category,
)


def get_rules() -> list[Rule]:
    """Return all architecture compliance rules."""
    return [
        RegexLineRule(
            rule_id="AR-001",
            name="Use ConnectorIntegrationV2, not ConnectorIntegration",
            severity=Severity.CRITICAL,
            category=Category.ARCHITECTURE,
            description="Legacy ConnectorIntegration trait must not be used. Use ConnectorIntegrationV2.",
            # Match ConnectorIntegration NOT followed by V2
            # Negative lookahead: ConnectorIntegration but not ConnectorIntegrationV2
            pattern=r"\bConnectorIntegration\b(?!V2)",
            message_template="Legacy `ConnectorIntegration` trait used. Must use `ConnectorIntegrationV2`.",
            suggestion="Replace `ConnectorIntegration` with `ConnectorIntegrationV2`.",
            context="The V2 trait system is the UCS standard. V1 is legacy and must not be used.",
            exclude_test_files=False,
            # Exclude comments, imports of the V2 trait itself, and string literals
            exclude_patterns=[
                r"^\s*//",
                r"^\s*\*",
                r"ConnectorIntegrationV2",  # Don't flag V2 references
                r"connector_integration_v2",  # Module names
            ],
            file_filter=r"backend/connector-integration/",
        ),
        RegexLineRule(
            rule_id="AR-002",
            name="Use RouterDataV2, not RouterData",
            severity=Severity.CRITICAL,
            category=Category.ARCHITECTURE,
            description="Legacy RouterData type must not be used. Use RouterDataV2.",
            pattern=r"\bRouterData\b(?!V2)",
            message_template="Legacy `RouterData` type used. Must use `RouterDataV2`.",
            suggestion="Replace `RouterData` with `RouterDataV2`.",
            context="RouterDataV2 is parameterized with phantom types for compile-time flow discrimination.",
            exclude_test_files=False,
            exclude_patterns=[
                r"^\s*//",
                r"^\s*\*",
                r"RouterDataV2",
                r"router_data_v2",
                r"ResponseRouterData",  # This is a valid V2-era type
            ],
            file_filter=r"backend/connector-integration/src/connectors/(?!macros\.rs)",
        ),
        RegexLineRule(
            rule_id="AR-003",
            name="Import from domain_types, not hyperswitch_domain_models",
            severity=Severity.CRITICAL,
            category=Category.ARCHITECTURE,
            description="Use domain_types crate, not the legacy hyperswitch_domain_models.",
            pattern=r"\bhyperswitch_domain_models\b",
            message_template="Legacy import from `hyperswitch_domain_models` detected.",
            suggestion="Import from `domain_types` crate instead.",
            context="The connector-service uses its own domain_types crate, not the hyperswitch monorepo crate.",
            exclude_test_files=False,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
            file_filter=r"backend/connector-integration/src/connectors/(?!macros\.rs)",
        ),
        RegexLineRule(
            rule_id="AR-004",
            name="Import from common_enums, not hyperswitch_enums",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="Use ucs_common_enums crate, not hyperswitch-specific enum crates.",
            pattern=r"\bhyperswitch_enums\b",
            message_template="Import from `hyperswitch_enums` detected.",
            suggestion="Import from `common_enums` (ucs_common_enums) crate instead.",
            context="The connector-service has its own common_enums crate.",
            exclude_test_files=False,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="AR-005",
            name="Use ForeignTryFrom/ForeignFrom for cross-crate conversions",
            severity=Severity.SUGGESTION,
            category=Category.ARCHITECTURE,
            description="For conversions between types from different crates, use ForeignTryFrom/ForeignFrom to work around the orphan rule.",
            # Detect TryFrom impls where both source and target might be foreign
            # This is a heuristic - it flags TryFrom in files that import from multiple crates
            pattern=r"impl\s+TryFrom<\s*(?:grpc_api_types|tonic)",
            message_template="Consider using `ForeignTryFrom` for cross-crate type conversions.",
            suggestion="Use `ForeignTryFrom`/`ForeignFrom` traits with `.switch()` for cross-crate conversions.",
            context="The orphan rule prevents implementing external traits on external types. ForeignTryFrom works around this.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="AR-006",
            name="No direct reqwest usage in connector code",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            description="Connector implementations should not use reqwest directly. Use the external-services layer.",
            pattern=r"\breqwest::(?!multipart)",
            message_template="Direct `reqwest` usage detected in connector code.",
            suggestion="Use the `external_services::service::execute_connector_processing_step` function.",
            context="HTTP calls to connectors go through the external-services layer for metrics, logging, and proxy handling.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
            file_filter=r"backend/connector-integration/src/connectors/(?!macros\.rs)",
        ),
    ]
