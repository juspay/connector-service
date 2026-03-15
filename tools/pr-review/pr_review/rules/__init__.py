"""Rule modules for PR review analysis."""

from pr_review.rules.base import Rule, Finding, Severity, Category, RuleRegistry
from pr_review.rules.type_safety import get_rules as get_type_safety_rules
from pr_review.rules.architecture import get_rules as get_architecture_rules
from pr_review.rules.security import get_rules as get_security_rules
from pr_review.rules.error_handling import get_rules as get_error_handling_rules
from pr_review.rules.connector_patterns import get_rules as get_connector_pattern_rules
from pr_review.rules.domain_rules import get_rules as get_domain_rules
from pr_review.rules.testing import get_rules as get_testing_rules
from pr_review.rules.pr_quality import get_rules as get_pr_quality_rules
from pr_review.rules.grpc_server import get_rules as get_grpc_server_rules
from pr_review.rules.proto import get_rules as get_proto_rules
from pr_review.rules.composite import get_rules as get_composite_rules


def get_all_rules(learned_data: dict | None = None) -> list[Rule]:
    """Return all registered rules from every category.

    Args:
        learned_data: Optional dict from learner.py. When provided, rules
                      use dynamically learned values instead of hardcoded defaults.
    """
    rules: list[Rule] = []
    rules.extend(get_type_safety_rules(learned_data=learned_data))
    rules.extend(get_architecture_rules())
    rules.extend(get_security_rules(learned_data=learned_data))
    rules.extend(get_error_handling_rules())
    rules.extend(get_connector_pattern_rules(learned_data=learned_data))
    rules.extend(get_domain_rules(learned_data=learned_data))
    rules.extend(get_testing_rules())
    rules.extend(get_pr_quality_rules(learned_data=learned_data))
    rules.extend(get_grpc_server_rules())
    rules.extend(get_proto_rules(learned_data=learned_data))
    rules.extend(get_composite_rules(learned_data=learned_data))
    return rules


__all__ = [
    "Rule",
    "Finding",
    "Severity",
    "Category",
    "RuleRegistry",
    "get_all_rules",
]
