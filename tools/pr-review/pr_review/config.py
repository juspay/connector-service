"""Configuration management for the PR review tool."""

from __future__ import annotations

import copy
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import]
    except ImportError:
        import tomli as tomllib  # type: ignore[import,no-redef]

from pr_review.rules.base import Severity


@dataclass
class RuleOverride:
    """Override for a specific rule."""

    severity: Severity | None = None
    enabled: bool = True


@dataclass
class Config:
    """Configuration for the PR review tool."""

    # Rule overrides by rule_id
    rule_overrides: dict[str, RuleOverride] = field(default_factory=dict)

    # File patterns to ignore (glob-style)
    ignore_patterns: list[str] = field(default_factory=list)

    # Score threshold for pass/fail
    fail_under: int = 60

    # Maximum files before scope warning
    max_file_count: int = 25

    @staticmethod
    def load(path: str | Path) -> Config:
        """Load configuration from a TOML file.

        Example config file:
        ```toml
        fail_under = 80
        max_file_count = 30

        [ignore]
        patterns = [
            "backend/connector-integration/src/connectors/*/test.rs",
            "sdk/**",
        ]

        [rules.TS-006]
        severity = "suggestion"

        [rules.TS-009]
        enabled = false

        [rules.SE-002]
        severity = "critical"
        ```
        """
        config_path = Path(path)
        if not config_path.exists():
            return Config()

        with open(config_path, "rb") as f:
            data = tomllib.load(f)

        config = Config()

        # Top-level settings
        config.fail_under = data.get("fail_under", config.fail_under)
        config.max_file_count = data.get("max_file_count", config.max_file_count)

        # Ignore patterns
        ignore = data.get("ignore", {})
        config.ignore_patterns = ignore.get("patterns", [])

        # Rule overrides
        rules = data.get("rules", {})
        for rule_id, overrides in rules.items():
            override = RuleOverride()
            if "severity" in overrides:
                sev_str = overrides["severity"].lower()
                sev_map = {
                    "critical": Severity.CRITICAL,
                    "warning": Severity.WARNING,
                    "suggestion": Severity.SUGGESTION,
                }
                override.severity = sev_map.get(sev_str)
            if "enabled" in overrides:
                override.enabled = bool(overrides["enabled"])
            config.rule_overrides[rule_id.upper()] = override

        return config

    def apply_to_rules(self, rules: list) -> list:
        """Apply configuration overrides to a list of rules.

        Returns a new list with disabled rules removed and severity overrides
        applied.  Overridden rules are shallow-copied so the originals are
        never mutated — this keeps the module-level rule singletons pristine
        for subsequent calls with different configs.
        """
        result = []
        for rule in rules:
            override = self.rule_overrides.get(rule.rule_id)
            if override:
                if not override.enabled:
                    continue
                if override.severity is not None:
                    rule = copy.copy(rule)
                    rule.severity = override.severity
            result.append(rule)
        return result

    def should_ignore_file(self, file_path: str) -> bool:
        """Check if a file path matches any ignore pattern."""
        from fnmatch import fnmatch

        return any(fnmatch(file_path, pat) for pat in self.ignore_patterns)
