"""Classify changed files by their role in the connector-service codebase."""

from __future__ import annotations

import re
from enum import Enum, auto
from dataclasses import dataclass

from pr_review.diff_parser import ChangedFile


class FileType(Enum):
    """Classification of a file's role in the codebase."""

    CONNECTOR = auto()  # backend/connector-integration/src/connectors/<name>.rs
    TRANSFORMER = (
        auto()
    )  # backend/connector-integration/src/connectors/<name>/transformers.rs
    CONNECTOR_TEST = (
        auto()
    )  # backend/connector-integration/src/connectors/<name>/test.rs
    CONNECTOR_MODULE = (
        auto()
    )  # backend/connector-integration/src/connectors.rs (registry)
    CONNECTOR_TYPES = auto()  # backend/domain_types/src/connector_types.rs
    GRPC_TEST = auto()  # backend/grpc-server/tests/*_test.rs
    GRPC_SERVER = auto()  # backend/grpc-server/src/**
    DOMAIN_TYPES = auto()  # backend/domain_types/src/**
    INTERFACES = auto()  # backend/interfaces/src/**
    COMMON_UTILS = auto()  # backend/common_utils/src/**
    COMMON_ENUMS = auto()  # backend/common_enums/src/**
    EXTERNAL_SERVICES = auto()  # backend/external-services/src/**
    COMPOSITE_SERVICE = auto()  # backend/composite-service/src/**
    GRPC_HANDLER = auto()  # backend/grpc-server/src/http/handlers/**/*.rs
    GRPC_SERVICE = auto()  # backend/grpc-server/src/server/*.rs
    GRPC_ROUTER = auto()  # backend/grpc-server/src/http/router.rs
    FFI = auto()  # backend/ffi/src/**
    PROTO = auto()  # *.proto files
    CONFIG = auto()  # config/*.toml, Cargo.toml
    CI = auto()  # .github/workflows/*.yml
    DOCUMENTATION = auto()  # *.md files
    SDK = auto()  # sdk/**
    OTHER_RUST = auto()  # Other .rs files not in the categories above
    OTHER = auto()  # Non-Rust, non-config files


@dataclass
class ClassifiedFile:
    """A changed file with its classification and extracted metadata."""

    changed_file: ChangedFile
    file_type: FileType
    connector_name: str | None = None  # Extracted connector name, if applicable

    @property
    def path(self) -> str:
        return self.changed_file.path

    @property
    def is_connector_related(self) -> bool:
        return self.file_type in (
            FileType.CONNECTOR,
            FileType.TRANSFORMER,
            FileType.CONNECTOR_TEST,
            FileType.CONNECTOR_MODULE,
            FileType.CONNECTOR_TYPES,
            FileType.GRPC_TEST,
        )

    @property
    def is_rust(self) -> bool:
        return self.changed_file.is_rust_file

    @property
    def is_test(self) -> bool:
        return self.file_type in (FileType.CONNECTOR_TEST, FileType.GRPC_TEST)


# Patterns for connector file detection
_CONNECTOR_FILE = re.compile(
    r"^backend/connector-integration/src/connectors/([a-z][a-z0-9_]*)\.rs$"
)
_TRANSFORMER_FILE = re.compile(
    r"^backend/connector-integration/src/connectors/([a-z][a-z0-9_]*)/transformers\.rs$"
)
_CONNECTOR_TEST_FILE = re.compile(
    r"^backend/connector-integration/src/connectors/([a-z][a-z0-9_]*)/test\.rs$"
)
_CONNECTOR_MODULE_FILE = re.compile(
    r"^backend/connector-integration/src/connectors\.rs$"
)
_CONNECTOR_TYPES_FILE = re.compile(r"^backend/domain_types/src/connector_types\.rs$")
_GRPC_TEST_FILE = re.compile(
    r"^backend/grpc-server/tests/([a-z][a-z0-9_]*?)_(?:payment_flows_)?test\.rs$"
)
_GRPC_SERVER_FILE = re.compile(r"^backend/grpc-server/src/.+\.rs$")
_DOMAIN_TYPES_FILE = re.compile(r"^backend/domain_types/src/.+\.rs$")
_INTERFACES_FILE = re.compile(r"^backend/interfaces/src/.+\.rs$")
_COMMON_UTILS_FILE = re.compile(r"^backend/common_utils/src/.+\.rs$")
_COMMON_ENUMS_FILE = re.compile(r"^backend/common_enums/src/.+\.rs$")
_EXTERNAL_SERVICES_FILE = re.compile(r"^backend/external-services/src/.+\.rs$")
_COMPOSITE_SERVICE_FILE = re.compile(r"^backend/composite-service/src/.+\.rs$")
_GRPC_HANDLER_FILE = re.compile(r"^backend/grpc-server/src/http/handlers/.+\.rs$")
_GRPC_SERVICE_FILE = re.compile(r"^backend/grpc-server/src/server/.+\.rs$")
_GRPC_ROUTER_FILE = re.compile(r"^backend/grpc-server/src/http/router\.rs$")
_FFI_FILE = re.compile(r"^backend/ffi/src/.+\.rs$")
_PROTO_FILE = re.compile(r".*\.proto$")
_CONFIG_FILE = re.compile(r"(^config/.+\.toml$|^Cargo\.toml$|.*Cargo\.toml$)")
_CI_FILE = re.compile(r"^\.github/workflows/.+\.yml$")
_DOC_FILE = re.compile(r".*\.md$")
_SDK_FILE = re.compile(r"^sdk/.+")


def classify_file(changed_file: ChangedFile) -> ClassifiedFile:
    """Classify a single changed file by its path.

    Args:
        changed_file: The changed file from the diff.

    Returns:
        ClassifiedFile with type and optional connector name.
    """
    path = changed_file.path

    # Check connector-specific patterns first (most specific)
    m = _CONNECTOR_FILE.match(path)
    if m:
        name = m.group(1)
        # Exclude the module registry file itself (connectors.rs at top level)
        if name != "macros" and name != "mod":
            return ClassifiedFile(changed_file, FileType.CONNECTOR, connector_name=name)

    m = _TRANSFORMER_FILE.match(path)
    if m:
        return ClassifiedFile(
            changed_file, FileType.TRANSFORMER, connector_name=m.group(1)
        )

    m = _CONNECTOR_TEST_FILE.match(path)
    if m:
        return ClassifiedFile(
            changed_file, FileType.CONNECTOR_TEST, connector_name=m.group(1)
        )

    if _CONNECTOR_MODULE_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.CONNECTOR_MODULE)

    if _CONNECTOR_TYPES_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.CONNECTOR_TYPES)

    m = _GRPC_TEST_FILE.match(path)
    if m:
        return ClassifiedFile(
            changed_file, FileType.GRPC_TEST, connector_name=m.group(1)
        )

    # gRPC sub-types must be checked before the generic GRPC_SERVER catch-all
    if _GRPC_ROUTER_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.GRPC_ROUTER)

    if _GRPC_HANDLER_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.GRPC_HANDLER)

    if _GRPC_SERVICE_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.GRPC_SERVICE)

    # Check broader categories
    if _GRPC_SERVER_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.GRPC_SERVER)

    if _DOMAIN_TYPES_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.DOMAIN_TYPES)

    if _INTERFACES_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.INTERFACES)

    if _COMMON_UTILS_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.COMMON_UTILS)

    if _COMMON_ENUMS_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.COMMON_ENUMS)

    if _EXTERNAL_SERVICES_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.EXTERNAL_SERVICES)

    if _COMPOSITE_SERVICE_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.COMPOSITE_SERVICE)

    if _FFI_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.FFI)

    if _PROTO_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.PROTO)

    if _CI_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.CI)

    if _CONFIG_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.CONFIG)

    if _DOC_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.DOCUMENTATION)

    if _SDK_FILE.match(path):
        return ClassifiedFile(changed_file, FileType.SDK)

    # Fallback
    if changed_file.is_rust_file:
        return ClassifiedFile(changed_file, FileType.OTHER_RUST)

    return ClassifiedFile(changed_file, FileType.OTHER)


def classify_files(changed_files: list[ChangedFile]) -> list[ClassifiedFile]:
    """Classify a list of changed files.

    Args:
        changed_files: List of changed files from the diff.

    Returns:
        List of classified files.
    """
    return [classify_file(f) for f in changed_files]


def get_connector_names(classified_files: list[ClassifiedFile]) -> set[str]:
    """Extract unique connector names from classified files.

    Args:
        classified_files: List of classified files.

    Returns:
        Set of connector names found in the changed files.
    """
    return {
        cf.connector_name for cf in classified_files if cf.connector_name is not None
    }
