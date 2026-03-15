"""Tests for file_classifier module."""

from pr_review.diff_parser import ChangedFile
from pr_review.file_classifier import (
    classify_file,
    classify_files,
    get_connector_names,
    ClassifiedFile,
    FileType,
)


def _make_file(path: str, *, is_new: bool = False) -> ChangedFile:
    return ChangedFile(
        path=path,
        old_path=None,
        is_new=is_new,
        is_deleted=False,
        is_renamed=False,
        is_binary=False,
    )


# --- Connector file classification ---


class TestClassifyConnectorFiles:
    def test_connector_file(self):
        cf = classify_file(
            _make_file("backend/connector-integration/src/connectors/stripe.rs")
        )
        assert cf.file_type == FileType.CONNECTOR
        assert cf.connector_name == "stripe"

    def test_connector_with_underscores(self):
        cf = classify_file(
            _make_file(
                "backend/connector-integration/src/connectors/bank_of_america.rs"
            )
        )
        assert cf.file_type == FileType.CONNECTOR
        assert cf.connector_name == "bank_of_america"

    def test_transformer_file(self):
        cf = classify_file(
            _make_file(
                "backend/connector-integration/src/connectors/adyen/transformers.rs"
            )
        )
        assert cf.file_type == FileType.TRANSFORMER
        assert cf.connector_name == "adyen"

    def test_connector_test_file(self):
        cf = classify_file(
            _make_file("backend/connector-integration/src/connectors/checkout/test.rs")
        )
        assert cf.file_type == FileType.CONNECTOR_TEST
        assert cf.connector_name == "checkout"

    def test_connector_module_registry(self):
        cf = classify_file(
            _make_file("backend/connector-integration/src/connectors.rs")
        )
        assert cf.file_type == FileType.CONNECTOR_MODULE
        assert cf.connector_name is None

    def test_connector_types(self):
        cf = classify_file(_make_file("backend/domain_types/src/connector_types.rs"))
        assert cf.file_type == FileType.CONNECTOR_TYPES

    def test_grpc_test_file(self):
        cf = classify_file(
            _make_file("backend/grpc-server/tests/stripe_payment_flows_test.rs")
        )
        assert cf.file_type == FileType.GRPC_TEST
        assert cf.connector_name == "stripe"

    def test_grpc_test_simple_name(self):
        cf = classify_file(_make_file("backend/grpc-server/tests/adyen_test.rs"))
        assert cf.file_type == FileType.GRPC_TEST
        assert cf.connector_name == "adyen"


# --- Non-connector classification ---


class TestClassifyNonConnectorFiles:
    def test_grpc_server(self):
        cf = classify_file(_make_file("backend/grpc-server/src/server.rs"))
        assert cf.file_type == FileType.GRPC_SERVER

    def test_domain_types(self):
        cf = classify_file(_make_file("backend/domain_types/src/payments.rs"))
        assert cf.file_type == FileType.DOMAIN_TYPES

    def test_interfaces(self):
        cf = classify_file(_make_file("backend/interfaces/src/api.rs"))
        assert cf.file_type == FileType.INTERFACES

    def test_common_utils(self):
        cf = classify_file(_make_file("backend/common_utils/src/helpers.rs"))
        assert cf.file_type == FileType.COMMON_UTILS

    def test_common_enums(self):
        cf = classify_file(_make_file("backend/common_enums/src/enums.rs"))
        assert cf.file_type == FileType.COMMON_ENUMS

    def test_external_services(self):
        cf = classify_file(_make_file("backend/external-services/src/http.rs"))
        assert cf.file_type == FileType.EXTERNAL_SERVICES

    def test_proto_file(self):
        cf = classify_file(_make_file("proto/services.proto"))
        assert cf.file_type == FileType.PROTO

    def test_cargo_toml(self):
        cf = classify_file(_make_file("Cargo.toml"))
        assert cf.file_type == FileType.CONFIG

    def test_nested_cargo_toml(self):
        cf = classify_file(_make_file("backend/grpc-server/Cargo.toml"))
        assert cf.file_type == FileType.CONFIG

    def test_config_toml(self):
        cf = classify_file(_make_file("config/development.toml"))
        assert cf.file_type == FileType.CONFIG

    def test_ci_workflow(self):
        cf = classify_file(_make_file(".github/workflows/ci.yml"))
        assert cf.file_type == FileType.CI

    def test_documentation(self):
        cf = classify_file(_make_file("README.md"))
        assert cf.file_type == FileType.DOCUMENTATION

    def test_sdk_file(self):
        cf = classify_file(_make_file("sdk/python/client.py"))
        assert cf.file_type == FileType.SDK

    def test_other_rust(self):
        cf = classify_file(_make_file("some_tool/src/main.rs"))
        assert cf.file_type == FileType.OTHER_RUST

    def test_other_non_rust(self):
        cf = classify_file(_make_file("scripts/deploy.sh"))
        assert cf.file_type == FileType.OTHER


# --- Exclusions for connector-like but special files ---


class TestConnectorExclusions:
    def test_macros_rs_not_connector(self):
        """backend/connector-integration/src/connectors/macros.rs should not be CONNECTOR."""
        cf = classify_file(
            _make_file("backend/connector-integration/src/connectors/macros.rs")
        )
        # macros.rs matches the regex but is excluded by name
        assert cf.file_type != FileType.CONNECTOR

    def test_mod_rs_not_connector(self):
        cf = classify_file(
            _make_file("backend/connector-integration/src/connectors/mod.rs")
        )
        assert cf.file_type != FileType.CONNECTOR


# --- ClassifiedFile properties ---


class TestClassifiedFileProperties:
    def test_is_connector_related(self):
        cf = classify_file(
            _make_file("backend/connector-integration/src/connectors/stripe.rs")
        )
        assert cf.is_connector_related

    def test_is_not_connector_related(self):
        cf = classify_file(_make_file("backend/grpc-server/src/server.rs"))
        assert not cf.is_connector_related

    def test_is_test(self):
        cf = classify_file(_make_file("backend/grpc-server/tests/stripe_test.rs"))
        assert cf.is_test

    def test_is_not_test(self):
        cf = classify_file(
            _make_file("backend/connector-integration/src/connectors/stripe.rs")
        )
        assert not cf.is_test

    def test_is_rust(self):
        cf = classify_file(_make_file("backend/src/main.rs"))
        assert cf.is_rust

    def test_path_property(self):
        cf = classify_file(_make_file("backend/src/main.rs"))
        assert cf.path == "backend/src/main.rs"


# --- Batch classification ---


class TestBatchClassification:
    def test_classify_files(self):
        files = [
            _make_file("backend/connector-integration/src/connectors/stripe.rs"),
            _make_file(
                "backend/connector-integration/src/connectors/adyen/transformers.rs"
            ),
            _make_file("README.md"),
        ]
        classified = classify_files(files)
        assert len(classified) == 3
        types = [c.file_type for c in classified]
        assert FileType.CONNECTOR in types
        assert FileType.TRANSFORMER in types
        assert FileType.DOCUMENTATION in types

    def test_get_connector_names(self):
        files = [
            _make_file("backend/connector-integration/src/connectors/stripe.rs"),
            _make_file(
                "backend/connector-integration/src/connectors/adyen/transformers.rs"
            ),
            _make_file("backend/grpc-server/tests/stripe_test.rs"),
            _make_file("README.md"),
        ]
        classified = classify_files(files)
        names = get_connector_names(classified)
        assert names == {"stripe", "adyen"}
