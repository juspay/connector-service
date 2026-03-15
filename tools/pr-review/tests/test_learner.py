"""Tests for the learner module."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase

from pr_review.learner import (
    SCHEMA_VERSION,
    learn,
    load_learned_data,
    save_learned_data,
    default_learned_data_path,
    scan_clippy_lints,
    scan_connector_flows,
    scan_connector_common_methods,
    scan_known_connectors,
    scan_attempt_status_variants,
    scan_sensitive_field_patterns,
    scan_error_response_patterns,
    scan_conventional_commit_config,
    scan_proto_conventions,
    scan_composite_service,
)


class TestDefaultLearnedDataPath(TestCase):
    def test_returns_correct_path(self):
        path = default_learned_data_path("/my/repo")
        self.assertEqual(path, "/my/repo/tools/pr-review/learned_data.json")


class TestSaveAndLoadLearnedData(TestCase):
    def test_roundtrip(self):
        data = {
            "schema_version": SCHEMA_VERSION,
            "lints": {"clippy": {"unwrap_used": "warn"}},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_learned_data(data, path)
            loaded = load_learned_data(path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["schema_version"], SCHEMA_VERSION)
            self.assertEqual(loaded["lints"]["clippy"]["unwrap_used"], "warn")
        finally:
            os.unlink(path)

    def test_load_missing_file(self):
        result = load_learned_data("/nonexistent/path.json")
        self.assertIsNone(result)

    def test_load_wrong_schema_version(self):
        data = {"schema_version": 99999}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
            json.dump(data, f)
        try:
            result = load_learned_data(path)
            self.assertIsNone(result)
        finally:
            os.unlink(path)

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
            f.write("not json {{{")
        try:
            result = load_learned_data(path)
            self.assertIsNone(result)
        finally:
            os.unlink(path)


class TestScanClippyLints(TestCase):
    def _make_repo(self, cargo_content: str) -> str:
        tmpdir = tempfile.mkdtemp()
        Path(tmpdir, "Cargo.toml").write_text(cargo_content)
        return tmpdir

    def test_parses_simple_lints(self):
        cargo = """
[workspace.lints.clippy]
unwrap_used = "warn"
panic = "warn"

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        repo = self._make_repo(cargo)
        result = scan_clippy_lints(repo)
        self.assertEqual(result["clippy"]["unwrap_used"], "warn")
        self.assertEqual(result["clippy"]["panic"], "warn")
        self.assertEqual(result["rust"]["unsafe_code"], "forbid")

    def test_parses_complex_lints(self):
        cargo = """
[workspace.lints.clippy]
large_futures = { level = "warn", priority = -1 }
"""
        repo = self._make_repo(cargo)
        result = scan_clippy_lints(repo)
        self.assertEqual(result["clippy"]["large_futures"], "warn")

    def test_missing_cargo(self):
        tmpdir = tempfile.mkdtemp()
        result = scan_clippy_lints(tmpdir)
        self.assertEqual(result["clippy"], {})
        self.assertEqual(result["rust"], {})


class TestScanConnectorFlows(TestCase):
    def _make_repo_with_flows(self, flow_content: str, types_content: str = "") -> str:
        tmpdir = tempfile.mkdtemp()
        flow_dir = Path(tmpdir, "backend", "domain_types", "src")
        flow_dir.mkdir(parents=True)
        (flow_dir / "connector_flow.rs").write_text(flow_content)

        if types_content:
            types_dir = Path(tmpdir, "backend", "interfaces", "src")
            types_dir.mkdir(parents=True)
            (types_dir / "connector_types.rs").write_text(types_content)

        return tmpdir

    def test_extracts_flow_structs(self):
        flow_content = """
pub struct Authorize;
pub struct PSync;
pub struct Capture;
"""
        repo = self._make_repo_with_flows(flow_content)
        result = scan_connector_flows(repo)
        self.assertEqual(len(result["flow_structs"]), 3)
        self.assertIn("Authorize", result["flow_structs"])

    def test_extracts_flow_trait_map(self):
        flow_content = "pub struct Authorize;"
        types_content = """
pub trait PaymentAuthorizeV2<T>: ConnectorIntegrationV2<connector_flow::Authorize, T, PaymentData> {}
pub trait PaymentSyncV2<T>: ConnectorIntegrationV2<connector_flow::PSync, T, PaymentData> {}
"""
        repo = self._make_repo_with_flows(flow_content, types_content)
        result = scan_connector_flows(repo)
        self.assertEqual(
            result["flow_trait_map"].get("Authorize"), "PaymentAuthorizeV2"
        )
        self.assertEqual(result["flow_trait_map"].get("PSync"), "PaymentSyncV2")


class TestScanConnectorCommonMethods(TestCase):
    def test_extracts_methods(self):
        tmpdir = tempfile.mkdtemp()
        api_dir = Path(tmpdir, "backend", "interfaces", "src")
        api_dir.mkdir(parents=True)
        (api_dir / "api.rs").write_text("""
pub trait ConnectorCommon {
    fn id(&self) -> &'static str;
    fn base_url(&self) -> &str;
    fn get_auth_header(&self) -> Result<Vec<(String, String)>>;
}
""")
        result = scan_connector_common_methods(tmpdir)
        self.assertIn("id", result)
        self.assertIn("base_url", result)
        self.assertIn("get_auth_header", result)
        self.assertEqual(len(result), 3)

    def test_missing_file(self):
        tmpdir = tempfile.mkdtemp()
        result = scan_connector_common_methods(tmpdir)
        self.assertEqual(result, [])


class TestScanKnownConnectors(TestCase):
    def test_finds_connectors(self):
        tmpdir = tempfile.mkdtemp()
        conn_dir = Path(tmpdir, "backend", "connector-integration", "src", "connectors")
        conn_dir.mkdir(parents=True)
        (conn_dir / "stripe.rs").write_text("// stripe")
        (conn_dir / "adyen.rs").write_text("// adyen")
        (conn_dir / "macros.rs").write_text("// macros")
        (conn_dir / "mod.rs").write_text("// mod")

        result = scan_known_connectors(tmpdir)
        self.assertEqual(len(result), 2)
        self.assertIn("adyen", result)
        self.assertIn("stripe", result)
        # macros and mod should be excluded
        self.assertNotIn("macros", result)
        self.assertNotIn("mod", result)


class TestScanAttemptStatusVariants(TestCase):
    def test_extracts_variants(self):
        tmpdir = tempfile.mkdtemp()
        enum_dir = Path(tmpdir, "backend", "common_enums", "src")
        enum_dir.mkdir(parents=True)
        (enum_dir / "enums.rs").write_text("""
pub enum AttemptStatus {
    #[default]
    Pending,
    Authorized,
    Charged,
    Failed,
    Voided,
}
""")
        result = scan_attempt_status_variants(tmpdir)
        self.assertEqual(len(result["variants"]), 5)
        self.assertEqual(result["default_variant"], "Pending")
        self.assertIn("Authorized", result["terminal_success"])
        self.assertIn("Charged", result["terminal_success"])
        self.assertNotIn("Pending", result["terminal_success"])
        self.assertNotIn("Failed", result["terminal_success"])

    def test_missing_file(self):
        tmpdir = tempfile.mkdtemp()
        result = scan_attempt_status_variants(tmpdir)
        self.assertEqual(result["variants"], [])
        self.assertIsNone(result["default_variant"])


class TestScanSensitiveFieldPatterns(TestCase):
    def test_finds_secret_fields(self):
        tmpdir = tempfile.mkdtemp()
        conn_dir = Path(tmpdir, "backend", "connector-integration", "src", "connectors")
        trans_dir = conn_dir / "stripe"
        trans_dir.mkdir(parents=True)
        (trans_dir / "transformers.rs").write_text("""
pub struct StripeAuth {
    pub api_key: Secret<String>,
    pub client_secret: Option<Secret<String>>,
    pub name: String,
}
""")
        result = scan_sensitive_field_patterns(tmpdir)
        self.assertIn("api_key", result)
        self.assertIn("client_secret", result)
        self.assertNotIn("name", result)

    def test_filters_generic_names(self):
        """The learner should filter out generic field names from learned data."""
        tmpdir = tempfile.mkdtemp()
        conn_dir = Path(tmpdir, "backend", "connector-integration", "src", "connectors")
        trans_dir = conn_dir / "stripe"
        trans_dir.mkdir(parents=True)
        (trans_dir / "transformers.rs").write_text("""
pub struct SomeStruct {
    pub id: Secret<String>,
    pub value: Secret<String>,
    pub data: Secret<String>,
    pub key: Secret<String>,
    pub access_token: Secret<String>,
    pub signing_key: Secret<String>,
}
""")
        result = scan_sensitive_field_patterns(tmpdir)
        # Generic names should be filtered out
        self.assertNotIn("id", result)
        self.assertNotIn("value", result)
        self.assertNotIn("data", result)
        self.assertNotIn("key", result)
        # Real sensitive names should be kept
        self.assertIn("access_token", result)
        self.assertIn("signing_key", result)

    def test_filters_short_names(self):
        """Field names <= 2 chars should be excluded."""
        tmpdir = tempfile.mkdtemp()
        conn_dir = Path(tmpdir, "backend", "connector-integration", "src", "connectors")
        trans_dir = conn_dir / "acme"
        trans_dir.mkdir(parents=True)
        (trans_dir / "transformers.rs").write_text("""
pub struct AcmeAuth {
    pub iv: Secret<String>,
    pub api_key: Secret<String>,
}
""")
        result = scan_sensitive_field_patterns(tmpdir)
        self.assertNotIn("iv", result)
        self.assertIn("api_key", result)


class TestScanErrorResponsePatterns(TestCase):
    def test_finds_error_structs(self):
        tmpdir = tempfile.mkdtemp()
        conn_dir = Path(tmpdir, "backend", "connector-integration", "src", "connectors")
        trans_dir = conn_dir / "stripe"
        trans_dir.mkdir(parents=True)
        (trans_dir / "transformers.rs").write_text("""
pub struct StripeErrorResponse {
    pub error: StripeErrorBody,
}

pub struct StripeErrorBody {
    pub message: String,
}
""")
        result = scan_error_response_patterns(tmpdir)
        self.assertIn("StripeErrorResponse", result)
        self.assertIn("StripeErrorBody", result)


class TestScanConventionalCommitConfig(TestCase):
    def test_returns_defaults_without_cog(self):
        tmpdir = tempfile.mkdtemp()
        result = scan_conventional_commit_config(tmpdir)
        self.assertEqual(result["source"], "default")
        self.assertIn("feat", result["commit_types"])
        self.assertIn("fix", result["commit_types"])

    def test_parses_cog_toml(self):
        tmpdir = tempfile.mkdtemp()
        (Path(tmpdir) / "cog.toml").write_text("""
[commit_types.feat]
changelog_title = "Features"

[commit_types.fix]
changelog_title = "Bug Fixes"
""")
        result = scan_conventional_commit_config(tmpdir)
        self.assertEqual(result["source"], "cog.toml")
        self.assertIn("feat", result["commit_types"])
        self.assertIn("fix", result["commit_types"])


class TestScanProtoConventions(TestCase):
    def test_extracts_package_name(self):
        tmpdir = tempfile.mkdtemp()
        proto_dir = Path(tmpdir) / "backend" / "grpc-api-types" / "proto"
        proto_dir.mkdir(parents=True)
        (proto_dir / "payment.proto").write_text(
            'syntax = "proto3";\npackage types;\n\nmessage PaymentRequest {}\n'
        )
        (proto_dir / "refund.proto").write_text(
            'syntax = "proto3";\npackage types;\n\nmessage RefundRequest {}\n'
        )
        result = scan_proto_conventions(tmpdir)
        self.assertEqual(result["package_name"], "types")

    def test_extracts_go_package(self):
        tmpdir = tempfile.mkdtemp()
        proto_dir = Path(tmpdir) / "backend" / "grpc-api-types" / "proto"
        proto_dir.mkdir(parents=True)
        (proto_dir / "payment.proto").write_text(
            'syntax = "proto3";\npackage types;\n'
            'option go_package = "github.com/juspay/connector-service/proto;proto";\n'
        )
        result = scan_proto_conventions(tmpdir)
        self.assertEqual(
            result["go_package"],
            "github.com/juspay/connector-service/proto;proto",
        )

    def test_extracts_service_names(self):
        tmpdir = tempfile.mkdtemp()
        proto_dir = Path(tmpdir) / "backend" / "grpc-api-types" / "proto"
        proto_dir.mkdir(parents=True)
        (proto_dir / "payment.proto").write_text(
            'syntax = "proto3";\npackage types;\n\n'
            "service PaymentService {\n  rpc Authorize(Req) returns (Resp);\n}\n"
            "service RefundService {\n  rpc Refund(Req) returns (Resp);\n}\n"
        )
        result = scan_proto_conventions(tmpdir)
        self.assertIn("PaymentService", result["service_names"])
        self.assertIn("RefundService", result["service_names"])

    def test_extracts_secret_string_fields(self):
        tmpdir = tempfile.mkdtemp()
        proto_dir = Path(tmpdir) / "backend" / "grpc-api-types" / "proto"
        proto_dir.mkdir(parents=True)
        (proto_dir / "payment.proto").write_text(
            'syntax = "proto3";\npackage types;\n\n'
            "message PaymentRequest {\n"
            "  SecretString card_number = 1;\n"
            "  optional SecretString cvv = 2;\n"
            "  string id = 3;\n"
            "}\n"
        )
        result = scan_proto_conventions(tmpdir)
        self.assertIn("card_number", result["secret_string_fields"])
        self.assertIn("cvv", result["secret_string_fields"])
        self.assertNotIn("id", result["secret_string_fields"])

    def test_skips_health_check_for_package(self):
        tmpdir = tempfile.mkdtemp()
        proto_dir = Path(tmpdir) / "backend" / "grpc-api-types" / "proto"
        proto_dir.mkdir(parents=True)
        (proto_dir / "payment.proto").write_text('syntax = "proto3";\npackage types;\n')
        (proto_dir / "health_check.proto").write_text(
            'syntax = "proto3";\npackage grpc.health.v1;\n'
        )
        result = scan_proto_conventions(tmpdir)
        # health_check's package should NOT influence the majority vote
        self.assertEqual(result["package_name"], "types")

    def test_missing_proto_dir(self):
        tmpdir = tempfile.mkdtemp()
        result = scan_proto_conventions(tmpdir)
        self.assertIsNone(result["package_name"])
        self.assertIsNone(result["go_package"])
        self.assertEqual(result["service_names"], [])
        self.assertEqual(result["secret_string_fields"], [])

    def test_majority_vote_for_package(self):
        tmpdir = tempfile.mkdtemp()
        proto_dir = Path(tmpdir) / "backend" / "grpc-api-types" / "proto"
        proto_dir.mkdir(parents=True)
        # 3 files with "types", 1 with "other"
        for name in ["a.proto", "b.proto", "c.proto"]:
            (proto_dir / name).write_text('syntax = "proto3";\npackage types;\n')
        (proto_dir / "d.proto").write_text('syntax = "proto3";\npackage other;\n')
        result = scan_proto_conventions(tmpdir)
        self.assertEqual(result["package_name"], "types")


class TestScanCompositeService(TestCase):
    def test_extracts_request_types(self):
        tmpdir = tempfile.mkdtemp()
        composite_dir = Path(tmpdir) / "backend" / "composite-service" / "src"
        composite_dir.mkdir(parents=True)
        (composite_dir / "payments.rs").write_text(
            "async fn process_composite_authorize(\n"
            "    &self,\n"
            "    request: tonic::Request<CompositeAuthorizeRequest>,\n"
            ") -> Result<tonic::Response<CompositeAuthorizeResponse>, tonic::Status> {}\n\n"
            "async fn process_composite_get(\n"
            "    &self,\n"
            "    request: tonic::Request<CompositeGetRequest>,\n"
            ") -> Result<tonic::Response<CompositeGetResponse>, tonic::Status> {}\n"
        )
        result = scan_composite_service(tmpdir)
        self.assertIn("Authorize", result["request_types"])
        self.assertIn("Get", result["request_types"])

    def test_extracts_access_token_impls(self):
        tmpdir = tempfile.mkdtemp()
        composite_dir = Path(tmpdir) / "backend" / "composite-service" / "src"
        composite_dir.mkdir(parents=True)
        (composite_dir / "payments.rs").write_text(
            "impl CompositeAccessTokenRequest for CompositeAuthorizeRequest {\n"
            "    fn payment_method(&self) -> Option<PaymentMethod> { todo!() }\n"
            "}\n\n"
            "impl CompositeAccessTokenRequest for CompositeGetRequest {\n"
            "    fn payment_method(&self) -> Option<PaymentMethod> { todo!() }\n"
            "}\n"
        )
        result = scan_composite_service(tmpdir)
        self.assertIn("Authorize", result["access_token_impls"])
        self.assertIn("Get", result["access_token_impls"])

    def test_extracts_process_methods(self):
        tmpdir = tempfile.mkdtemp()
        composite_dir = Path(tmpdir) / "backend" / "composite-service" / "src"
        composite_dir.mkdir(parents=True)
        (composite_dir / "payments.rs").write_text(
            "async fn process_composite_authorize(\n"
            "    &self, request: tonic::Request<CompositeAuthorizeRequest>,\n"
            ") {}\n\n"
            "async fn process_composite_get(\n"
            "    &self, request: tonic::Request<CompositeGetRequest>,\n"
            ") {}\n"
        )
        result = scan_composite_service(tmpdir)
        self.assertIn("process_composite_authorize", result["process_methods"])
        self.assertIn("process_composite_get", result["process_methods"])

    def test_filters_access_token_from_request_types(self):
        tmpdir = tempfile.mkdtemp()
        composite_dir = Path(tmpdir) / "backend" / "composite-service" / "src"
        composite_dir.mkdir(parents=True)
        (composite_dir / "payments.rs").write_text(
            "trait CompositeAccessTokenRequest {}\n"
            "impl CompositeAccessTokenRequest for CompositeAuthorizeRequest {}\n"
        )
        result = scan_composite_service(tmpdir)
        # "AccessToken" comes from the trait name itself, should be filtered
        self.assertNotIn("AccessToken", result["request_types"])
        self.assertIn("Authorize", result["request_types"])

    def test_missing_composite_dir(self):
        tmpdir = tempfile.mkdtemp()
        result = scan_composite_service(tmpdir)
        self.assertEqual(result["request_types"], [])
        self.assertEqual(result["access_token_impls"], [])
        self.assertEqual(result["process_methods"], [])


class TestLearnFunction(TestCase):
    def test_learn_returns_complete_structure(self):
        tmpdir = tempfile.mkdtemp()
        # Create minimal Cargo.toml
        Path(tmpdir, "Cargo.toml").write_text("""
[workspace]
members = ["backend/foo"]

[workspace.lints.clippy]
unwrap_used = "warn"
""")
        data = learn(tmpdir)
        self.assertEqual(data["schema_version"], SCHEMA_VERSION)
        self.assertIn("generated_at", data)
        self.assertIn("lints", data)
        self.assertIn("flows", data)
        self.assertIn("connector_common_methods", data)
        self.assertIn("known_connectors", data)
        self.assertIn("attempt_status", data)
        self.assertIn("sensitive_fields_from_code", data)
        self.assertIn("error_response_patterns", data)
        self.assertIn("commit_config", data)
        self.assertIn("proto_conventions", data)
        self.assertIn("composite_service", data)
        # Removed categories should not be present
        self.assertNotIn("workspace", data)
        self.assertNotIn("status_enum_fields_from_code", data)
        self.assertNotIn("test_patterns", data)

    def test_learn_empty_repo(self):
        tmpdir = tempfile.mkdtemp()
        data = learn(tmpdir)
        self.assertEqual(data["schema_version"], SCHEMA_VERSION)
        self.assertEqual(data["known_connectors"], [])


class TestStalenessWarning(TestCase):
    """Test the _warn_if_stale helper from cli.py."""

    def test_warns_on_old_data(self):
        from pr_review.cli import _warn_if_stale
        from unittest.mock import patch
        import time

        # 10 days ago
        old_time = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - 10 * 86400),
        )
        data = {"generated_at": old_time}

        with patch("click.echo") as mock_echo:
            _warn_if_stale(data, max_age_days=7)
            mock_echo.assert_called_once()
            call_args = mock_echo.call_args[0][0]
            self.assertIn("days old", call_args)

    def test_no_warning_on_fresh_data(self):
        from pr_review.cli import _warn_if_stale
        from unittest.mock import patch
        import time

        # 1 day ago
        fresh_time = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - 1 * 86400),
        )
        data = {"generated_at": fresh_time}

        with patch("click.echo") as mock_echo:
            _warn_if_stale(data, max_age_days=7)
            mock_echo.assert_not_called()

    def test_no_crash_on_missing_timestamp(self):
        from pr_review.cli import _warn_if_stale
        from unittest.mock import patch

        data = {}

        with patch("click.echo") as mock_echo:
            _warn_if_stale(data, max_age_days=7)
            mock_echo.assert_not_called()


class TestRulesWithLearnedData(TestCase):
    """Test that rules properly consume learned data."""

    def test_type_safety_rules_use_learned_context(self):
        from pr_review.rules.type_safety import get_rules

        learned = {
            "lints": {
                "clippy": {"unwrap_used": "warn", "expect_used": "deny"},
                "rust": {"unsafe_code": "forbid"},
            },
        }
        rules = get_rules(learned_data=learned)
        # TS-001 should have "warns on unwrap_used" in context
        ts001 = rules[0]
        self.assertIn("warns on unwrap_used", ts001._context)
        # TS-002 should have "denies expect_used" in context
        ts002 = rules[1]
        self.assertIn("denies expect_used", ts002._context)

    def test_type_safety_rules_use_defaults(self):
        from pr_review.rules.type_safety import get_rules

        rules = get_rules(learned_data=None)
        ts001 = rules[0]
        self.assertIn("unwrap_used", ts001._context)

    def test_connector_patterns_uses_learned_flow_map(self):
        from pr_review.rules.connector_patterns import get_rules, FlowMarkerTraitsRule

        learned = {
            "flows": {
                "flow_structs": ["Authorize", "PSync", "Capture"],
                "flow_trait_map": {
                    "Authorize": "PaymentAuthorizeV2",
                    "PSync": "PaymentSyncV2",
                    "Capture": "PaymentCapture",
                    "Void": "PaymentVoidV2",
                },
            },
        }
        rules = get_rules(learned_data=learned)
        # Find CP-008
        cp008 = [r for r in rules if r.rule_id == "CP-008"][0]
        self.assertIsInstance(cp008, FlowMarkerTraitsRule)
        self.assertEqual(len(cp008._flow_to_trait), 4)
        self.assertEqual(cp008._flow_to_trait["Capture"], "PaymentCapture")

    def test_connector_patterns_uses_learned_known_connectors(self):
        from pr_review.rules.connector_patterns import (
            get_rules,
            ConnectorRegistrationRule,
        )

        learned = {
            "known_connectors": ["stripe", "adyen", "braintree"],
            "flows": {"flow_structs": [], "flow_trait_map": {}},
        }
        rules = get_rules(learned_data=learned)
        cp007 = [r for r in rules if r.rule_id == "CP-007"][0]
        self.assertIsInstance(cp007, ConnectorRegistrationRule)
        self.assertEqual(len(cp007._known_connectors), 3)
        self.assertIn("stripe", cp007._known_connectors)

    def test_connector_patterns_uses_learned_error_response_patterns(self):
        from pr_review.rules.connector_patterns import (
            get_rules,
            TransformerHasErrorResponseRule,
        )

        learned = {
            "error_response_patterns": ["StripeErrorResponse", "AdyenErrorBody"],
            "flows": {"flow_structs": [], "flow_trait_map": {}},
        }
        rules = get_rules(learned_data=learned)
        cp005 = [r for r in rules if r.rule_id == "CP-005"][0]
        self.assertIsInstance(cp005, TransformerHasErrorResponseRule)
        self.assertEqual(len(cp005._known_error_structs), 2)
        self.assertIn("StripeErrorResponse", cp005._known_error_structs)

    def test_connector_patterns_uses_learned_common_methods(self):
        from pr_review.rules.connector_patterns import (
            get_rules,
            ConnectorCommonTraitRule,
        )

        learned = {
            "connector_common_methods": [
                "id",
                "base_url",
                "get_currency_unit",
                "get_auth_header",
                "build_error_response",
                "common_get_content_type",
            ],
            "flows": {"flow_structs": [], "flow_trait_map": {}},
        }
        rules = get_rules(learned_data=learned)
        cp003 = [r for r in rules if r.rule_id == "CP-003"][0]
        self.assertIsInstance(cp003, ConnectorCommonTraitRule)
        self.assertEqual(len(cp003._required_methods), 6)
        self.assertIn("common_get_content_type", cp003._required_methods)

    def test_security_rules_uses_learned_sensitive_fields(self):
        from pr_review.rules.security import get_rules, SensitiveFieldNotWrappedRule

        learned = {
            "sensitive_fields_from_code": ["merchant_key", "auth_token", "api_secret"],
        }
        rules = get_rules(learned_data=learned)
        se001 = [r for r in rules if r.rule_id == "SE-001"][0]
        self.assertIsInstance(se001, SensitiveFieldNotWrappedRule)
        self.assertIn("merchant_key", se001._learned_fields)
        self.assertIn("auth_token", se001._learned_fields)

    def test_security_rules_filters_generic_learned_fields(self):
        from pr_review.rules.security import get_rules, SensitiveFieldNotWrappedRule

        learned = {
            "sensitive_fields_from_code": [
                "id",
                "name",
                "api_secret",
                "value",
                "signing_key",
            ],
        }
        rules = get_rules(learned_data=learned)
        se001 = [r for r in rules if r.rule_id == "SE-001"][0]
        # Generic names should be filtered out by the rule
        self.assertNotIn("id", se001._learned_fields)
        self.assertNotIn("name", se001._learned_fields)
        self.assertNotIn("value", se001._learned_fields)
        # Real sensitive names should be kept
        self.assertIn("api_secret", se001._learned_fields)
        self.assertIn("signing_key", se001._learned_fields)

    def test_connector_patterns_uses_defaults(self):
        from pr_review.rules.connector_patterns import get_rules, FlowMarkerTraitsRule

        rules = get_rules(learned_data=None)
        cp008 = [r for r in rules if r.rule_id == "CP-008"][0]
        self.assertEqual(len(cp008._flow_to_trait), 7)  # Default has 7

    def test_domain_rules_uses_learned_status(self):
        from pr_review.rules.domain_rules import get_rules, StatusMappingDefaultRule

        learned = {
            "attempt_status": {
                "variants": ["Pending", "Authorized", "Charged", "Failed"],
                "terminal_success": ["Authorized", "Charged", "PartialCharged"],
                "default_variant": "Pending",
            },
        }
        rules = get_rules(learned_data=learned)
        dr003 = [r for r in rules if r.rule_id == "DR-003"][0]
        self.assertIsInstance(dr003, StatusMappingDefaultRule)
        # Should match PartialCharged now (from learned data)
        self.assertIsNotNone(
            dr003._bad_default.search("_ => AttemptStatus::PartialCharged")
        )
        # Should NOT match Pending (not in terminal_success)
        self.assertIsNone(dr003._bad_default.search("_ => AttemptStatus::Pending"))

    def test_domain_rules_uses_defaults(self):
        from pr_review.rules.domain_rules import get_rules, StatusMappingDefaultRule

        rules = get_rules(learned_data=None)
        dr003 = [r for r in rules if r.rule_id == "DR-003"][0]
        # Default includes Charged, Authorized, CaptureInitiated
        self.assertIsNotNone(dr003._bad_default.search("_ => AttemptStatus::Charged"))
        # Default no longer includes nonexistent Success
        self.assertIsNone(dr003._bad_default.search("_ => AttemptStatus::Success"))

    def test_pr_quality_uses_learned_commit_types(self):
        from pr_review.rules.pr_quality import get_rules, PRTitleConventionalCommitRule

        learned = {
            "commit_config": {
                "commit_types": ["feat", "fix", "custom"],
                "branch_prefixes": ["feat", "fix", "custom", "hotfix"],
            },
        }
        rules = get_rules(learned_data=learned)
        pq001 = [r for r in rules if r.rule_id == "PQ-001"][0]
        self.assertIsInstance(pq001, PRTitleConventionalCommitRule)
        # Should match custom type now
        self.assertIsNotNone(pq001._pattern.match("custom(scope): add thing"))
        # Should still match standard types
        self.assertIsNotNone(pq001._pattern.match("feat(scope): add thing"))

    def test_pr_quality_uses_defaults(self):
        from pr_review.rules.pr_quality import get_rules, PRTitleConventionalCommitRule

        rules = get_rules(learned_data=None)
        pq001 = [r for r in rules if r.rule_id == "PQ-001"][0]
        self.assertIsNotNone(pq001._pattern.match("feat(scope): add feature"))
        self.assertIsNone(pq001._pattern.match("custom(scope): add thing"))

    def test_proto_rules_uses_learned_conventions(self):
        from pr_review.rules.proto import get_rules, ProtoPackageDeclarationRule

        learned = {
            "proto_conventions": {
                "package_name": "mypackage",
                "go_package": "github.com/example/proto;proto",
                "secret_string_fields": ["merchant_key", "signing_secret"],
            },
        }
        rules = get_rules(learned_data=learned)
        pt001 = [r for r in rules if r.rule_id == "PT-001"][0]
        self.assertIsInstance(pt001, ProtoPackageDeclarationRule)
        self.assertEqual(pt001._expected_package, "mypackage")

    def test_proto_rules_uses_defaults(self):
        from pr_review.rules.proto import get_rules

        rules = get_rules(learned_data=None)
        pt001 = [r for r in rules if r.rule_id == "PT-001"][0]
        self.assertEqual(pt001._expected_package, "types")

    def test_composite_rules_uses_learned_data(self):
        from pr_review.rules.composite import get_rules, CompositeAccessTokenTraitRule

        learned = {
            "composite_service": {
                "request_types": ["Authorize", "Get"],
            },
        }
        rules = get_rules(learned_data=learned)
        cs002 = [r for r in rules if r.rule_id == "CS-002"][0]
        self.assertIsInstance(cs002, CompositeAccessTokenTraitRule)
        self.assertEqual(cs002._known_request_types, {"Authorize", "Get"})

    def test_composite_rules_uses_defaults(self):
        from pr_review.rules.composite import get_rules

        rules = get_rules(learned_data=None)
        cs002 = [r for r in rules if r.rule_id == "CS-002"][0]
        self.assertIsNone(cs002._known_request_types)

    def test_get_all_rules_with_learned_data(self):
        from pr_review.rules import get_all_rules

        learned = {
            "lints": {"clippy": {"unwrap_used": "warn"}, "rust": {}},
            "flows": {"flow_structs": [], "flow_trait_map": {}},
            "attempt_status": {
                "variants": [],
                "terminal_success": [],
                "default_variant": None,
            },
            "commit_config": {
                "commit_types": ["feat", "fix"],
                "branch_prefixes": ["feat", "fix"],
            },
        }
        rules = get_all_rules(learned_data=learned)
        self.assertEqual(len(rules), 63)

    def test_get_all_rules_without_learned_data(self):
        from pr_review.rules import get_all_rules

        rules = get_all_rules(learned_data=None)
        self.assertEqual(len(rules), 63)
