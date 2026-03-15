"""Tests for gRPC server, proto, and composite service rules."""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field

from pr_review.diff_parser import DiffLine, DiffHunk, ChangedFile
from pr_review.file_classifier import ClassifiedFile, FileType
from pr_review.rules.base import Severity, Category


def _make_cf(
    path: str,
    file_type: FileType,
    content_lines: list[str] | None = None,
    is_new: bool = False,
    is_deleted: bool = False,
) -> ClassifiedFile:
    """Create a ClassifiedFile for testing."""
    added = []
    if content_lines:
        for i, line in enumerate(content_lines, 1):
            added.append(
                DiffLine(
                    line_number=i,
                    content=line,
                    is_added=True,
                    is_removed=False,
                    is_context=False,
                )
            )

    hunk = DiffHunk(
        old_start=1,
        old_count=0,
        new_start=1,
        new_count=len(added),
        header="@@ -0,0 +1,%d @@" % len(added),
        lines=added,
    )

    cf = ChangedFile(
        path=path,
        old_path=path,
        is_new=is_new,
        is_deleted=is_deleted,
        is_renamed=False,
        is_binary=False,
        hunks=[hunk],
    )
    return ClassifiedFile(changed_file=cf, file_type=file_type)


# ═══════════════════════════════════════════════════════════════════
# gRPC Server Rules
# ═══════════════════════════════════════════════════════════════════


class TestHandlerMustUseHttpHandlerMacroRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.grpc_server import HandlerMustUseHttpHandlerMacroRule

        self.rule = HandlerMustUseHttpHandlerMacroRule()

    def test_passes_when_macro_used(self):
        cf = _make_cf(
            "backend/grpc-server/src/http/handlers/payments.rs",
            FileType.GRPC_HANDLER,
            [
                "use crate::http::handlers::macros::http_handler;",
                "",
                "http_handler!(authorize, PaymentServiceAuthorizeRequest, PaymentServiceAuthorizeResponse, authorize, payments_service);",
            ],
        )
        findings = self.rule.check_file_content(
            cf,
            "\n".join(l.content for l in cf.changed_file.hunks[0].lines),
            "/repo",
            [],
        )
        self.assertEqual(len(findings), 0)

    def test_flags_hand_rolled_handler(self):
        code = """
use axum::Json;

pub async fn authorize(
    State(state): State<AppState>,
    Json(payload): Json<Request>,
) -> Result<Json<Response>, HttpError> {
    todo!()
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/http/handlers/payments.rs",
            FileType.GRPC_HANDLER,
            code.strip().split("\n"),
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "GR-001")

    def test_skips_macros_file(self):
        code = "pub async fn some_fn() {}"
        cf = _make_cf(
            "backend/grpc-server/src/http/handlers/macros.rs",
            FileType.GRPC_HANDLER,
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_skips_non_handler_files(self):
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(
            cf, "pub async fn handle() {}", "/repo", []
        )
        self.assertEqual(len(findings), 0)

    def test_skips_mod_file(self):
        cf = _make_cf(
            "backend/grpc-server/src/http/handlers/mod.rs",
            FileType.GRPC_HANDLER,
        )
        findings = self.rule.check_file_content(cf, "pub mod payments;", "/repo", [])
        self.assertEqual(len(findings), 0)


class TestServiceMustHaveTracingInstrumentRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.grpc_server import ServiceMustHaveTracingInstrumentRule

        self.rule = ServiceMustHaveTracingInstrumentRule()

    def test_passes_with_instrument(self):
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    #[tracing::instrument(
        name = "authorize",
        skip(self, request)
    )]
    async fn authorize(&self, request: tonic::Request<Req>) -> Result<tonic::Response<Resp>, tonic::Status> {
        todo!()
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_missing_instrument(self):
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    async fn authorize(&self, request: tonic::Request<Req>) -> Result<tonic::Response<Resp>, tonic::Status> {
        todo!()
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("authorize", findings[0].message)
        self.assertEqual(findings[0].rule_id, "GR-002")

    def test_passes_multiline_with_instrument(self):
        """Real-world rustfmt multi-line signature with tracing::instrument."""
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    #[tracing::instrument(
        name = "authorize",
        fields(merchant_id),
        skip(self, request)
    )]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName, |data| {}).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_multiline_missing_instrument(self):
        """Real-world rustfmt multi-line signature WITHOUT tracing::instrument."""
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName, |data| {}).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("authorize", findings[0].message)
        self.assertEqual(findings[0].rule_id, "GR-002")

    def test_multiline_multiple_methods_mixed(self):
        """Multiple multi-line methods: one with instrument, one without."""
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    #[tracing::instrument(
        name = "authorize",
        skip(self, request)
    )]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName, |data| {}).await
    }

    async fn void(
        &self,
        request: tonic::Request<PaymentServiceVoidRequest>,
    ) -> Result<tonic::Response<PaymentServiceVoidResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName, |data| {}).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("void", findings[0].message)

    def test_skips_non_service_files(self):
        code = "async fn authorize(&self, request: tonic::Request<Req>) {}"
        cf = _make_cf(
            "backend/grpc-server/src/http/handlers/payments.rs", FileType.GRPC_HANDLER
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_skips_file_without_async_trait(self):
        code = "async fn authorize(&self, request: tonic::Request<Req>) {}"
        cf = _make_cf("backend/grpc-server/src/server/utils.rs", FileType.GRPC_SERVICE)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)


class TestServiceMustUseGrpcLoggingWrapperRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.grpc_server import ServiceMustUseGrpcLoggingWrapperRule

        self.rule = ServiceMustUseGrpcLoggingWrapperRule()

    def test_passes_with_wrapper(self):
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    async fn authorize(&self, request: tonic::Request<Req>) -> Result<tonic::Response<Resp>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName, |data| {}).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_missing_wrapper(self):
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    async fn authorize(&self, request: tonic::Request<Req>) -> Result<tonic::Response<Resp>, tonic::Status> {
        let response = do_stuff(request).await?;
        Ok(tonic::Response::new(response))
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "GR-003")

    def test_passes_multiline_with_wrapper(self):
        """Real-world rustfmt multi-line signature with grpc_logging_wrapper."""
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    #[tracing::instrument(
        name = "authorize",
        skip(self, request)
    )]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName::Authorize, |data| {
            Box::pin(call_connector_authorize(data))
        }).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_multiline_missing_wrapper(self):
        """Real-world rustfmt multi-line signature WITHOUT grpc_logging_wrapper."""
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    #[tracing::instrument(
        name = "authorize",
        skip(self, request)
    )]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        let response = do_stuff(request).await?;
        Ok(tonic::Response::new(response))
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("authorize", findings[0].message)
        self.assertEqual(findings[0].rule_id, "GR-003")


class TestServiceMustCallGetConfigRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.grpc_server import ServiceMustCallGetConfigRule

        self.rule = ServiceMustCallGetConfigRule()

    def test_passes_with_config_call(self):
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    async fn authorize(&self, request: tonic::Request<Req>) -> Result<tonic::Response<Resp>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName, |data| {}).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_missing_config_call(self):
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    async fn authorize(&self, request: tonic::Request<Req>) -> Result<tonic::Response<Resp>, tonic::Status> {
        grpc_logging_wrapper(request, &service_name, Config::default(), FlowName, |data| {}).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "GR-004")

    def test_passes_multiline_with_config_call(self):
        """Real-world rustfmt multi-line signature with get_config_from_request."""
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    #[tracing::instrument(
        name = "authorize",
        skip(self, request)
    )]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName::Authorize, |data| {
            Box::pin(call_connector_authorize(data))
        }).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_multiline_missing_config_call(self):
        """Real-world rustfmt multi-line signature WITHOUT get_config_from_request."""
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    #[tracing::instrument(
        name = "authorize",
        skip(self, request)
    )]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        grpc_logging_wrapper(request, &service_name, Config::default(), FlowName::Authorize, |data| {
            Box::pin(call_connector_authorize(data))
        }).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("authorize", findings[0].message)
        self.assertEqual(findings[0].rule_id, "GR-004")

    def test_multiline_multiple_methods_one_missing_config(self):
        """Multiple multi-line methods: one with config, one without."""
        code = """
#[tonic::async_trait]
impl PaymentService for PaymentsImpl {
    #[tracing::instrument(name = "authorize", skip(self, request))]
    async fn authorize(
        &self,
        request: tonic::Request<PaymentServiceAuthorizeRequest>,
    ) -> Result<tonic::Response<PaymentServiceAuthorizeResponse>, tonic::Status> {
        let config = get_config_from_request(&request)?;
        grpc_logging_wrapper(request, &service_name, config, FlowName::Authorize, |data| {
            Box::pin(call_connector_authorize(data))
        }).await
    }

    #[tracing::instrument(name = "void", skip(self, request))]
    async fn void(
        &self,
        request: tonic::Request<PaymentServiceVoidRequest>,
    ) -> Result<tonic::Response<PaymentServiceVoidResponse>, tonic::Status> {
        grpc_logging_wrapper(request, &service_name, Config::default(), FlowName::Void, |data| {
            Box::pin(call_connector_void(data))
        }).await
    }
}
"""
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("void", findings[0].message)


class TestRouterMustUsePostRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.grpc_server import RouterMustUsePostRule

        self.rule = RouterMustUsePostRule()

    def test_flags_get_route(self):
        cf = _make_cf(
            "backend/grpc-server/src/http/router.rs",
            FileType.GRPC_ROUTER,
            ['.route("/payments/authorize", get(handlers::payments::authorize))'],
        )
        findings = self.rule.check(cf, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "GR-005")

    def test_passes_health_get(self):
        cf = _make_cf(
            "backend/grpc-server/src/http/router.rs",
            FileType.GRPC_ROUTER,
            ['.route("/health", get(handlers::health::health))'],
        )
        findings = self.rule.check(cf, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_passes_post_route(self):
        cf = _make_cf(
            "backend/grpc-server/src/http/router.rs",
            FileType.GRPC_ROUTER,
            ['.route("/payments/authorize", post(handlers::payments::authorize))'],
        )
        findings = self.rule.check(cf, "/repo", [])
        self.assertEqual(len(findings), 0)


class TestNoDirectTonicStatusConstructionRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.grpc_server import NoDirectTonicStatusConstructionRule

        self.rule = NoDirectTonicStatusConstructionRule()

    def test_flags_unknown_status(self):
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs",
            FileType.GRPC_SERVICE,
            ['    return Err(tonic::Status::unknown("something went wrong"));'],
        )
        findings = self.rule.check(cf, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "GR-006")

    def test_passes_specific_status(self):
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs",
            FileType.GRPC_SERVICE,
            ['    return Err(tonic::Status::internal("something went wrong"));'],
        )
        findings = self.rule.check(cf, "/repo", [])
        self.assertEqual(len(findings), 0)


# ═══════════════════════════════════════════════════════════════════
# Proto Rules
# ═══════════════════════════════════════════════════════════════════


class TestProtoPackageDeclarationRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.proto import ProtoPackageDeclarationRule

        self.rule = ProtoPackageDeclarationRule()

    def test_passes_with_correct_package(self):
        code = 'syntax = "proto3";\npackage types;\n'
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_wrong_package(self):
        code = 'syntax = "proto3";\npackage my.custom.package;\n'
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PT-001")

    def test_custom_expected_package(self):
        from pr_review.rules.proto import ProtoPackageDeclarationRule

        rule = ProtoPackageDeclarationRule(expected_package="ucs.v2")
        code = 'syntax = "proto3";\npackage ucs.v2;\n'
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_custom_expected_package_mismatch(self):
        from pr_review.rules.proto import ProtoPackageDeclarationRule

        rule = ProtoPackageDeclarationRule(expected_package="ucs.v2")
        code = 'syntax = "proto3";\npackage types;\n'
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)

    def test_flags_missing_package(self):
        code = 'syntax = "proto3";\nmessage Foo {}\n'
        cf = _make_cf("backend/grpc-api-types/proto/custom.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)

    def test_skips_health_check(self):
        code = 'syntax = "proto3";\npackage grpc.health.v1;\n'
        cf = _make_cf("backend/grpc-api-types/proto/health_check.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_skips_non_proto(self):
        cf = _make_cf("backend/something.rs", FileType.OTHER_RUST)
        findings = self.rule.check_file_content(cf, "no package here", "/repo", [])
        self.assertEqual(len(findings), 0)


class TestProtoEnumZeroValueRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.proto import ProtoEnumZeroValueRule

        self.rule = ProtoEnumZeroValueRule()

    def test_passes_with_unspecified(self):
        code = """
enum AttemptStatus {
    ATTEMPT_STATUS_UNSPECIFIED = 0;
    ATTEMPT_STATUS_SUCCESS = 1;
    ATTEMPT_STATUS_FAILURE = 2;
}
"""
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_missing_unspecified(self):
        code = """
enum PaymentStatus {
    SUCCESS = 0;
    FAILURE = 1;
}
"""
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("PaymentStatus", findings[0].message)
        self.assertEqual(findings[0].rule_id, "PT-002")

    def test_flags_enum_without_zero(self):
        code = """
enum Currency {
    USD = 1;
    EUR = 2;
}
"""
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)


class TestProtoSensitiveFieldsRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.proto import ProtoSensitiveFieldsMustUseSecretStringRule

        self.rule = ProtoSensitiveFieldsMustUseSecretStringRule()

    def test_flags_plain_string_email(self):
        code = "  string email = 2;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("email", findings[0].message)
        self.assertEqual(findings[0].rule_id, "PT-003")

    def test_passes_secret_string_email(self):
        code = "  SecretString email = 2;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_plain_string_api_key(self):
        code = "  string api_key = 1;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)

    def test_flags_plain_string_first_name(self):
        code = "  optional string first_name = 1;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)

    def test_passes_non_sensitive_field(self):
        code = "  string id = 1;\n  string product_name = 2;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_skips_comments(self):
        code = "  // string email = 2;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)


class TestProtoGoPackageOptionRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.proto import ProtoGoPackageOptionRule

        self.rule = ProtoGoPackageOptionRule()

    def test_passes_with_go_package(self):
        code = 'option go_package = "github.com/juspay/...;proto";\n'
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_missing_go_package(self):
        code = 'syntax = "proto3";\npackage ucs.v2;\n'
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PT-004")


class TestProtoFieldNumberGapRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.proto import ProtoFieldNumberGapRule

        self.rule = ProtoFieldNumberGapRule()

    def test_flags_large_gap_in_new_file(self):
        code = """
message Foo {
    string id = 1;
    string name = 2;
    string value = 50;
}
"""
        cf = _make_cf(
            "backend/grpc-api-types/proto/new.proto", FileType.PROTO, is_new=True
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PT-005")

    def test_passes_sequential_fields(self):
        code = """
message Foo {
    string id = 1;
    string name = 2;
    string value = 3;
}
"""
        cf = _make_cf(
            "backend/grpc-api-types/proto/new.proto", FileType.PROTO, is_new=True
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_skips_existing_files(self):
        code = """
message Foo {
    string id = 1;
    string value = 50;
}
"""
        cf = _make_cf(
            "backend/grpc-api-types/proto/existing.proto", FileType.PROTO, is_new=False
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)


# ═══════════════════════════════════════════════════════════════════
# Composite Service Rules
# ═══════════════════════════════════════════════════════════════════


class TestCompositeRequestDecompositionRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.composite import CompositeRequestDecompositionRule

        self.rule = CompositeRequestDecompositionRule()

    def test_passes_with_into_parts(self):
        code = """
    async fn process_composite_void(
        &self,
        request: tonic::Request<CompositeVoidRequest>,
    ) -> Result<tonic::Response<CompositeVoidResponse>, tonic::Status> {
        let (metadata, extensions, payload) = request.into_parts();
        todo!()
    }
"""
        cf = _make_cf(
            "backend/composite-service/src/payments.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_missing_into_parts(self):
        code = """
    async fn process_composite_void(
        &self,
        request: tonic::Request<CompositeVoidRequest>,
    ) -> Result<tonic::Response<CompositeVoidResponse>, tonic::Status> {
        let payload = request.into_inner();
        todo!()
    }
"""
        cf = _make_cf(
            "backend/composite-service/src/payments.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CS-001")
        self.assertIn("process_composite_void", findings[0].message)

    def test_skips_non_composite(self):
        cf = _make_cf(
            "backend/grpc-server/src/server/payments.rs", FileType.GRPC_SERVICE
        )
        findings = self.rule.check_file_content(
            cf, "async fn process_composite_void() {}", "/repo", []
        )
        self.assertEqual(len(findings), 0)


class TestCompositeAccessTokenTraitRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.composite import CompositeAccessTokenTraitRule

        self.rule = CompositeAccessTokenTraitRule()

    def test_passes_when_trait_implemented(self):
        code = """
impl CompositeAccessTokenRequest for CompositeVoidRequest {
    fn payment_method(&self) -> Option<PaymentMethod> { self.payment_method.clone() }
    fn state(&self) -> Option<&ConnectorState> { self.state.as_ref() }
    fn build_access_token_request(&self, connector: &ConnectorEnum) -> Req { todo!() }
}

async fn process_composite_void(&self, request: tonic::Request<CompositeVoidRequest>) {}
"""
        cf = _make_cf(
            "backend/composite-service/src/payments.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_missing_trait_impl(self):
        code = """
async fn process_composite_void(&self, request: tonic::Request<CompositeVoidRequest>) {}
"""
        cf = _make_cf(
            "backend/composite-service/src/payments.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CS-002")
        self.assertIn("CompositeVoidRequest", findings[0].message)


class TestCompositeMetadataPropagationRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.composite import CompositeMetadataPropagationRule

        self.rule = CompositeMetadataPropagationRule()

    def test_passes_with_metadata_propagation(self):
        code = """
        let mut void_request = tonic::Request::new(void_payload);
        *void_request.metadata_mut() = metadata.clone();
        *void_request.extensions_mut() = extensions.clone();
"""
        cf = _make_cf(
            "backend/composite-service/src/payments.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_missing_metadata(self):
        code = """
        let mut void_request = tonic::Request::new(void_payload);
        let response = service.void(void_request).await?;
"""
        cf = _make_cf(
            "backend/composite-service/src/payments.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CS-003")


class TestCompositeForeignFromRule(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.composite import CompositeForeignFromRule

        self.rule = CompositeForeignFromRule()

    def test_passes_with_foreign_from(self):
        code = """
impl ForeignFrom<&CompositeVoidRequest> for PaymentServiceVoidRequest {
    fn foreign_from(item: &CompositeVoidRequest) -> Self { todo!() }
}
"""
        cf = _make_cf(
            "backend/composite-service/src/transformers.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)

    def test_flags_raw_from(self):
        code = """
impl From<&CompositeVoidRequest> for PaymentServiceVoidRequest {
    fn from(item: &CompositeVoidRequest) -> Self { todo!() }
}
"""
        cf = _make_cf(
            "backend/composite-service/src/transformers.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CS-004")

    def test_passes_when_both_present(self):
        code = """
impl ForeignFrom<&Foo> for Bar {
    fn foreign_from(item: &Foo) -> Self { todo!() }
}
impl From<&Baz> for Qux {
    fn from(item: &Baz) -> Self { todo!() }
}
"""
        cf = _make_cf(
            "backend/composite-service/src/transformers.rs", FileType.COMPOSITE_SERVICE
        )
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        # When both are present, it's fine (ForeignFrom is already in use)
        self.assertEqual(len(findings), 0)


# ═══════════════════════════════════════════════════════════════════
# Proto / Composite Rules with Learned Data
# ═══════════════════════════════════════════════════════════════════


class TestProtoSensitiveFieldsWithLearnedData(unittest.TestCase):
    def setUp(self):
        from pr_review.rules.proto import ProtoSensitiveFieldsMustUseSecretStringRule

        self.rule = ProtoSensitiveFieldsMustUseSecretStringRule(
            learned_secret_fields=["merchant_key", "routing_key", "connector_token"],
        )

    def test_flags_learned_sensitive_field(self):
        code = "  string merchant_key = 1;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("merchant_key", findings[0].message)

    def test_flags_learned_connector_token(self):
        code = "  string connector_token = 5;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)

    def test_still_flags_default_sensitive_field(self):
        code = "  string api_key = 1;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)

    def test_passes_non_sensitive_field(self):
        code = "  string product_name = 1;\n"
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = self.rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 0)


class TestProtoGoPackageWithLearnedData(unittest.TestCase):
    def test_suggestion_uses_learned_go_package(self):
        from pr_review.rules.proto import ProtoGoPackageOptionRule

        rule = ProtoGoPackageOptionRule(
            expected_go_package="github.com/juspay/custom/proto;proto"
        )
        code = 'syntax = "proto3";\npackage types;\n'
        cf = _make_cf("backend/grpc-api-types/proto/payment.proto", FileType.PROTO)
        findings = rule.check_file_content(cf, code, "/repo", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("github.com/juspay/custom/proto;proto", findings[0].suggestion)


class TestCompositeAccessTokenWithLearnedData(unittest.TestCase):
    def test_with_known_request_types(self):
        from pr_review.rules.composite import CompositeAccessTokenTraitRule

        rule = CompositeAccessTokenTraitRule(
            known_request_types=["Authorize", "Get", "Void"]
        )
        # The known_request_types are stored but the rule still scans content
        # to find used types and their trait impls
        code = """
impl CompositeAccessTokenRequest for CompositeAuthorizeRequest {
    fn payment_method(&self) -> Option<PaymentMethod> { todo!() }
}

async fn process_composite_authorize(&self, request: tonic::Request<CompositeAuthorizeRequest>) {}
async fn process_composite_get(&self, request: tonic::Request<CompositeGetRequest>) {}
"""
        cf = _make_cf(
            "backend/composite-service/src/payments.rs", FileType.COMPOSITE_SERVICE
        )
        findings = rule.check_file_content(cf, code, "/repo", [])
        # CompositeGetRequest is used but missing trait impl
        self.assertEqual(len(findings), 1)
        self.assertIn("CompositeGetRequest", findings[0].message)


class TestProtoRulesViaGetRulesWithLearnedData(unittest.TestCase):
    def test_get_rules_with_learned_proto_conventions(self):
        from pr_review.rules.proto import get_rules, ProtoPackageDeclarationRule

        learned = {
            "proto_conventions": {
                "package_name": "custom.pkg",
                "go_package": "github.com/example/proto;proto",
                "secret_string_fields": ["merchant_secret"],
            },
        }
        rules = get_rules(learned_data=learned)
        self.assertEqual(len(rules), 5)
        # PT-001 should use the learned package name
        pt001 = rules[0]
        self.assertIsInstance(pt001, ProtoPackageDeclarationRule)
        self.assertEqual(pt001._expected_package, "custom.pkg")

    def test_get_rules_without_learned_data(self):
        from pr_review.rules.proto import get_rules

        rules = get_rules(learned_data=None)
        self.assertEqual(len(rules), 5)
        # Should default to "types"
        pt001 = rules[0]
        self.assertEqual(pt001._expected_package, "types")


class TestCompositeRulesViaGetRulesWithLearnedData(unittest.TestCase):
    def test_get_rules_with_learned_composite_data(self):
        from pr_review.rules.composite import get_rules, CompositeAccessTokenTraitRule

        learned = {
            "composite_service": {
                "request_types": ["Authorize", "Get", "Void"],
                "access_token_impls": ["Authorize", "Get"],
                "process_methods": [
                    "process_composite_authorize",
                    "process_composite_get",
                ],
            },
        }
        rules = get_rules(learned_data=learned)
        self.assertEqual(len(rules), 4)
        cs002 = [r for r in rules if r.rule_id == "CS-002"][0]
        self.assertIsInstance(cs002, CompositeAccessTokenTraitRule)
        self.assertEqual(cs002._known_request_types, {"Authorize", "Get", "Void"})

    def test_get_rules_without_learned_data(self):
        from pr_review.rules.composite import get_rules

        rules = get_rules(learned_data=None)
        self.assertEqual(len(rules), 4)
        cs002 = [r for r in rules if r.rule_id == "CS-002"][0]
        self.assertIsNone(cs002._known_request_types)


# ═══════════════════════════════════════════════════════════════════
# File Classifier Tests for new types
# ═══════════════════════════════════════════════════════════════════


class TestFileClassifierNewTypes(unittest.TestCase):
    def _classify(self, path: str) -> FileType:
        from pr_review.file_classifier import classify_file

        cf = ChangedFile(
            path=path,
            old_path=path,
            is_new=False,
            is_deleted=False,
            is_renamed=False,
            is_binary=False,
            hunks=[],
        )
        return classify_file(cf).file_type

    def test_composite_service(self):
        self.assertEqual(
            self._classify("backend/composite-service/src/payments.rs"),
            FileType.COMPOSITE_SERVICE,
        )

    def test_composite_transformers(self):
        self.assertEqual(
            self._classify("backend/composite-service/src/transformers.rs"),
            FileType.COMPOSITE_SERVICE,
        )

    def test_grpc_handler(self):
        self.assertEqual(
            self._classify("backend/grpc-server/src/http/handlers/payments.rs"),
            FileType.GRPC_HANDLER,
        )

    def test_grpc_handler_composite(self):
        self.assertEqual(
            self._classify(
                "backend/grpc-server/src/http/handlers/composite/payments.rs"
            ),
            FileType.GRPC_HANDLER,
        )

    def test_grpc_service(self):
        self.assertEqual(
            self._classify("backend/grpc-server/src/server/payments.rs"),
            FileType.GRPC_SERVICE,
        )

    def test_grpc_router(self):
        self.assertEqual(
            self._classify("backend/grpc-server/src/http/router.rs"),
            FileType.GRPC_ROUTER,
        )

    def test_ffi(self):
        self.assertEqual(
            self._classify("backend/ffi/src/handlers/payments.rs"),
            FileType.FFI,
        )

    def test_grpc_server_other(self):
        # Files in grpc-server but not in handlers/server/router should still be GRPC_SERVER
        self.assertEqual(
            self._classify("backend/grpc-server/src/http/state.rs"),
            FileType.GRPC_SERVER,
        )

    def test_grpc_server_utils(self):
        self.assertEqual(
            self._classify("backend/grpc-server/src/utils.rs"),
            FileType.GRPC_SERVER,
        )


# ═══════════════════════════════════════════════════════════════════
# Rule Module Tests
# ═══════════════════════════════════════════════════════════════════


class TestRuleModules(unittest.TestCase):
    def test_grpc_server_rule_count(self):
        from pr_review.rules.grpc_server import get_rules

        rules = get_rules()
        self.assertEqual(len(rules), 6)

    def test_proto_rule_count(self):
        from pr_review.rules.proto import get_rules

        rules = get_rules()
        self.assertEqual(len(rules), 5)

    def test_composite_rule_count(self):
        from pr_review.rules.composite import get_rules

        rules = get_rules()
        self.assertEqual(len(rules), 4)

    def test_all_rule_ids_unique(self):
        from pr_review.rules import get_all_rules

        rules = get_all_rules()
        ids = [r.rule_id for r in rules]
        dupes = [x for x in ids if ids.count(x) > 1]
        self.assertEqual(len(dupes), 0, f"Duplicate rule IDs: {dupes}")

    def test_grpc_server_rule_ids(self):
        from pr_review.rules.grpc_server import get_rules

        ids = [r.rule_id for r in get_rules()]
        self.assertEqual(
            ids, ["GR-001", "GR-002", "GR-003", "GR-004", "GR-005", "GR-006"]
        )

    def test_proto_rule_ids(self):
        from pr_review.rules.proto import get_rules

        ids = [r.rule_id for r in get_rules()]
        self.assertEqual(ids, ["PT-001", "PT-002", "PT-003", "PT-004", "PT-005"])

    def test_composite_rule_ids(self):
        from pr_review.rules.composite import get_rules

        ids = [r.rule_id for r in get_rules()]
        self.assertEqual(ids, ["CS-001", "CS-002", "CS-003", "CS-004"])


if __name__ == "__main__":
    unittest.main()
