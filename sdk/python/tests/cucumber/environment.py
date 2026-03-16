"""Behave environment hooks for HTTP client sanity tests."""
import os
import sys

# Add SDK src and generated proto dirs to import path.
sdk_src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
sdk_generated = os.path.join(sdk_src, 'payments', 'generated')
sys.path.insert(0, sdk_generated)
sys.path.insert(0, sdk_src)

ARTIFACTS_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'tests', 'client_sanity', 'artifacts'))

LANG = 'python'
SKIP_TAGS = {'@skip_python'}


def before_scenario(context, scenario):
    """Reset state and check skip tags."""
    context.base_url = ''
    context.method = ''
    context.url = ''
    context.headers = {}
    context.query_params = []
    context.body = None
    context.proxy_url = None
    context.response_timeout_ms = None
    context.scenario_id = ''
    context.source_id = ''
    context.sdk_response = None
    context.sdk_error = None
    context.artifacts_dir = ARTIFACTS_DIR

    tags = set(scenario.tags) | set(scenario.feature.tags)
    if tags & SKIP_TAGS:
        scenario.skip('Skipped for Python SDK')
