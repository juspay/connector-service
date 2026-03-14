"""Thin step definitions for HTTP client sanity Gherkin tests (Python/behave).

Execute the SDK request and write actual JSON. All assertion/normalization
logic is delegated to the shared judge_scenario.js (single source of truth).
"""
import asyncio
import base64
import json
import os
import subprocess
import time

from behave import given, when, then

from payments.http_client import execute, HttpRequest, create_client, merge_http_config, DEFAULT_HTTP_CONFIG
from payments.generated import sdk_config_pb2

LANG = 'python'
JUDGE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', '..', 'tests', 'client_sanity', 'judge_scenario.js'))


# ── Given ────────────────────────────────────────────────────────

@given('the echo server is running on port {port:d}')
def step_echo_server(context, port):
    pass  # started externally


@given('a "{method}" request to "{url}"')
def step_request(context, method, url):
    context.method = method
    context.url = url


@given('header "{name}" is "{value}"')
def step_header(context, name, value):
    context.headers[name] = value


@given("body is '{body}'")
def step_body_single(context, body):
    context.body = body.replace('\\r\\n', '\r\n').replace('\\n', '\n')


@given('body is "{body}"')
def step_body_double(context, body):
    context.body = body.replace('\\r\\n', '\r\n').replace('\\n', '\n')


@given('a response timeout of {ms:d} ms')
def step_timeout(context, ms):
    context.response_timeout_ms = ms


@given('the proxy is "{url}"')
def step_proxy(context, url):
    context.proxy_url = url


# ── When (thin: execute + write actual JSON) ─────────────────────

@when('the request is sent as scenario "{scenario_id}"')
def step_execute(context, scenario_id):
    context.scenario_id = scenario_id
    context.source_id = f'{LANG}_{scenario_id}'

    actual_file = os.path.join(context.artifacts_dir, f'actual_{context.source_id}.json')
    capture_file = os.path.join(context.artifacts_dir, f'capture_{context.source_id}.json')
    for f in [actual_file, capture_file]:
        if os.path.exists(f):
            os.unlink(f)

    headers = dict(context.headers)
    headers['x-source'] = context.source_id
    headers['x-scenario-id'] = scenario_id

    body = context.body
    if isinstance(body, str) and body.startswith('base64:'):
        body = base64.b64decode(body[7:])
    elif isinstance(body, str):
        body = body.encode('utf-8')

    client_config = None
    if context.proxy_url:
        client_config = sdk_config_pb2.HttpConfig(
            proxy=sdk_config_pb2.ProxyOptions(http_url=context.proxy_url))

    try:
        client = create_client(client_config)
    except Exception as e:
        code = getattr(e, 'error_code', None) or getattr(e, 'errorCode', None) or 'UNKNOWN_ERROR'
        _write_json(actual_file, {'error': {'code': str(code), 'message': str(e)}})
        return

    override = None
    if context.response_timeout_ms is not None:
        override = sdk_config_pb2.HttpConfig(response_timeout_ms=context.response_timeout_ms)

    resolved_ms = None
    if override:
        base = client_config if client_config else DEFAULT_HTTP_CONFIG
        merged = merge_http_config(base, override)
        resolved_ms = (merged.total_timeout_ms, merged.connect_timeout_ms, merged.response_timeout_ms)

    request = HttpRequest(url=context.url, method=context.method, headers=headers, body=body)
    output = {}

    try:
        resp = asyncio.get_event_loop().run_until_complete(execute(request, client, resolved_ms))
        ct = (resp.headers.get('content-type', '') or '').lower()
        body_str = (base64.b64encode(resp.body).decode('utf-8')
                    if 'application/octet-stream' in ct
                    else resp.body.decode('utf-8', errors='replace'))
        output['response'] = {'statusCode': resp.status_code, 'headers': resp.headers, 'body': body_str}
    except Exception as e:
        code = getattr(e, 'error_code', None) or getattr(e, 'errorCode', None) or 'UNKNOWN_ERROR'
        output['error'] = {'code': str(code), 'message': str(e)}

    _write_json(actual_file, output)
    time.sleep(0.2)  # wait for echo server capture


# ── Then (delegate ALL assertions to the shared judge) ───────────

@then('the response status should be {status:d}')
def step_status(context, status):
    pass  # validated by judge


@then("the response body should be '{expected}'")
def step_body_check_single(context, expected):
    pass  # validated by judge


@then('the response body should be \'{expected}\'')
def step_body_check_escaped(context, expected):
    pass  # validated by judge


@then('the response header "{name}" should be "{value}"')
def step_header_check(context, name, value):
    pass  # validated by judge


@then('the response should have multi-value header "{name}" with values "{values_str}"')
def step_multi_header_check(context, name, values_str):
    pass  # validated by judge


@then('the SDK should return error "{expected_code}"')
def step_error_check(context, expected_code):
    _run_judge(context)


@then('the server should have received the correct request')
def step_capture_check(context):
    _run_judge(context)


# ── Helpers ──────────────────────────────────────────────────────

def _write_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def _run_judge(context):
    if getattr(context, '_judged', False):
        return
    context._judged = True
    result = subprocess.run(
        ['node', JUDGE, LANG, context.scenario_id],
        capture_output=True, text=True)
    if result.returncode != 0:
        msg = f'Judge FAILED for {context.scenario_id}'
        try:
            msg = json.loads(result.stdout)['message']
        except Exception:
            pass
        raise AssertionError(msg)
