"""Step definitions for HTTP client sanity Gherkin tests (Python/behave)."""
import asyncio
import base64
import json
import os
import re
import time
from urllib.parse import urlparse, urlunparse

from behave import given, when, then

from payments.http_client import execute, HttpRequest, create_client, merge_http_config, DEFAULT_HTTP_CONFIG
from payments.generated import sdk_config_pb2

LANG = 'python'


@given('the echo server is running on port {port:d}')
def step_echo_server_running(context, port):
    """Echo server started externally; documentation step."""
    pass


@given('a "{method}" request to "{url}"')
def step_request_method_url(context, method, url):
    context.method = method
    context.url = url


@given('header "{name}" is "{value}"')
def step_set_header(context, name, value):
    context.headers[name] = value


@given("body is '{body}'")
def step_set_body_single(context, body):
    context.body = body.replace('\\r\\n', '\r\n').replace('\\n', '\n')


@given('body is "{body}"')
def step_set_body_double(context, body):
    context.body = body.replace('\\r\\n', '\r\n').replace('\\n', '\n')


@given('a response timeout of {ms:d} ms')
def step_set_response_timeout(context, ms):
    context.response_timeout_ms = ms


@given('the proxy is "{url}"')
def step_set_proxy(context, url):
    context.proxy_url = url


@when('the request is sent as scenario "{scenario_id}"')
def step_execute_request(context, scenario_id):
    context.scenario_id = scenario_id
    context.source_id = f'{LANG}_{scenario_id}'

    # Clean old artifacts
    capture_file = os.path.join(context.artifacts_dir, f'capture_{context.source_id}.json')
    actual_file = os.path.join(context.artifacts_dir, f'actual_{context.source_id}.json')
    for f in [capture_file, actual_file]:
        if os.path.exists(f):
            os.unlink(f)

    # Build headers
    headers = dict(context.headers)
    headers['x-source'] = context.source_id
    headers['x-scenario-id'] = context.scenario_id

    # Build body
    body = context.body
    if isinstance(body, str) and body.startswith('base64:'):
        body = base64.b64decode(body[7:])
    elif isinstance(body, str):
        body = body.encode('utf-8')

    # Create client with proxy config
    client_config = None
    if context.proxy_url:
        client_config = sdk_config_pb2.HttpConfig(
            proxy=sdk_config_pb2.ProxyOptions(http_url=context.proxy_url)
        )

    try:
        client = create_client(client_config)
    except Exception as e:
        code = getattr(e, 'error_code', None) or getattr(e, 'errorCode', None) or 'UNKNOWN_ERROR'
        context.sdk_error = {'code': str(code), 'message': str(e)}
        return

    request = HttpRequest(
        url=context.url,
        method=context.method,
        headers=headers,
        body=body,
    )

    # Handle timeouts
    override_config = None
    if context.response_timeout_ms is not None:
        override_config = sdk_config_pb2.HttpConfig(response_timeout_ms=context.response_timeout_ms)

    resolved_ms = None
    if override_config:
        base_cfg = client_config if client_config else DEFAULT_HTTP_CONFIG
        merged = merge_http_config(base_cfg, override_config)
        resolved_ms = (merged.total_timeout_ms, merged.connect_timeout_ms, merged.response_timeout_ms)

    try:
        sdk_response = asyncio.get_event_loop().run_until_complete(
            execute(request, client, resolved_ms)
        )
        ct = (sdk_response.headers.get('content-type', '') or '').lower()
        if 'application/octet-stream' in ct:
            body_str = base64.b64encode(sdk_response.body).decode('utf-8')
        else:
            body_str = sdk_response.body.decode('utf-8', errors='replace')

        context.sdk_response = {
            'statusCode': sdk_response.status_code,
            'headers': sdk_response.headers,
            'body': body_str,
        }
    except Exception as e:
        code = getattr(e, 'error_code', None) or getattr(e, 'errorCode', None) or 'UNKNOWN_ERROR'
        context.sdk_error = {'code': str(code), 'message': str(e)}

    # Wait for echo server to write capture
    time.sleep(0.2)


@then('the response status should be {status:d}')
def step_check_status(context, status):
    assert context.sdk_response is not None, \
        f'Expected response but got error: {context.sdk_error}'
    assert context.sdk_response['statusCode'] == status, \
        f"Status mismatch: expected {status}, got {context.sdk_response['statusCode']}"


@then("the response body should be '{expected}'")
def step_check_body_single(context, expected):
    assert context.sdk_response is not None, \
        f'Expected response but got error: {context.sdk_error}'
    assert context.sdk_response['body'] == expected, \
        f"Body mismatch: expected {expected!r}, got {context.sdk_response['body']!r}"


@then('the response body should be \'{expected}\'')
def step_check_body_escaped(context, expected):
    step_check_body_single(context, expected)


@then('the response header "{name}" should be "{value}"')
def step_check_header(context, name, value):
    assert context.sdk_response is not None, \
        f'Expected response but got error: {context.sdk_error}'
    actual = context.sdk_response['headers'].get(name.lower(), '')
    assert actual == value, f'Header "{name}" mismatch: expected "{value}", got "{actual}"'


@then('the response should have multi-value header "{name}" with values "{values_str}"')
def step_check_multi_header(context, name, values_str):
    assert context.sdk_response is not None, \
        f'Expected response but got error: {context.sdk_error}'
    expected_values = sorted(values_str.split(','))
    actual = context.sdk_response['headers'].get(name.lower(), '')
    if isinstance(actual, list):
        actual_values = sorted(actual)
    else:
        actual_values = sorted(v.strip() for v in actual.split(',') if v.strip())
    assert actual_values == expected_values, \
        f'Multi-value header "{name}" mismatch: expected {expected_values}, got {actual_values}'


@then('the SDK should return error "{expected_code}"')
def step_check_error(context, expected_code):
    assert context.sdk_error is not None, \
        f'Expected error "{expected_code}" but got response: {context.sdk_response}'
    assert context.sdk_error['code'] == expected_code, \
        f"Error code mismatch: expected \"{expected_code}\", got \"{context.sdk_error['code']}\""


def _normalize_url(url_str):
    try:
        parsed = urlparse(url_str)
        return urlunparse(parsed)
    except Exception:
        return url_str


def _normalize_multipart_body(body, headers):
    ct = ''
    for k, v in headers.items():
        if k.lower() == 'content-type':
            ct = v
            break
    if 'multipart/form-data' in ct:
        m = re.search(r'boundary=([^;]+)', ct)
        if m:
            return body.replace(m.group(1), 'REFERENCE')
    return body


@then('the server should have received the correct request')
def step_check_capture(context):
    capture_file = os.path.join(context.artifacts_dir, f'capture_{context.source_id}.json')
    assert os.path.exists(capture_file), \
        f'Echo server capture file not found for {context.source_id}'

    with open(capture_file, 'r') as f:
        capture = json.load(f)

    # Verify method
    assert capture['method'] == context.method, \
        f"Captured method mismatch: expected {context.method}, got {capture['method']}"

    # Verify URL
    assert _normalize_url(capture['url']) == _normalize_url(context.url), \
        f"Captured URL mismatch: expected {context.url}, got {capture['url']}"

    # Verify headers (ignoring transport noise)
    ignored = {'user-agent', 'host', 'connection', 'accept-encoding', 'content-length',
               'x-source', 'x-scenario-id', 'accept', 'keep-alive', 'date',
               'transfer-encoding', 'accept-language', 'sec-fetch-mode',
               'sec-fetch-site', 'sec-fetch-dest', 'priority'}

    expected_headers = {k.lower(): v for k, v in context.headers.items()
                        if k.lower() not in ignored}
    captured_headers = {k.lower(): str(v) for k, v in capture['headers'].items()
                        if k.lower() not in ignored}
    assert captured_headers == expected_headers, \
        f'Captured headers mismatch: expected {expected_headers}, got {captured_headers}'

    # Verify body
    expected_body = context.body if context.body else ''
    if isinstance(expected_body, str):
        expected_body = expected_body.replace('\\r\\n', '\r\n').replace('\\n', '\n')
    captured_body = capture.get('body', '')
    assert _normalize_multipart_body(captured_body, capture.get('headers', {})) == \
           _normalize_multipart_body(expected_body, context.headers), \
        f'Captured body mismatch: expected {expected_body!r}, got {captured_body!r}'
