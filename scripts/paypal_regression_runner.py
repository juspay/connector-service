#!/usr/bin/env python3
"""Execute PayPal financial contracts through actual UCS gRPC mapping.

Fixture mode uses public inert authentication and a local HTTP response server.
It never labels a local mapping check as a live PayPal outcome. Live modes require
explicit environment inputs, durable journals and read-only reconciliation.
"""
import argparse
import copy
import contextlib
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT / 'crates/internal/integration-tests/src/connector_specs/paypal'
PROTECTED_ORDER = '0SG65781FC8888712'
PROTECTED_CAPTURE = '2K728570VG9010042'
PUBLIC_STATE = {'access_token': {'token': {'value': 'PUBLIC_INERT_FIXTURE_TOKEN'},
                                'token_type': 'Bearer', 'expires_in_seconds': 300}}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    os.replace(temporary, path)


def strict_keys(value, allowed, required):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError('Invalid contract shape or unknown fields')


def at(value, path):
    for key in path.split('.'):
        if isinstance(value, list) and key.isdigit():
            index = int(key)
            value = value[index] if index < len(value) else None
        elif isinstance(value, dict):
            value = value.get(key)
        else:
            return None
    return value


def normalize(value):
    if isinstance(value, dict):
        return {re.sub(r'(?<!^)(?=[A-Z])', '_', k).lower(): normalize(v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def number(value):
    if isinstance(value, bool):
        raise ValueError('Boolean is not money')
    if isinstance(value, str) and re.fullmatch(r'-?\d+', value):
        value = int(value)
    if not isinstance(value, int) or not -(2 ** 63) <= value < 2 ** 63:
        raise ValueError('Money is not an i64')
    return value


def load_contracts():
    order = json.loads((SPECS / 'order_reconciliation_contract.json').read_text())
    capture = json.loads((SPECS / 'capture_operation_chain.json').read_text())
    closure = json.loads((SPECS / 'financial_closure_chain.json').read_text())
    fixture = json.loads((SPECS / 'financial_reconciliation_fixtures.json').read_text())
    strict_keys(fixture, ['schema', 'provenance', 'cases'], ['schema', 'cases'])
    if fixture['schema'] != 'paypal-financial-reconciliation-fixtures/1':
        raise ValueError('Unknown fixture schema')
    expected = ([c['id'] for c in order['cases']] + [c['id'] for c in capture['source_regressions']]
                + [c['id'] for c in closure.get('refund_source_regressions', [])]
                + [c['id'] for c in closure.get('rsync_source_regressions', [])]
                + [c['id'] for c in closure.get('threeds_source_regressions', [])]
                + [c['id'] for c in closure.get('webhook_source_regressions', [])])
    actual = [c['id'] for c in fixture['cases']]
    if len(expected) != len(set(expected)) or len(actual) != len(set(actual)) or set(expected) != set(actual):
        raise ValueError('Missing, duplicate or unmatched contract case IDs')
    for case in fixture['cases']:
        strict_keys(case, ['id', 'rpc', 'request', 'http', 'repeat', 'expect', 'error_contains', 'omit_access_token', 'connector'],
                    ['id', 'rpc', 'request', 'http', 'repeat', 'expect'])
        strict_keys(case['http'], ['method', 'path', 'response', 'response_status', 'calls', 'request_body_contains', 'base_url_suffix', 'steps'],
                    ['method', 'path', 'response', 'response_status', 'calls', 'request_body_contains'])
        if case.get('connector', 'Paypal') not in ['Paypal', 'Stripe']:
            raise ValueError('Unsupported inert fixture connector')
        if case.get('connector') == 'Stripe' and case['rpc'] != 'CompositePaymentService/Authorize':
            raise ValueError('Shared connector control must use actual composite Authorize')
        if case['rpc'] not in ['PaymentService/Authorize', 'RecurringPaymentService/Charge', 'PaymentService/Get', 'PaymentService/Capture', 'PaymentService/Void', 'PaymentService/Refund', 'RefundService/Get',
                               'CompositePaymentService/Authorize', 'PaymentMethodAuthenticationService/PostAuthenticate',
                               'EventService/HandleEvent', 'EventService/ParseEvent']:
            raise ValueError('Unsupported fixture RPC')
        if not isinstance(case.get('omit_access_token', False), bool):
            raise ValueError('Invalid access-token omission flag')
        if 'steps' in case['http']:
            if not isinstance(case['http']['steps'], list) or not 1 <= len(case['http']['steps']) <= 8:
                raise ValueError('Invalid fixture HTTP sequence')
            for step in case['http']['steps']:
                strict_keys(step, ['method', 'path', 'response', 'response_status', 'request_body_contains', 'request_body_equals', 'authorization_matches_fresh_oauth'], ['method', 'path', 'response', 'response_status', 'request_body_contains'])
                if (step['method'] not in ['GET', 'POST'] or not step['path'].startswith(('/v1/oauth2/token', '/v2/'))
                        or step['response_status'] not in [200, 201, 204, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503]
                        or not isinstance(step['request_body_contains'], dict)
                        or not isinstance(step.get('authorization_matches_fresh_oauth', False), bool)):
                    raise ValueError('Invalid sequence step')
        if case['http'].get('base_url_suffix', '') not in ['', '?fields=payment_source', '#PUBLIC_FRAGMENT']:
            raise ValueError('Unsupported inert fixture base URL suffix')
        if case['http']['method'] not in ['GET', 'POST'] or not case['http']['path'].startswith(('/v2/', '/v3/vault/setup-tokens', '/v1/notifications/verify-webhook-signature', '/v1/payment_intents')):
            raise ValueError('Invalid fixture HTTP contract')
        if (isinstance(case['http']['calls'], bool) or not isinstance(case['http']['calls'], int)
                or not 0 <= case['http']['calls'] <= 8):
            raise ValueError('Invalid HTTP count')
        if (isinstance(case['http']['response_status'], bool)
                or case['http']['response_status'] not in [200, 201, 204, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503]):
            raise ValueError('Invalid HTTP fixture status')
        if not isinstance(case['http']['request_body_contains'], dict):
            raise ValueError('Invalid HTTP body assertions')
        if isinstance(case['repeat'], bool) or case['repeat'] not in [1, 2]:
            raise ValueError('Invalid repeat count')
        if not isinstance(case['expect'], dict) or not case['expect']:
            raise ValueError('Missing response assertions')
        for key, value in case['expect'].items():
            if key not in ['error_present', 'status', 'captured_amount', 'connector_refund_id', 'refund_amount_minor', 'refund_amount_currency', 'error_code', 'error_reason', 'source_verified'] and not key.startswith(('meta.', 'response.')):
                raise ValueError('Unknown assertion path')
            if key == 'error_present' and not isinstance(value, bool):
                raise ValueError('Invalid error assertion')
            if key == 'status' and not isinstance(value, str):
                raise ValueError('Invalid status assertion')
            if key in ['captured_amount', 'refund_amount_minor'] and value is not None:
                number(value)
        for name in ['amount', 'amount_to_capture', 'refund_amount']:
            if name in case['request']:
                number(case['request'][name]['minor_amount'])
        if 'payment_amount' in case['request']:
            number(case['request']['payment_amount'])
        metadata = json.loads(case['request'].get('connector_feature_data', {}).get('value', '{}'))
        if not case['rpc'].startswith('EventService/') and 'connector_feature_data' not in case['request']:
            raise ValueError('Financial fixture requires payment metadata')
        if metadata.get('order_id') == PROTECTED_ORDER or metadata.get('capture_id') == PROTECTED_CAPTURE:
            raise ValueError('Protected real resource cannot be a fixture')
    return fixture['cases']


OWNING_ROOTS = ['crates', 'scripts', 'config', '.cargo', 'Cargo.toml',
                'Cargo.lock', 'buf.yaml', 'buf.lock', 'buf.gen.yaml']


def owning_path(path):
    return (Path(path).suffix in {'.rs', '.proto', '.py', '.toml', '.lock', '.json', '.yaml', '.yml', '.sh'}
            and path not in {'creds.json', 'creds_dummy.json'} and 'target' not in Path(path).parts)


def git_paths(arguments):
    result = subprocess.run(['git', '-C', str(ROOT)] + arguments + ['--'] + OWNING_ROOTS,
                            capture_output=True, check=True)
    return {p.decode() for p in result.stdout.split(b'\0') if p and owning_path(p.decode())}


def owning_manifest():
    # Retain missing indexed paths explicitly. Dropping a deleted file would
    # otherwise let the remaining subset pretend to match the committed tree.
    paths = git_paths(['ls-files', '--cached', '--others', '--exclude-standard', '-z'])
    return {p: digest(ROOT / p) if (ROOT / p).is_file() else None for p in sorted(paths)}


def bindings(binary=None):
    commit = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, check=True).stdout.strip()
    manifest = owning_manifest()
    head_paths = git_paths(['ls-tree', '-r', '--name-only', '-z', commit])
    dirty = git_paths(['diff', '--name-only', '-z', commit])
    committed = set(manifest) == head_paths and not dirty and all(manifest.values())
    for path, hashed in manifest.items():
        saved = subprocess.run(['git', '-C', str(ROOT), 'show', commit + ':' + path], capture_output=True)
        committed = bool(committed and saved.returncode == 0
                         and hashlib.sha256(saved.stdout).hexdigest() == hashed)
    return {'commit': commit, 'source_sha256': manifest,
            'binary_sha256': digest(binary) if binary else None,
            'source_matches_commit': bool(committed), 'owning_dirty_paths': sorted(dirty),
            'owning_missing_paths': sorted(p for p, hashed in manifest.items() if hashed is None),
            'head_owning_paths_match': set(manifest) == head_paths}


def verify_build_receipt(path, current, binary):
    if not path or not binary or not current['source_matches_commit']:
        raise ValueError('Committed runtime requires actual build receipt and complete clean source manifest')
    receipt = json.loads(Path(path).read_text())
    if (receipt.get('schema') != 'ucs-actual-build-receipt/1'
            or receipt.get('commit') != current['commit']
            or receipt.get('source_sha256_before') != current['source_sha256']
            or receipt.get('source_sha256_after') != current['source_sha256']
            or receipt.get('binary_sha256') != current['binary_sha256']
            or receipt.get('exit_code') != 0
            or receipt.get('producer') != 'owned_actual_build'
            or not isinstance(receipt.get('build_pid'), int)
            or isinstance(receipt.get('build_pid'), bool)
            or receipt['build_pid'] <= 0):
        raise ValueError('Build receipt does not bind actual successful build to current owning source/binary')
    command = receipt.get('command', [])
    expected = ['cargo', 'build', '-p', 'grpc-server', '--bin', 'grpc-server']
    if (not isinstance(command, list) or command[:6] != expected
            or any(value in command for value in ['--lib', '--bins', '--all-targets'])
            or command.count('--bin') != 1
            or not any(value in command for value in ['--message-format=json', '--message-format=json-render-diagnostics'])):
        raise ValueError('Build receipt requires actual grpc-server binary build with Cargo JSON artifacts')
    log = Path(receipt.get('build_log', ''))
    if not log.is_file() or digest(log) != receipt.get('build_log_sha256'):
        raise ValueError('Build receipt missing immutable actual build log')
    events = []
    for line in log.read_bytes().splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                events.append(value)
        except (ValueError, UnicodeError):
            continue
    artifact = any(event.get('reason') == 'compiler-artifact'
                   and event.get('target', {}).get('name') == 'grpc-server'
                   and event.get('target', {}).get('kind') == ['bin']
                   and isinstance(event.get('executable'), str)
                   and Path(event['executable']).is_absolute()
                   and Path(event['executable']).resolve() == Path(binary).resolve()
                   and event['executable'] in event.get('filenames', [])
                   for event in events)
    finished = any(event.get('reason') == 'build-finished' and event.get('success') is True for event in events)
    if not artifact or not finished:
        raise ValueError('Build log lacks successful grpc-server executable compiler artifact')
    start, end = receipt.get('started_at_epoch'), receipt.get('finished_at_epoch')
    if (isinstance(start, bool) or isinstance(end, bool)
            or not isinstance(start, (int, float)) or not isinstance(end, (int, float))
            or start > end or end > time.time() + 5
            or Path(binary).stat().st_mtime > end + 5):
        raise ValueError('Build receipt time/binary provenance is invalid')
    return {'path': str(path), 'sha256': digest(path), 'commit': current['commit'],
            'binary_sha256': current['binary_sha256'], 'build_log_sha256': digest(log)}


@contextlib.contextmanager
def journal_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('JOURNAL_BUSY: another invocation owns this journal') from None
        yield
    finally:
        os.close(descriptor)


def verify_runtime(endpoint, binary):
    if not binary:
        raise ValueError('Actual runtime binary is required')
    host, port = endpoint.rsplit(':', 1)
    if host not in ['127.0.0.1', 'localhost'] or not port.isdigit():
        raise ValueError('Runtime binding requires local UCS endpoint')
    listeners = subprocess.run(['ss', '-H', '-ltnp', 'sport = :' + port],
                               capture_output=True, text=True, check=True).stdout
    pids = set(re.findall(r'pid=(\d+)', listeners))
    matches = [int(pid) for pid in pids if Path('/proc/' + pid + '/exe').exists()
               and digest('/proc/' + pid + '/exe') == digest(binary)]
    if len(matches) != 1:
        raise ValueError('Endpoint does not match exactly one supplied runtime binary')
    return matches[0]


def rpc(endpoint, method, request, config, token, inject_state=True, connector='paypal'):
    # Configuration and OAuth remain memory-only. Never emit argv, raw stderr,
    # headers or an unfiltered provider response into an artifact.
    q = copy.deepcopy(request)
    if inject_state and method == 'EventService/HandleEvent':
        q['access_token'] = {'token': {'value': token}, 'token_type': 'Bearer', 'expires_in_seconds': 300}
    elif inject_state and not method.startswith('EventService/'):
        q['state'] = {'access_token': {'token': {'value': token}, 'token_type': 'Bearer',
                                     'expires_in_seconds': 300}}
    command = ['grpcurl', '-plaintext', '-max-time', '40', '-format-error',
               '-expand-headers', '-H', 'x-connector-config: ${PAYPAL_REGRESSION_CONNECTOR_CONFIG}',
               '-H', 'x-connector: ' + connector, '-H', 'x-merchant-id: paypal-regression',
               '-H', 'x-tenant-id: public', '-d', '@', endpoint, 'types.' + method]
    environment = dict(os.environ, PAYPAL_REGRESSION_CONNECTOR_CONFIG=config)
    proc = subprocess.run(command, input=json.dumps(q), capture_output=True, text=True, timeout=45, env=environment)
    try:
        response = normalize(json.loads(proc.stdout)) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        response = {}
    error = proc.returncode != 0 or bool(response.get('error'))
    # Error text is used in-memory only for inert fixture local guard checks.
    error_text = proc.stderr + proc.stdout
    return response, error, error_text


def projection(response, error):
    result = {'error_present': error, 'source_verified': response.get('source_verified', False), 'status': response.get('status'),
              'captured_amount': response.get('captured_amount'),
              'connector_refund_id': response.get('connector_refund_id'),
              'refund_amount_minor': at(response, 'refund_amount.minor_amount'),
              'refund_amount_currency': at(response, 'refund_amount.currency'),
              'error_code': at(response, 'error.connector_details.code'),
              'error_reason': at(response, 'error.connector_details.reason'),
              'response': response}
    raw = at(response, 'connector_feature_data.value')
    if isinstance(raw, str):
        result['meta'] = json.loads(raw)
    return result


def assert_response(result, expected):
    failures = []
    for path, wanted in expected.items():
        actual = at(result, path)
        if isinstance(wanted, int) and not isinstance(wanted, bool):
            try:
                actual = number(actual)
            except ValueError:
                pass
        if actual != wanted:
            # Artifact contains assertion paths only, never arbitrary values.
            failures.append(path)
    return failures


class FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self):
        server = self.server
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            if 'application/x-www-form-urlencoded' in self.headers.get('Content-Type', ''):
                data = {key: values[0] for key, values in urllib.parse.parse_qs(body.decode('ascii')).items()}
            else:
                data = {}
        contract = server.case['http']
        steps = contract.get('steps')
        step_index = len(server.observations)
        expected = steps[min(step_index, len(steps) - 1)] if steps else contract
        failures = ['http.extra_step'] if steps and step_index >= len(steps) else []
        if self.command != expected['method']:
            failures.append('http.method')
        if self.path != expected['path']:
            failures.append('http.path')
        if 'request_body_equals' in expected and data != expected['request_body_equals']:
            failures.append('http.body_exact')
        fresh_matches = None
        if expected.get('authorization_matches_fresh_oauth'):
            fresh = steps[0]['response'].get('access_token') if steps else None
            fresh_matches = isinstance(fresh, str) and bool(fresh) and self.headers.get('Authorization') == 'Bearer ' + fresh
            if not fresh_matches:
                failures.append('http.fresh_oauth_not_propagated')
        for path, wanted in expected['request_body_contains'].items():
            if at(data, path) != wanted:
                failures.append('http.body.' + path)
        server.observations.append({'method': self.command, 'path': self.path,
                                    'body_sha256': hashlib.sha256(body).hexdigest(),
                                    'authorization_present': bool(self.headers.get('Authorization')),
                                    'authorization_value_recorded': False, 'fresh_oauth_matches': fresh_matches, 'failures': failures})
        payload = b'' if expected['response_status'] == 204 else json.dumps(expected['response']).encode()
        self.send_response(expected['response_status'] if not failures else 500)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = respond
    do_POST = respond


def fixture_mode(args, cases):
    host = args.endpoint.rsplit(':', 1)[0]
    if host not in ['127.0.0.1', 'localhost']:
        raise ValueError('Fixture UCS endpoint must be loopback')
    if not args.binary:
        raise ValueError('Fixture execution requires actual runtime binary for source binding')
    server = FixtureServer(('127.0.0.1', 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}/'
    config = json.dumps({'config': {'Paypal': {'client_id': 'PUBLIC_INERT_CLIENT',
                                              'client_secret': 'PUBLIC_INERT_SECRET', 'base_url': url}}})
    results = []
    try:
        for case in cases:
            server.case = case
            server.observations = []
            failures = []
            connector = case.get('connector', 'Paypal')
            case_config = ({'config': {'Stripe': {'api_key': 'PUBLIC_INERT_STRIPE_API_KEY', 'base_url': url}}}
                           if connector == 'Stripe' else json.loads(config))
            case_config['config'][connector]['base_url'] = url + case['http'].get('base_url_suffix', '')
            for _ in range(case['repeat']):
                try:
                    response, error, text = rpc(args.endpoint, case['rpc'], case['request'],
                                                json.dumps(case_config), PUBLIC_STATE['access_token']['token']['value'],
                                                inject_state=not case.get('omit_access_token', False), connector=connector.lower())
                except (OSError, subprocess.SubprocessError, ValueError):
                    response, error, text = {}, True, ''
                    failures.append('execution_error')
                failures.extend(assert_response(projection(response, error), case['expect']))
                if case.get('error_contains') and case['error_contains'] not in text:
                    failures.append('specific_local_error')
            observed = server.observations
            if len(observed) != case['http']['calls']:
                failures.append('http.call_count')
            for observation in observed:
                failures.extend(observation['failures'])
                if not observation['authorization_present']:
                    failures.append('http.authorization_missing')
            results.append({'case_id': case['id'], 'local_mapping_oracle': 'FAIL' if failures else 'PASS',
                            'failed_assertion_paths': sorted(set(failures)), 'wire': observed,
                            'evidence_state': 'IMPLEMENTED', 'provider_wire_graded': False,
                            'provider_live_verified': False})
    finally:
        server.shutdown()
        server.server_close()
    return {'mode': 'fixture', 'pass': all(r['local_mapping_oracle'] == 'PASS' for r in results),
            'case_count': len(results), 'cases': results, 'provider_calls': 0,
            'execution': 'Actual production UCS gRPC and HTTP mapping, local inert fixtures only'}


def financial_metadata(response):
    raw = at(response, 'connector_feature_data.value')
    parsed = json.loads(raw) if isinstance(raw, str) else {}
    allowed = ['order_id', 'authorize_id', 'capture_id', 'incremental_authorization_id',
               'psync_flow', 'reference_id']
    result = {key: value for key, value in parsed.items() if key in allowed}
    context = parsed.get('capture_context')
    if isinstance(context, dict):
        keys = ['capture_history_complete', 'authorization_closed', 'authorized_amount',
                'capture_amounts', 'capture_method', 'invoice_id', 'soft_descriptor']
        result['capture_context'] = {key: value for key, value in context.items() if key in keys}
    return result


def live_mode(args):
    with journal_lock(args.journal):
        return locked_live_mode(args)


def locked_live_mode(args):
    config = os.environ.get('UCS_CONNECTOR_CONFIG')
    token = os.environ.get('PAYPAL_ACCESS_TOKEN')
    if not config or not token:
        raise ValueError('OPERATOR_GAP: required live configuration environment missing')
    cfg = json.loads(config)
    paypal = at(cfg, 'config.Paypal')
    if not isinstance(paypal, dict):
        raise ValueError('Invalid live connector configuration shape')
    endpoint = urllib.parse.urlparse(paypal.get('base_url', 'https://api-m.sandbox.paypal.com/'))
    if endpoint.scheme != 'https' or endpoint.hostname not in ['api-m.sandbox.paypal.com', 'api.sandbox.paypal.com']:
        raise ValueError('Live regression modes require explicit PayPal sandbox host')
    journal = json.loads(args.journal.read_text()) if args.journal.exists() else {
        'schema': 'paypal-financial-regression-journal/1', 'operations': {}, 'run_identity': str(uuid.uuid4())}
    if journal.get('schema') != 'paypal-financial-regression-journal/1':
        raise ValueError('Unknown journal schema')

    cached_operations = []
    current_source = args.execution_binding

    def save():
        atomic(args.journal, journal)

    def get_order(metadata, identity):
        q = {'connector_transaction_id': identity, 'connector_feature_data': {'value': json.dumps(metadata)},
             'amount': {'minor_amount': 6000, 'currency': 'USD'}, 'capture_method': 'MANUAL_MULTIPLE',
             'merchant_request_id': journal['run_identity'], 'test_mode': True}
        return rpc(args.endpoint, 'PaymentService/Get', q, config, token)

    def perform(name, method, request):
        operations = journal['operations']
        existing = operations.get(name)
        request_sha = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        if existing:
            provenance = existing.get('source_binding')
            valid = (existing.get('request_sha256') == request_sha
                     and existing.get('method') == method
                     and isinstance(provenance, dict) and provenance.get('commit')
                     and provenance.get('source_sha256') and provenance.get('binary_sha256'))
            metadata = existing.get('reconcile_metadata') or financial_metadata(existing.get('response', {}))
            if metadata and metadata.get('order_id'):
                response, error, _ = get_order(metadata, metadata['order_id'])
                existing['read_only_reconciliation'] = {'error': error,
                    'observed_metadata': financial_metadata(response),
                    'captured_amount': response.get('captured_amount'),
                    'current_source_binding': current_source}
                save()
                if error:
                    raise ValueError('Read-only reconciliation failed; completed financial operation never replayed')
            elif existing.get('state') == 'completed':
                raise ValueError('Completed operation lacks actual identity for read-only reconciliation')
            if not valid:
                raise ValueError('JOURNAL_INPUT_OR_PROVENANCE_MISMATCH: preserve original; no financial replay')
            if existing.get('state') == 'completed':
                cached_operations.append({'operation': name, 'original_source_binding': provenance,
                                          'current_source_same': provenance == current_source,
                                          'current_mapping_verified': False})
                return existing['response']
            raise ValueError('AMBIGUOUS_OPERATION: read-only reconciliation retained; financial retry refused')
        metadata = financial_metadata(request)
        if (request.get('connector_transaction_id') in [PROTECTED_ORDER, PROTECTED_CAPTURE]
                or request.get('connector_order_id') == PROTECTED_ORDER
                or metadata.get('order_id') == PROTECTED_ORDER or metadata.get('capture_id') == PROTECTED_CAPTURE):
            raise ValueError('Protected completed capture must never be replayed')
        operations[name] = {'state': 'started', 'request_sha256': hashlib.sha256(
            json.dumps(request, sort_keys=True).encode()).hexdigest(), 'reconcile_metadata': metadata,
                            'method': method, 'source_binding': current_source}
        save()
        response, error, _ = rpc(args.endpoint, method, request, config, token)
        if error:
            operations[name]['state'] = 'uncertain'
            save()
            raise ValueError('OPERATION_ERROR: reconcile before any financial retry')
        safe = {'status': response.get('status'), 'captured_amount': response.get('captured_amount'),
                'connector_transaction_id': response.get('connector_transaction_id'),
                'connector_feature_data': {'value': json.dumps(financial_metadata(response))}}
        operations[name].update(state='completed', response=safe)
        save()
        return safe

    if args.mode == 'live-read-only':
        if not args.context:
            raise ValueError('Read-only mode requires original financial context file')
        metadata = json.loads(args.context.read_text())
        if metadata.get('order_id') != PROTECTED_ORDER:
            raise ValueError('Read-only reconciliation requires protected original order identity')
        response, error, _ = get_order(metadata, PROTECTED_ORDER)
        observed = financial_metadata(response)
        amount = at(observed, 'capture_context.capture_amounts.' + PROTECTED_CAPTURE + '.value')
        passed = not error and observed.get('order_id') == PROTECTED_ORDER and amount == '30.00'
        return {'mode': args.mode, 'pass': passed, 'evidence_state': 'VERIFIED' if passed else 'IMPLEMENTED',
                'provider_live_verified': passed, 'financial_posts': 0, 'protected_capture_replayed': False,
                'status': response.get('status'), 'captured_amount': response.get('captured_amount'),
                'actual_financial_metadata': observed, 'hs_reconciliation': 'NOT_RUN: separate actual HS before/after oracle required'}
    if not args.authorize:
        raise ValueError('Shared chain requires original public sandbox Authorize request file')
    request = json.loads(args.authorize.read_text())
    # Shared-chain mode creates a fresh raw-card authorization. It cannot be used
    # to resume a wallet/vault/native order or mutate the protected original order.
    payment_method = request.get('payment_method', {})
    if not isinstance(payment_method, dict) or not set(payment_method).intersection(['card', 'card_with_no_cvc']):
        raise ValueError('Shared chain requires fresh raw-card sandbox request')
    original_metadata = json.loads(at(request, 'connector_feature_data.value') or '{}')
    if (request.get('connector_order_id') or original_metadata.get('continuation')
            or any(original_metadata.get(key) for key in ['order_id', 'authorize_id', 'capture_id'])):
        raise ValueError('Shared chain cannot reuse an existing financial order')
    identity = journal['run_identity']
    request.update(merchant_order_id=identity, merchant_request_id=identity, capture_method='MANUAL_MULTIPLE',
                   amount={'minor_amount': 6000, 'currency': 'USD'})
    if isinstance(request.get('l2_l3_data'), dict):
        request['l2_l3_data'].setdefault('order_info', {})['merchant_order_reference_id'] = identity
    previous = perform('authorize', 'PaymentService/Authorize', request)
    if previous.get('status') != 'AUTHORIZED':
        raise ValueError('Authorization outcome oracle failed')
    auth = financial_metadata(previous)
    if at(auth, 'capture_context.authorized_amount.value') != '60.00':
        raise ValueError('Actual authorized amount oracle failed')
    first_request = None
    for sequence in [1, 2]:
        q = {'connector_transaction_id': previous['connector_transaction_id'],
             'connector_feature_data': previous['connector_feature_data'],
             'amount_to_capture': {'minor_amount': 3000, 'currency': 'USD'},
             'capture_method': 'MANUAL_MULTIPLE', 'merchant_capture_id': identity + f'-{sequence}',
             'merchant_request_id': identity + f'-{sequence}', 'test_mode': True,
             'multiple_capture_data': {'capture_sequence': sequence, 'capture_reference': identity + f'-{sequence}'}}
        if sequence == 1:
            first_request = q
        previous = perform(f'capture_{sequence}', 'PaymentService/Capture', q)
        expected_status = 'PARTIAL_CHARGED_AND_CHARGEABLE' if sequence == 1 else 'CHARGED'
        if previous.get('status') != expected_status or number(previous.get('captured_amount')) != 3000:
            raise ValueError('Actual capture operation amount/status oracle failed')
        if not financial_metadata(previous).get('capture_id'):
            raise ValueError('Actual capture identity missing')
    metadata = financial_metadata(previous)
    first_metadata = financial_metadata(journal['operations']['capture_1']['response'])
    if first_metadata.get('capture_id') == metadata.get('capture_id'):
        raise ValueError('Distinct captures returned the same identity')
    observed, error, _ = get_order(metadata, metadata['order_id'])
    if error or number(observed.get('captured_amount')) != 6000:
        raise ValueError('Authoritative order aggregate oracle failed')
    # An explicit fresh-chain idempotency row, never an automatic crash retry.
    retry = perform('intentional_same_operation_retry', 'PaymentService/Capture', first_request)
    first = financial_metadata(journal['operations']['capture_1']['response'])
    if (financial_metadata(retry).get('capture_id') != first.get('capture_id')
            or number(retry.get('captured_amount')) != 3000):
        raise ValueError('Idempotency returned a different capture identity')
    final, error, _ = get_order(metadata, metadata['order_id'])
    passed = not error and number(final.get('captured_amount')) == 6000
    return {'mode': args.mode, 'pass': passed, 'evidence_state': 'VERIFIED' if passed and not cached_operations else 'IMPLEMENTED',
            'provider_live_verified': passed and not cached_operations,
            'cached_operations': cached_operations,
            'current_mapping_verified': passed and not cached_operations,
            'cached_provider_result_is_current_verified': False,
            'captured_amount': final.get('captured_amount'),
            'actual_financial_metadata': financial_metadata(final), 'protected_capture_replayed': False,
            'provider_wire_graded': False,
            'literal_http_body_bytes_verified': False,
            'remaining_wire_oracles': ['actual emitted PayPal-Request-Id identity and literal HTTP body byte equality'],
            'pass_scope': 'live financial outcome oracles; emitted-wire proof must be reported separately'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['validate-contracts', 'fixture', 'live-read-only', 'shared-chain'])
    parser.add_argument('--endpoint', default='127.0.0.1:8001')
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--journal', type=Path)
    parser.add_argument('--context', type=Path)
    parser.add_argument('--authorize', type=Path)
    parser.add_argument('--require-committed', action='store_true')
    parser.add_argument('--build-receipt', type=Path)
    args = parser.parse_args()
    try:
        cases = load_contracts()
        before = bindings(args.binary)
        if args.mode != 'validate-contracts' and not args.require_committed:
            raise ValueError('All runtime execution requires --require-committed')
        receipt = verify_build_receipt(args.build_receipt, before, args.binary) if args.require_committed else None
        args.execution_binding = dict(before, actual_build_receipt=receipt)
        runtime_pid = verify_runtime(args.endpoint, args.binary) if args.mode != 'validate-contracts' else None
        if args.mode == 'validate-contracts':
            result = {'mode': args.mode, 'pass': True, 'contract_cases': len(cases),
                      'executed_cases': 0, 'evidence_state': 'IMPLEMENTED',
                      'provider_live_verified': False, 'provider_calls': 0}
        elif args.mode == 'fixture':
            result = fixture_mode(args, cases)
        else:
            if not args.journal:
                raise ValueError('Live execution requires a durable journal')
            result = live_mode(args)
        after_pid = verify_runtime(args.endpoint, args.binary) if runtime_pid else None
        if after_pid != runtime_pid:
            raise ValueError('Serving process changed during execution')
        after = bindings(args.binary)
        if before != after:
            raise ValueError('Source or runtime binary changed during execution')
        result['bindings'] = after
        result['runtime_pid'] = runtime_pid
        result['actual_build_receipt'] = receipt
        atomic(args.out, result)
        print(json.dumps({'mode': args.mode, 'pass': result['pass'],
                          'cases': result.get('case_count', result.get('contract_cases')),
                          'provider_live_verified': result.get('provider_live_verified', False)}))
        return 0 if result['pass'] else 1
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError):
        # Never serialize exception values: transports can include authentication.
        atomic(args.out, {'mode': args.mode, 'pass': False, 'error': 'EXECUTION_OR_CONTRACT_FAILURE',
                          'evidence_state': 'IMPLEMENTED', 'provider_live_verified': False})
        print('Execution/contract failure; no response or credential values emitted.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
