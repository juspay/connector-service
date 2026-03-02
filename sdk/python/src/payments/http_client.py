import time
import json
import requests
from typing import Optional, Dict, Union, Any
from dataclasses import dataclass
from .generated import sdk_options_pb2

# Centralized defaults from Protobuf Single Source of Truth
Defaults = sdk_options_pb2.SdkDefault

@dataclass
class HttpRequest:
    url: str
    method: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[Union[str, bytes]] = None

@dataclass
class HttpResponse:
    status_code: int
    headers: Dict[str, str]
    body: bytes
    latency_ms: float

class ConnectorError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, error_code: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code

SESSION_CACHE = {}
MAX_CACHE_SIZE = 100

def get_session_key(proxy_url: Optional[str], options: sdk_options_pb2.HttpOptions) -> str:
    identity = {
        "proxy": proxy_url,
        "connect": options.connect_timeout_ms or Defaults.CONNECT_TIMEOUT_MS,
        "response": options.response_timeout_ms or Defaults.RESPONSE_TIMEOUT_MS,
        "ca_length": len(options.ca_cert) if options.ca_cert else None
    }
    return json.dumps(identity, sort_keys=True)

def create_session(proxy_url: Optional[str], options: sdk_options_pb2.HttpOptions) -> requests.Session:
    try:
        session = requests.Session()
        if proxy_url:
            session.proxies = {"http": proxy_url, "https": proxy_url}
        
        if options.ca_cert:
            session.verify = options.ca_cert
        return session
    except Exception as e:
        raise ConnectorError(f"Invalid HTTP Configuration: {str(e)}", 500, "INVALID_CONFIGURATION")

def execute(request: HttpRequest, options: Optional[sdk_options_pb2.HttpOptions] = None) -> HttpResponse:
    """Standardized network execution engine for Unified Connector Service."""
    if options is None: options = sdk_options_pb2.HttpOptions()
    
    # Configuration & Proxy Resolution (using Protobuf field names)
    total_timeout = (options.total_timeout_ms or Defaults.TOTAL_TIMEOUT_MS) / 1000.0
    connect_timeout = (options.connect_timeout_ms or Defaults.CONNECT_TIMEOUT_MS) / 1000.0
    response_timeout = (options.response_timeout_ms or Defaults.RESPONSE_TIMEOUT_MS) / 1000.0
    
    proxy = options.proxy
    should_bypass = request.url in (proxy.bypass_urls if proxy else [])
    proxy_url = None if (not proxy or should_bypass) else (proxy.https_url or proxy.http_url)
    
    session_key = get_session_key(proxy_url, options)
    if session_key not in SESSION_CACHE:
        if len(SESSION_CACHE) >= MAX_CACHE_SIZE:
            del SESSION_CACHE[next(iter(SESSION_CACHE))]
        SESSION_CACHE[session_key] = create_session(proxy_url, options)
    
    session = SESSION_CACHE[session_key]
    
    start_time = time.time()
    try:
        response = session.request(
            method=request.method.upper(),
            url=request.url,
            headers=request.headers or {},
            data=request.body,
            timeout=(connect_timeout, response_timeout),
            allow_redirects=False
        )
        
        latency = (time.time() - start_time) * 1000
        if (time.time() - start_time) > total_timeout:
            raise requests.exceptions.Timeout("Total request timeout exceeded")

        # Normalize headers to lowercase for global parity
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        return HttpResponse(
            status_code=response.status_code,
            headers=response_headers,
            body=response.content,
            latency_ms=latency
        )

    except requests.exceptions.ConnectTimeout:
        raise ConnectorError(f"Connection Timeout: {request.url}", 504, "CONNECT_TIMEOUT")
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(f"Response Timeout: {request.url}", 504, "RESPONSE_TIMEOUT")
    except requests.exceptions.Timeout:
        raise ConnectorError(f"Total Request Timeout: {request.url}", 504, "TOTAL_TIMEOUT")
    except Exception as e:
        raise ConnectorError(f"Network Error: {str(e)}", 500, "NETWORK_FAILURE")
