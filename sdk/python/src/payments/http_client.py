import time
import json
import requests
from typing import Optional, Dict, List, Union, Any
from dataclasses import dataclass

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
    body: str
    latency_ms: float

class ConnectorError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, error_code: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code

SESSION_CACHE = {}
MAX_CACHE_SIZE = 100

DEFAULT_CONFIG = {
    "total_timeout_ms": 45000,
    "connect_timeout_ms": 10000,
    "response_timeout_ms": 30000,
    "keep_alive_timeout": 60000,
}

def get_session_key(proxy_url: Optional[str], options: Dict[str, Any]) -> str:
    identity = {
        "proxy": proxy_url,
        "connect_timeout": options.get("connect_timeout_ms", DEFAULT_CONFIG["connect_timeout_ms"]),
        "response_timeout": options.get("response_timeout_ms", DEFAULT_CONFIG["response_timeout_ms"]),
        "ca_length": len(options.get("ca_cert")) if options.get("ca_cert") else None
    }
    return json.dumps(identity, sort_keys=True)

def create_session(proxy_url: Optional[str], options: Dict[str, Any]) -> requests.Session:
    session = requests.Session()
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
    
    if options.get("ca_cert"):
        # Note: requests supports file path for CA cert
        session.verify = options["ca_cert"]
    return session

def execute(request: HttpRequest, options: Optional[Dict[str, Any]] = None) -> HttpResponse:
    if options is None: options = {}
    
    # Configuration & Proxy Resolution
    total_timeout = (options.get("total_timeout_ms") or DEFAULT_CONFIG["total_timeout_ms"]) / 1000.0
    connect_timeout = (options.get("connect_timeout_ms") or DEFAULT_CONFIG["connect_timeout_ms"]) / 1000.0
    response_timeout = (options.get("response_timeout_ms") or DEFAULT_CONFIG["response_timeout_ms"]) / 1000.0
    
    proxy = options.get("proxy", {})
    should_bypass = request.url in proxy.get("bypass_urls", [])
    proxy_url = None if (not proxy or should_bypass) else (proxy.get("https_url") or proxy.get("http_url"))
    
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
            body=response.text,
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
