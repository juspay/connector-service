import time
import requests
from typing import Optional, Dict, Union, Any
from dataclasses import dataclass
from urllib.parse import urlparse
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

def resolve_proxy_config(url: str, proxy_options: Optional[Any] = None) -> Optional[Dict[str, str]]:
    """
    Decides the proxy configuration for a specific URL.
    
    Returns:
        - dict: Explicit proxy map (e.g. {'https': '...'}) or {} for explicit bypass.
        - None: No proxy configured; use system/session defaults.
    """
    if not proxy_options:
        return None

    # Hostname matching for bypass (Fintech Standard)
    # Checks if the target hostname ends with any string in bypass_urls.
    target_host = urlparse(url).hostname or ""
    for bypass in getattr(proxy_options, 'bypass_urls', []):
        if target_host.endswith(bypass):
            return {} # Explicit bypass (direct connection)

    # Protocol-specific selection
    proxies = {}
    if url.startswith("https") and getattr(proxy_options, 'https_url', None):
        proxies["https"] = proxy_options.https_url
    elif getattr(proxy_options, 'http_url', None):
        proxies["http"] = proxy_options.http_url
        
    return proxies if proxies else None

def create_session(http_options: Optional[Any] = None) -> requests.Session:
    """
    Creates a high-performance connection pool (Session).
    The ConnectorClient instance will own this.
    """
    session = requests.Session()
    
    if http_options:
        # Set session-level default proxies if provided
        proxies = {}
        if http_options.proxy:
            if getattr(http_options.proxy, 'http_url', None):
                proxies["http"] = http_options.proxy.http_url
            if getattr(http_options.proxy, 'https_url', None):
                proxies["https"] = http_options.proxy.https_url
        if proxies:
            session.proxies = proxies

        # Certificate Pinning / CA Bundle
        if getattr(http_options, 'ca_cert', None):
            session.verify = http_options.ca_cert

    return session

def execute(
    request: HttpRequest, 
    session: requests.Session,
    connect_timeout_ms: float,
    response_timeout_ms: float,
    total_timeout_ms: float,
    proxy_config: Optional[Dict[str, str]] = None
) -> HttpResponse:
    """
    Standardized stateless execution engine. 
    Accepts primitive types only to ensure decoupling from Business Protos.
    """
    
    start_time = time.time()
    try:
        response = session.request(
            method=request.method.upper(),
            url=request.url,
            headers=request.headers or {},
            data=request.body,
            # (Connect Timeout, Read Timeout)
            timeout=(connect_timeout_ms / 1000.0, response_timeout_ms / 1000.0),
            proxies=proxy_config, # Overrides session defaults if provided
            allow_redirects=False
        )
        
        latency = (time.time() - start_time) * 1000
        
        # Post-call SLA enforcement (Hard Gate)
        if (time.time() - start_time) * 1000 > total_timeout_ms:
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
