import time
import httpx
import ssl
import asyncio
from typing import Optional, Dict, Union, Any
from dataclasses import dataclass
from urllib.parse import urlparse
from .generated import sdk_config_pb2

# Centralized defaults from Protobuf Single Source of Truth
Defaults = sdk_config_pb2.HttpDefault

# Type alias for proto-generated HttpConfig and sub-configs
HttpConfig = sdk_config_pb2.HttpConfig
HttpTimeoutConfig = sdk_config_pb2.HttpTimeoutConfig
ProxyOptions = sdk_config_pb2.ProxyOptions

@dataclass
class HttpRequest:
    url: str
    method: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[bytes] = None # Strictly bytes from UCS transformation

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

def resolve_proxies(proxy_options: Optional[ProxyOptions]) -> Optional[Dict[str, Optional[str]]]:
    """
    Builds the native httpx proxy dictionary with bypass support.
    """
    if not proxy_options:
        return None
        
    proxy_url = proxy_options.https_url or proxy_options.http_url
    if not proxy_url:
        return None

    proxies = {"all://": proxy_url}
    for bypass in list(proxy_options.bypass_urls):
        clean_domain = bypass.replace("http://", "").replace("https://", "").split("/")[0]
        if clean_domain:
            proxies[f"all://{clean_domain}"] = None
        
    return proxies

def create_client(http_config: Optional[HttpConfig] = None) -> httpx.AsyncClient:
    """
    Creates a high-performance asynchronous connection pool.
    """
    verify: Union[bool, ssl.SSLContext] = True
    mounts = None
    
    # 1. Resolve Timeouts (Client Level Defaults)
    t = http_config.timeouts if (http_config and http_config.HasField('timeouts')) else None
    
    total_timeout = (t.total_timeout_ms / 1000.0) if (t and t.HasField('total_timeout_ms')) else (Defaults.TOTAL_TIMEOUT_MS / 1000.0)
    connect_timeout = (t.connect_timeout_ms / 1000.0) if (t and t.HasField('connect_timeout_ms')) else (Defaults.CONNECT_TIMEOUT_MS / 1000.0)
    read_timeout = (t.response_timeout_ms / 1000.0) if (t and t.HasField('response_timeout_ms')) else (Defaults.RESPONSE_TIMEOUT_MS / 1000.0)

    if http_config:
        # 2. Resolve Certificate
        if http_config.HasField('ca_cert'):
            ca = http_config.ca_cert
            context = ssl.create_default_context()
            if ca.HasField('pem'):
                context.load_verify_locations(cadata=ca.pem)
            elif ca.HasField('der'):
                context.load_verify_locations(cadata=ca.der)
            verify = context

        # 3. Resolve Proxy
        proxies = resolve_proxies(http_config.proxy if http_config.HasField('proxy') else None)
        if proxies:
            mounts = {k: httpx.AsyncHTTPTransport(proxy=v) if v else None for k, v in proxies.items()}

    return httpx.AsyncClient(
        verify=verify,
        mounts=mounts,
        http2=True,
        timeout=httpx.Timeout(
            total_timeout,
            connect=connect_timeout,
            read=read_timeout
        )
    )

async def execute(
    request: HttpRequest, 
    client: httpx.AsyncClient,
    timeout_config: Optional[HttpTimeoutConfig] = None
) -> HttpResponse:
    """
    Standardized stateless execution engine using httpx AsyncClient.
    """
    start_time = time.time()
    
    # Per-request timeout override
    timeout = httpx.USE_CLIENT_DEFAULT
    if timeout_config:
        total = (timeout_config.total_timeout_ms / 1000.0) if timeout_config.HasField('total_timeout_ms') else None
        connect = (timeout_config.connect_timeout_ms / 1000.0) if timeout_config.HasField('connect_timeout_ms') else None
        read = (timeout_config.response_timeout_ms / 1000.0) if timeout_config.HasField('response_timeout_ms') else None
        timeout = httpx.Timeout(total, connect=connect, read=read)

    try:
        response = await client.request(
            method=request.method.upper(),
            url=request.url,
            headers=request.headers or {},
            content=request.body if request.body else None,
            timeout=timeout,
            follow_redirects=False
        )
        
        latency = (time.time() - start_time) * 1000
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        return HttpResponse(
            status_code=response.status_code,
            headers=response_headers,
            body=response.content,
            latency_ms=latency
        )

    except httpx.ConnectTimeout:
        raise ConnectorError(f"Connection Timeout: {request.url}", 504, "CONNECT_TIMEOUT")
    except (httpx.ReadTimeout, httpx.WriteTimeout):
        raise ConnectorError(f"Response Timeout: {request.url}", 504, "RESPONSE_TIMEOUT")
    except httpx.TimeoutException:
        raise ConnectorError(f"Total Request Timeout: {request.url}", 504, "TOTAL_TIMEOUT")
    except Exception as e:
        raise ConnectorError(f"Network Error: {str(e)}", 500, "NETWORK_FAILURE")
