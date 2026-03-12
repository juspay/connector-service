import time
import httpx
import ssl
from typing import Optional, Dict, Union
from dataclasses import dataclass
from .generated import sdk_config_pb2

# Centralized defaults from Protobuf Single Source of Truth
Defaults = sdk_config_pb2.HttpDefault

# Type alias for proto-generated HttpConfig and sub-configs
HttpConfig = sdk_config_pb2.HttpConfig
ProxyOptions = sdk_config_pb2.ProxyOptions
NetworkErrorCode = sdk_config_pb2.NetworkErrorCode

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

class NetworkError(Exception):
    """Network error for HTTP transport failures. Uses proto NetworkErrorCode for cross-SDK parity."""

    def __init__(
        self,
        message: str,
        code: int = sdk_config_pb2.NetworkErrorCode.NETWORK_ERROR_CODE_UNSPECIFIED,
        status_code: Optional[int] = None,
    ):
        super().__init__(message)
        self.code = code
        self.status_code = status_code

    @property
    def error_code(self) -> str:
        """String error code for parity with RequestError/ResponseError (e.g. 'CONNECT_TIMEOUT')."""
        names = {
            sdk_config_pb2.NetworkErrorCode.CONNECT_TIMEOUT: "CONNECT_TIMEOUT",
            sdk_config_pb2.NetworkErrorCode.RESPONSE_TIMEOUT: "RESPONSE_TIMEOUT",
            sdk_config_pb2.NetworkErrorCode.TOTAL_TIMEOUT: "TOTAL_TIMEOUT",
            sdk_config_pb2.NetworkErrorCode.NETWORK_FAILURE: "NETWORK_FAILURE",
            sdk_config_pb2.NetworkErrorCode.INVALID_CONFIGURATION: "INVALID_CONFIGURATION",
            sdk_config_pb2.NetworkErrorCode.CLIENT_INITIALIZATION: "CLIENT_INITIALIZATION",
            sdk_config_pb2.NetworkErrorCode.URL_PARSING_FAILED: "URL_PARSING_FAILED",
            sdk_config_pb2.NetworkErrorCode.RESPONSE_DECODING_FAILED: "RESPONSE_DECODING_FAILED",
            sdk_config_pb2.NetworkErrorCode.INVALID_PROXY_CONFIGURATION: "INVALID_PROXY_CONFIGURATION",
        }
        return names.get(self.code, "NETWORK_ERROR_CODE_UNSPECIFIED")

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

    # Resolve Timeouts (Defaults from HttpConfig or Protobuf Constants)
    total_timeout = (http_config.total_timeout_ms / 1000.0) if (http_config and http_config.HasField('total_timeout_ms')) else (Defaults.TOTAL_TIMEOUT_MS / 1000.0)
    connect_timeout = (http_config.connect_timeout_ms / 1000.0) if (http_config and http_config.HasField('connect_timeout_ms')) else (Defaults.CONNECT_TIMEOUT_MS / 1000.0)
    read_timeout = (http_config.response_timeout_ms / 1000.0) if (http_config and http_config.HasField('response_timeout_ms')) else (Defaults.RESPONSE_TIMEOUT_MS / 1000.0)

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

    try:
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
    except NetworkError:
        raise  # already classified, pass through
    except Exception as e:
        code = sdk_config_pb2.NetworkErrorCode.INVALID_PROXY_CONFIGURATION if "proxy" in str(e).lower() else sdk_config_pb2.NetworkErrorCode.CLIENT_INITIALIZATION
        raise NetworkError(f"Internal HTTP setup failed: {e}", code, 500)

async def execute(
    request: HttpRequest,
    client: httpx.AsyncClient,
    http_config: Optional[HttpConfig] = None
) -> HttpResponse:
    """
    Standardized stateless execution engine using httpx AsyncClient.
    """
    # Validate URL: httpx.URL() does not raise for missing scheme (e.g. "not-a-valid-url").
    # Check scheme explicitly so we fail fast before a network attempt.
    try:
        parsed_url = httpx.URL(request.url)
        if parsed_url.scheme not in ('http', 'https'):
            raise NetworkError(f"Invalid URL (missing or unsupported scheme): {request.url}", sdk_config_pb2.NetworkErrorCode.URL_PARSING_FAILED)
    except NetworkError:
        raise
    except Exception:
        raise NetworkError(f"Invalid URL: {request.url}", sdk_config_pb2.NetworkErrorCode.URL_PARSING_FAILED)
    start_time = time.time()

    # Per-request timeout override merged with the already-resolved client defaults.
    # This keeps timeout resolution centralized in create_client().
    timeout = httpx.USE_CLIENT_DEFAULT
    if http_config:
        total = (http_config.total_timeout_ms / 1000.0) if http_config.HasField('total_timeout_ms') else None
        connect = (http_config.connect_timeout_ms / 1000.0) if http_config.HasField('connect_timeout_ms') else None
        read = (http_config.response_timeout_ms / 1000.0) if http_config.HasField('response_timeout_ms') else None
        if total is not None or connect is not None or read is not None:
            base_timeout = client.timeout
            effective_total = total if total is not None else base_timeout.timeout
            effective_connect = connect if connect is not None else base_timeout.connect
            effective_read = read if read is not None else base_timeout.read
            timeout = httpx.Timeout(
                effective_total,
                connect=effective_connect,
                read=effective_read
            )

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

        try:
            body = response.content
        except Exception as e:
            raise NetworkError(f"Failed to read response body: {e}", sdk_config_pb2.NetworkErrorCode.RESPONSE_DECODING_FAILED, response.status_code)

        return HttpResponse(
            status_code=response.status_code,
            headers=response_headers,
            body=body,
            latency_ms=latency
        )

    except httpx.ConnectTimeout:
        raise NetworkError(f"Connection Timeout: {request.url}", sdk_config_pb2.NetworkErrorCode.CONNECT_TIMEOUT, 504)
    except (httpx.ReadTimeout, httpx.WriteTimeout):
        raise NetworkError(f"Response Timeout: {request.url}", sdk_config_pb2.NetworkErrorCode.RESPONSE_TIMEOUT, 504)
    except Exception as e:
        raise NetworkError(f"Network Error: {str(e)}", sdk_config_pb2.NetworkErrorCode.NETWORK_FAILURE, 500)
