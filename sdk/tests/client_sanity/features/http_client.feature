Feature: HTTP Client Sanity
  Every SDK HTTP client must handle standard request patterns, status codes,
  content types, and error conditions consistently. The echo server reflects
  requests so parity can be verified across all languages.

  Background:
    Given the echo server is running on port 8081

  # ── Requests & Content Types ──────────────────────────────────

  Scenario: JSON POST preserves Unicode and emoji characters
    Given a "POST" request to "http://localhost:8081/sanity/v1"
    And header "Content-Type" is "application/json"
    And body is '{"merchant": "Juspay 💰", "location": "Café"}'
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: GET encodes complex query parameters correctly
    Given a "GET" request to "http://localhost:8081/sanity/v1?ids[]=1&q=payment+gateway&encoded=café"
    And header "Accept" is "application/json"
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Form-urlencoded POST sends key-value pairs
    Given a "POST" request to "http://localhost:8081/sanity/v1"
    And header "Content-Type" is "application/x-www-form-urlencoded"
    And body is "amount=1000&currency=USD&capture=true"
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: PUT request delivers a JSON update
    Given a "PUT" request to "http://localhost:8081/sanity/v1/update"
    And header "Content-Type" is "application/json"
    And body is '{"status": "updated"}'
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: PATCH request sends a partial JSON payload
    Given a "PATCH" request to "http://localhost:8081/sanity/v1/partial"
    And header "Content-Type" is "application/json"
    And body is '{"part": "A"}'
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: DELETE request returns no body
    Given a "DELETE" request to "http://localhost:8081/sanity/v1/resource/123"
    And header "Accept" is "*/*"
    When the request is sent
    Then the response status should be 204

  Scenario: POST with an empty body succeeds
    Given a "POST" request to "http://localhost:8081/sanity/v1/empty"
    And header "Content-Type" is "application/json"
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: XML body is transmitted verbatim
    Given a "POST" request to "http://localhost:8081/sanity/v1/soap"
    And header "Content-Type" is "application/xml"
    And body is '<?xml version="1.0"?><payment><amount>100</amount></payment>'
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Multipart form data is framed correctly
    Given a "POST" request to "http://localhost:8081/sanity/v1/upload"
    And header "Accept" is "*/*"
    And header "Content-Type" is "multipart/form-data; boundary=SanityBoundary"
    And body is "-----SanityBoundary\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n-----SanityBoundary--\r\n"
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: UTF-8 BOM prefix is preserved in body
    Given a "POST" request to "http://localhost:8081/sanity/v1/bom"
    And header "Content-Type" is "application/json"
    And body is '\uFEFF{"key": "value_with_bom"}'
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Binary payload is sent byte-for-byte
    Given a "POST" request to "http://localhost:8081/sanity/v1/binary"
    And header "Content-Type" is "application/octet-stream"
    And body is "base64:AAECAwQFBgcICQ=="
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: POST combines URL query parameters with a JSON body
    Given a "POST" request to "http://localhost:8081/sanity/v1/hybrid?source=webhook&retry=1"
    And header "Content-Type" is "application/json"
    And body is '{"confirmed": true}'
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Form-urlencoded POST preserves Unicode values
    Given a "POST" request to "http://localhost:8081/sanity/v1"
    And header "Content-Type" is "application/x-www-form-urlencoded"
    And body is "customer_name=René Smith&emoji=💰&status=verified"
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  # ── HTTP Status Codes ─────────────────────────────────────────

  Scenario: Server returns 500 Internal Server Error
    Given a "POST" request to "http://localhost:8081/sanity/v1/error500"
    And header "Content-Type" is "application/json"
    And body is '{"trigger": "failure"}'
    When the request is sent
    Then the response status should be 500
    And the response body should be '{"error":"internal_server_error","code":500}'

  Scenario: Server returns 502 Bad Gateway
    Given a "GET" request to "http://localhost:8081/sanity/v1/error502"
    And header "Accept" is "application/json"
    When the request is sent
    Then the response status should be 502
    And the response body should be '{"error":"bad_gateway","code":502}'

  Scenario: Server returns 503 Service Unavailable
    Given a "GET" request to "http://localhost:8081/sanity/v1/error503"
    And header "Accept" is "application/json"
    When the request is sent
    Then the response status should be 503
    And the response body should be '{"error":"unavailable","code":503}'

  Scenario: Server returns 504 Gateway Timeout
    Given a "GET" request to "http://localhost:8081/sanity/v1/error504"
    And header "Accept" is "application/json"
    When the request is sent
    Then the response status should be 504
    And the response body should be '{"error":"gateway_timeout","code":504}'

  Scenario: DELETE returns 204 No Content
    Given a "DELETE" request to "http://localhost:8081/sanity/v1/resource/123"
    And header "Accept" is "*/*"
    When the request is sent
    Then the response status should be 204

  Scenario: GET receives a 302 redirect with a location header
    Given a "GET" request to "http://localhost:8081/sanity/v1/redirect"
    And header "Accept" is "application/json"
    When the request is sent
    Then the response status should be 302
    And the response header "location" should be "http://localhost:8081/sanity/v1/target"

  # ── Multi-value Headers (optional) ────────────────────────────

  @optional
  Scenario: Response contains multiple Set-Cookie values
    Given a "GET" request to "http://localhost:8081/sanity/v1/multi-header"
    And header "Accept" is "*/*"
    When the request is sent
    Then the response status should be 200
    And the response should have multi-value header "set-cookie" with values "session=abc,theme=dark"

  # ── Timeout Handling ──────────────────────────────────────────

  @skip_rust @skip_python
  Scenario: SDK times out when the server responds too slowly
    Given a "POST" request to "http://localhost:8081/sanity/v1/timeout"
    And header "Content-Type" is "application/json"
    And body is '{"action": "sync"}'
    And a response timeout of 1000 ms
    When the request is sent
    Then the SDK should return error "RESPONSE_TIMEOUT"

  # ── Proxy Scenarios ───────────────────────────────────────────

  @skip_node
  Scenario: Request is routed through a forward proxy
    Given a "GET" request to "http://localhost:8081/sanity/v1/proxy"
    And header "Accept" is "application/json"
    And the proxy is "http://localhost:9082"
    When the request is sent
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  # ── Error Handling ────────────────────────────────────────────

  Scenario: Invalid URL is rejected before any network call
    Given a "GET" request to "not-a-valid-url"
    And header "Accept" is "application/json"
    When the request is sent
    Then the SDK should return error "URL_PARSING_FAILED"

  @skip_python @skip_kotlin
  Scenario: Invalid proxy URL is rejected at client creation
    Given a "GET" request to "http://localhost:8081/sanity/v1"
    And header "Accept" is "application/json"
    And the proxy is "invalid://bad"
    When the request is sent
    Then the SDK should return error "INVALID_PROXY_CONFIGURATION"
