Feature: HTTP Client Sanity Certification
  The HTTP client must consistently handle various request types,
  response codes, error conditions, and edge cases across all SDK languages.

  Background:
    Given the echo server is running on port 8081

  # ── Core HTTP Methods & Content Types ──────────────────────────

  Scenario: Standard JSON POST with Unicode/Emojis
    Given a "POST" request to "http://localhost:8081/sanity/v1"
    And header "Content-Type" is "application/json"
    And body is '{"merchant": "Juspay 💰", "location": "Café"}'
    When the request is sent as scenario "CASE_01_JSON_UNICODE"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: GET with complex query encoding
    Given a "GET" request to "http://localhost:8081/sanity/v1?ids[]=1&q=payment+gateway&encoded=café"
    And header "Accept" is "application/json"
    When the request is sent as scenario "CASE_02_URL_ENCODING"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Standard Form-URL POST
    Given a "POST" request to "http://localhost:8081/sanity/v1"
    And header "Content-Type" is "application/x-www-form-urlencoded"
    And body is "amount=1000&currency=USD&capture=true"
    When the request is sent as scenario "CASE_03_FORM_URL_ENCODED"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: PUT method check
    Given a "PUT" request to "http://localhost:8081/sanity/v1/update"
    And header "Content-Type" is "application/json"
    And body is '{"status": "updated"}'
    When the request is sent as scenario "CASE_04_PUT_METHOD"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: PATCH method check
    Given a "PATCH" request to "http://localhost:8081/sanity/v1/partial"
    And header "Content-Type" is "application/json"
    And body is '{"part": "A"}'
    When the request is sent as scenario "CASE_05_PATCH_METHOD"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: DELETE method check
    Given a "DELETE" request to "http://localhost:8081/sanity/v1/resource/123"
    And header "Accept" is "*/*"
    When the request is sent as scenario "CASE_06_DELETE_METHOD"
    Then the response status should be 204

  Scenario: POST with no body
    Given a "POST" request to "http://localhost:8081/sanity/v1/empty"
    And header "Content-Type" is "application/json"
    When the request is sent as scenario "CASE_07_POST_EMPTY_BODY"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: XML/SOAP body
    Given a "POST" request to "http://localhost:8081/sanity/v1/soap"
    And header "Content-Type" is "application/xml"
    And body is '<?xml version="1.0"?><payment><amount>100</amount></payment>'
    When the request is sent as scenario "CASE_08_XML_BODY"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Multipart form data
    Given a "POST" request to "http://localhost:8081/sanity/v1/upload"
    And header "Accept" is "*/*"
    And header "Content-Type" is "multipart/form-data; boundary=SanityBoundary"
    And body is "-----SanityBoundary\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n-----SanityBoundary--\r\n"
    When the request is sent as scenario "CASE_09_MULTIPART_FORMDATA"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Body with UTF-8 BOM
    Given a "POST" request to "http://localhost:8081/sanity/v1/bom"
    And header "Content-Type" is "application/json"
    And body is '\uFEFF{"key": "value_with_bom"}'
    When the request is sent as scenario "CASE_15_BOM_UTF8"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Binary request payload
    Given a "POST" request to "http://localhost:8081/sanity/v1/binary"
    And header "Content-Type" is "application/octet-stream"
    And body is "base64:AAECAwQFBgcICQ=="
    When the request is sent as scenario "CASE_18_RAW_BYTES"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: POST with URL query parameters
    Given a "POST" request to "http://localhost:8081/sanity/v1/hybrid?source=webhook&retry=1"
    And header "Content-Type" is "application/json"
    And body is '{"confirmed": true}'
    When the request is sent as scenario "CASE_20_POST_WITH_QUERY"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  Scenario: Form-URL with Unicode body
    Given a "POST" request to "http://localhost:8081/sanity/v1"
    And header "Content-Type" is "application/x-www-form-urlencoded"
    And body is "customer_name=René Smith&emoji=💰&status=verified"
    When the request is sent as scenario "CASE_21_FORM_UNICODE"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  # ── HTTP Status Codes ──────────────────────────────────────────

  Scenario: Server returns 500 Internal Server Error
    Given a "POST" request to "http://localhost:8081/sanity/v1/error500"
    And header "Content-Type" is "application/json"
    And body is '{"trigger": "failure"}'
    When the request is sent as scenario "CASE_11_SERVER_ERROR_500"
    Then the response status should be 500
    And the response body should be '{"error":"internal_server_error","code":500}'

  Scenario: Server returns 502 Bad Gateway
    Given a "GET" request to "http://localhost:8081/sanity/v1/error502"
    And header "Accept" is "application/json"
    When the request is sent as scenario "CASE_12_SERVER_ERROR_502"
    Then the response status should be 502
    And the response body should be '{"error":"bad_gateway","code":502}'

  Scenario: Server returns 503 Service Unavailable
    Given a "GET" request to "http://localhost:8081/sanity/v1/error503"
    And header "Accept" is "application/json"
    When the request is sent as scenario "CASE_13_SERVER_ERROR_503"
    Then the response status should be 503
    And the response body should be '{"error":"unavailable","code":503}'

  Scenario: Server returns 504 Gateway Timeout
    Given a "GET" request to "http://localhost:8081/sanity/v1/error504"
    And header "Accept" is "application/json"
    When the request is sent as scenario "CASE_14_SERVER_ERROR_504"
    Then the response status should be 504
    And the response body should be '{"error":"gateway_timeout","code":504}'

  Scenario: 204 No Content check
    Given a "DELETE" request to "http://localhost:8081/sanity/v1/resource/123"
    And header "Accept" is "*/*"
    When the request is sent as scenario "CASE_16_NO_CONTENT_204"
    Then the response status should be 204

  Scenario: 302 Redirect handling
    Given a "GET" request to "http://localhost:8081/sanity/v1/redirect"
    And header "Accept" is "application/json"
    When the request is sent as scenario "CASE_17_REDIRECT"
    Then the response status should be 302
    And the response header "location" should be "http://localhost:8081/sanity/v1/target"

  # ── Multi-value Headers (optional) ─────────────────────────────

  @optional
  Scenario: Multi-value Set-Cookie headers
    Given a "GET" request to "http://localhost:8081/sanity/v1/multi-header"
    And header "Accept" is "*/*"
    When the request is sent as scenario "CASE_19_MULTI_VALUE_HEADERS"
    Then the response status should be 200
    And the response should have multi-value header "set-cookie" with values "session=abc,theme=dark"

  # ── Timeout Handling ───────────────────────────────────────────

  @skip_rust @skip_python
  Scenario: Response timeout when server is slow
    Given a "POST" request to "http://localhost:8081/sanity/v1/timeout"
    And header "Content-Type" is "application/json"
    And body is '{"action": "sync"}'
    And a response timeout of 1000 ms
    When the request is sent as scenario "CASE_10_RESPONSE_TIMEOUT"
    Then the SDK should return error "RESPONSE_TIMEOUT"

  # ── Proxy Scenarios ────────────────────────────────────────────

  @skip_node
  Scenario: Request sent via forward proxy
    Given a "GET" request to "http://localhost:8081/sanity/v1/proxy"
    And header "Accept" is "application/json"
    And the proxy is "http://localhost:9082"
    When the request is sent as scenario "CASE_PROXY_FORWARD"
    Then the response status should be 200
    And the response body should be '{"status":"ok"}'
    And the server should have received the correct request

  # ── Error Scenarios ────────────────────────────────────────────

  Scenario: Invalid URL should fail before sending
    Given a "GET" request to "not-a-valid-url"
    And header "Accept" is "application/json"
    When the request is sent as scenario "CASE_ERR_INVALID_URL"
    Then the SDK should return error "URL_PARSING_FAILED"

  @skip_python @skip_kotlin
  Scenario: Invalid proxy configuration
    Given a "GET" request to "http://localhost:8081/sanity/v1"
    And header "Accept" is "application/json"
    And the proxy is "invalid://bad"
    When the request is sent as scenario "CASE_ERR_INVALID_PROXY"
    Then the SDK should return error "INVALID_PROXY_CONFIGURATION"
