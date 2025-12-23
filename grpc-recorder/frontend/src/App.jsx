import { useEffect, useState } from "react";
import ReplayResults from "./ReplayResults";

export default function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchRecordings = async () => {
      try {
        setLoading(true);
        const response = await fetch("http://localhost:8000/recordings");
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const recordings = await response.json();
        setData(recordings);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch recordings:', err);
        setError(err.message);
        
        // For demo purposes, use the sample data if API fails
        const sampleData = [
          {
            "request_id": "test-logging-1766147267",
            "method": "/ucs.v2.PaymentService/Authorize",
            "authority": "localhost:8086",
            "id": "sample/recordings.ndjson:1",
            "folder_name": "sample",
            "filename": "recordings.ndjson",
            "line_number": 1,
            "request": {
              "headers": {
                ":method": ["POST"],
                ":scheme": ["http"],
                ":path": ["/ucs.v2.PaymentService/Authorize"],
                ":authority": ["localhost:8086"],
                "content-type": ["application/grpc"],
                "user-agent": ["grpcurl/1.9.3 grpc-go/1.61.0"],
                "te": ["trailers"],
                "grpc-accept-encoding": ["gzip"],
                "x-key1": ["body-key"],
                "x-api-key": ["asdasd"],
                "x-connector": ["stripe"],
                "x-merchant-id": ["test_merchant"],
                "x-tenant-id": ["public"],
                "x-request-id": ["test-logging-1766147267"],
                "x-auth": ["body-key"],
                "x-forwarded-proto": ["http"]
              },
              "body_base64": "AAAAAUIKEAoOZnJlc2hfYXV0aF8wMDEQiCcYkgEgoMIeOjsaOQoSChA1NTU1NTU1NTU1NTU0NDQ0EgQKAjA2GgYKBDIwMjYiBQoDNDU2KgwKCkZyZXNoIFVzZXI4AkoTChFmcmVzaEBleGFtcGxlLmNvbVIKRnJlc2ggVXNlcloKZnJlc2hfdXNlcmKbAQpBCgcKBUZyZXNoEgYKBFVzZXIaDAoKNDU2IE5ldyBTdDIPCg1TYW4gRnJhbmNpc2NvOgQKAkNBQgcKBTk0MTA1SAESVgoHCgVGcmVzaBIGCgRVc2VyGgwKCjQ1NiBOZXcgU3QyDwoNU2FuIEZyYW5jaXNjbzoECgJDQUIHCgU5NDEwNUgBUhMKEWZyZXNoQGV4YW1wbGUuY29taAKKARlodHRwOi8vbG9jYWxob3N0OjgwMDEuY29t"
            },
            "response": {
              "headers": {
                ":status": ["200"],
                "content-type": ["application/grpc"],
                "x-request-id": ["test-logging-1766147267"],
                "date": ["Fri, 19 Dec 2025 12:27:47 GMT"],
                "x-envoy-upstream-service-time": ["5"]
              },
              "body_base64": "AAAAAE4KAhoAEBUaD0NPTk5FQ1RPUl9FUlJPUiIkRmFpbGVkIHRvIG9idGFpbiBhdXRoZW50aWNhdGlvbiB0eXBlUJADagwSCmZyZXNoX3VzZXI=",
              "trailers": {
                "grpc-status": ["0"]
              }
            },
            "start_ms": 1766147267658,
            "end_ms": 1766147267666
          },
          {
            "request_id": "019b45b9-cd71-75a0-af5c-1f415f028a39",
            "method": "/ucs.v2.PaymentService/Authorize",
            "authority": "localhost:8086",
            "id": "sample/recordings.ndjson:2",
            "folder_name": "sample",
            "filename": "recordings.ndjson",
            "line_number": 2,
            "request": {
              "headers": {
                ":method": ["POST"],
                ":scheme": ["http"],
                ":authority": ["localhost:8086"],
                ":path": ["/ucs.v2.PaymentService/Authorize"],
                "x-connector": ["stripe"],
                "x-auth": ["header-key"],
                "x-api-key": ["sk_test_51M7fTaD5R7gDAGffb0hcum2V2HAScdPZ9HOI3mshaOQWbBJcRkIqUVCUQOiBsi6BjZrYhGtq3llkVwcEeCcnrH3M00JqAtc3hm"],
                "x-merchant-id": ["merchant_1765436933"],
                "x-lineage-ids": ["merchant_id=merchant_1765436933&profile_id=pro_KpctPHWMnG4yzPAtZg5q"],
                "x-request-id": ["019b45b9-cd71-75a0-af5c-1f415f028a39"],
                "x-shadow-mode": ["true"],
                "x-tenant-id": ["public"],
                "te": ["trailers"],
                "content-type": ["application/grpc"],
                "user-agent": ["tonic/0.13.1"],
                "x-forwarded-proto": ["http"]
              },
              "body_base64": "AAAAA2wKHAoacGF5X2l2MWN1d2F5YTNZV0MxSkRxaEFyXzEQjDMYkgEgjDM6Oho4ChIKEDQxMTExMTExMTExMTExMTESBAoCMDMaBgoEMjAzMCIFCgM3MzcqDQoLQ0xCUlcgZGZmZGdAAUoTChFndWVzdEBleGFtcGxlLmNvbVIISm9obiBEb2VaEmN1c19UYUVVVVhINGcydk9TNWL7AQp7CggKBmpvc2VwaBIFCgNEb2UaBgoEMTQ2NyIRCg9IYXJyaXNvbiBTdHJlZXQqEQoPSGFycmlzb24gU3RyZWV0Mg4KDFNhbiBGcmFuc2ljbzoMCgpDYWxpZm9ybmlhQgcKBTk0MTIySAFaDAoKODA1NjU5NDQyN2IDKzkxEnwKBwoFQ0xCUlcSBwoFZGZmZGcaBgoEMTQ2NyIRCg9IYXJyaXNvbiBTdHJlZXQqEQoPSGFycmlzb24gU3RyZWV0Mg4KDFNhbiBGcmFuc2ljbzoMCgpDYWxpZm9ybmlhQgcKBTk0MTIySAFaDAoKODA1NjU5NDQyN2IDKzkxaAJwAYIBIgoKbG9naW5fZGF0ZRIUMjAxOS0wOS0xMFQxMDoxMToxMlqCAQ4KBHVkZjESBnZhbHVlMYIBFAoMbmV3X2N1c3RvbWVyEgR0cnVligFkaHR0cDovL2xvY2FsaG9zdDo4MDgwL3BheW1lbnRzL3BheV9pdjFjdXdheWEzWVdDMUpEcWhBci9tZXJjaGFudF8xNzY1NDM2OTMzL3JlZGlyZWN0L3Jlc3BvbnNlL3N0cmlwZZIBS2h0dHA6Ly9sb2NhbGhvc3Q6ODA4MC93ZWJob29rcy9tZXJjaGFudF8xNzY1NDM2OTMzL21jYV9GNkdQSUMwQ0dhU0llMkpNV292Q5oBZGh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9wYXltZW50cy9wYXlfaXYxY3V3YXlhM1lXQzFKRHFoQXIvbWVyY2hhbnRfMTc2NTQzNjkzMy9yZWRpcmVjdC9jb21wbGV0ZS9zdHJpcGXAAQH4AQCCAhhjdXNfZjVabjVtdUxMNkgwVlVIZ014VmmKAgoKBGNpdHkSAk5ZigILCgR1bml0EgMyNDWaAhxJdHMgbXkgZmlyc3QgcGF5bWVudCByZXF1ZXN0ogIGam9zZXBoqgICSlM="
            },
            "response": {
              "headers": {
                ":status": ["200"],
                "content-type": ["application/grpc"],
                "x-request-id": ["019b45b9-cd71-75a0-af5c-1f415f028a39"],
                "date": ["Mon, 22 Dec 2025 11:02:45 GMT"],
                "x-envoy-upstream-service-time": ["278"]
              },
              "body_base64": "AAAAH9wKHQobcGlfM1NoNnN5RDVSN2dEQUdmZjFRS3lKakIxEAgyDzk3NjkxMDExMDA0OTExNDodChtwaV8zU2g2c3lENVI3Z0RBR2ZmMVFLeUpqQjFAAErhIQreIXsiaWQiOiJwaV8zU2g2c3lENVI3Z0RBR2ZmMVFLeUpqQjEiLCJvYmplY3QiOiJwYXltZW50X2ludGVudCIsImFtb3VudCI6NjU0MCwiYW1vdW50X2NhcHR1cmFibGUiOjAsImFtb3VudF9kZXRhaWxzIjp7InRpcCI6e319LCJhbW91bnRfcmVjZWl2ZWQiOjY1NDAsImFwcGxpY2F0aW9uIjpudWxsLCJhcHBsaWNhdGlvbl9mZWVfYW1vdW50IjpudWxsLCJhdXRvbWF0aWNfcGF5bWVudF9tZXRob2RzIjpudWxsLCJjYW5jZWxlZF9hdCI6bnVsbCwiY2FuY2VsbGF0aW9uX3JlYXNvbiI6bnVsbCwiY2FwdHVyZV9tZXRob2QiOiJhdXRvbWF0aWMiLCJjbGllbnRfc2VjcmV0IjoicGlfM1NoNnN5RDVSN2dEQUdmZjFRS3lKakIxX3NlY3JldF9lamtqUHRETHEwSmlBaHZYM1FweFVVVUtCIiwiY29uZmlybWF0aW9uX21ldGhvZCI6ImF1dG9tYXRpYyIsImNyZWF0ZWQiOjE3NjY0MDEzNjQsImN1cnJlbmN5IjoidXNkIiwiY3VzdG9tZXIiOiJjdXNfVGFFVVVYSDRnMnZPUzUiLCJjdXN0b21lcl9hY2NvdW50IjpudWxsLCJkZXNjcmlwdGlvbiI6Ikl0cyBteSBmaXJzdCBwYXltZW50IHJlcXVlc3QiLCJleGNsdWRlZF9wYXltZW50X21ldGhvZF90eXBlcyI6bnVsbCwiaW52b2ljZSI6bnVsbCwibGFzdF9wYXltZW50X2Vycm9yIjpudWxsLCJsYXRlc3RfY2hhcmdlIjp7ImlkIjoiY2hfM1NoNnN5RDVSN2dEQUdmZjFtWWM1VVVHIiwib2JqZWN0IjoiY2hhcmdlIiwiYW1vdW50Ijo2NTQwLCJhbW91bnRfY2FwdHVyZWQiOjY1NDAsImFtb3VudF9yZWZ1bmRlZCI6MCwiYW1vdW50X3VwZGF0ZXMiOltdLCJhcHBsaWNhdGlvbiI6bnVsbCwiYXBwbGljYXRpb25fZmVlIjpudWxsLCJhcHBsaWNhdGlvbl9mZWVfYW1vdW50IjpudWxsLCJiYWxhbmNlX3RyYW5zYWN0aW9uIjoidHhuXzNTaDZzeUQ1UjdnREFHZmYxb1pSd2JnVyIsImJpbGxpbmdfZGV0YWlscyI6eyJhZGRyZXNzIjp7ImNpdHkiOiJTYW4gRnJhbnNpY28iLCJjb3VudHJ5IjoiVVMiLCJsaW5lMSI6IjE0NjciLCJsaW5lMiI6IkhhcnJpc29uIFN0cmVldCIsInBvc3RhbF9jb2RlIjoiOTQxMjIiLCJzdGF0ZSI6IkNhbGlmb3JuaWEifSwiZW1haWwiOm51bGwsIm5hbWUiOiJDTEJSVyBkZmZkZyIsInBob25lIjoiODA1NjU5NDQyNyIsInRheF9pZCI6bnVsbH0sImNhbGN1bGF0ZWRfc3RhdGVtZW50X2Rlc2NyaXB0b3IiOiJCRVJOQVJEKiBKUyIsImNhcHR1cmVkIjp0cnVlLCJjcmVhdGVkIjoxNzY2NDAxMzY0LCJjdXJyZW5jeSI6InVzZCIsImN1c3RvbWVyIjoiY3VzX1RhRVVVWEg0ZzJ2T1M1IiwiZGVzY3JpcHRpb24iOiJJdHMgbXkgZmlyc3QgcGF5bWVudCByZXF1ZXN0IiwiZGVzdGluYXRpb24iOm51bGwsImRpc3B1dGUiOm51bGwsImRpc3B1dGVkIjpmYWxzZSwiZmFpbHVyZV9iYWxhbmNlX3RyYW5zYWN0aW9uIjpudWxsLCJmYWlsdXJlX2NvZGUiOm51bGwsImZhaWx1cmVfbWVzc2FnZSI6bnVsbCwiZnJhdWRfZGV0YWlscyI6e30sImludm9pY2UiOm51bGwsImxpdmVtb2RlIjpmYWxzZSwibWV0YWRhdGEiOnsibG9naW5fZGF0ZSI6IlwiMjAxOS0wOS0xMFQxMDoxMToxMlpcIiIsIm5ld19jdXN0b21lciI6IlwidHJ1ZVwiIiwib3JkZXJfaWQiOiJwYXlfaXYxY3V3YXlhM1lXQzFKRHFoQXJfMSIsInVkZjEiOiJcInZhbHVlMVwiIn0sIm9uX2JlaGFsZl9vZiI6bnVsbCwib3JkZXIiOm51bGwsIm91dGNvbWUiOnsiYWR2aWNlX2NvZGUiOm51bGwsIm5ldHdvcmtfYWR2aWNlX2NvZGUiOm51bGwsIm5ldHdvcmtfZGVjbGluZV9jb2RlIjpudWxsLCJuZXR3b3JrX3N0YXR1cyI6ImFwcHJvdmVkX2J5X25ldHdvcmsiLCJyZWFzb24iOm51bGwsInJpc2tfbGV2ZWwiOiJub3JtYWwiLCJyaXNrX3Njb3JlIjo2LCJzZWxsZXJfbWVzc2FnZSI6IlBheW1lbnQgY29tcGxldGUuIiwidHlwZSI6ImF1dGhvcml6ZWQifSwicGFpZCI6dHJ1ZSwicGF5bWVudF9pbnRlbnQiOiJwaV8zU2g2c3lENVI3Z0RBR2ZmMVFLeUpqQjEiLCJwYXltZW50X21ldGhvZCI6InBtXzFTaDZzeUQ1UjdnREFHZmZxOWZUdWNITyIsInBheW1lbnRfbWV0aG9kX2RldGFpbHMiOnsiY2FyZCI6eyJhbW91bnRfYXV0aG9yaXplZCI6NjU0MCwiYXV0aG9yaXphdGlvbl9jb2RlIjoiODkwNzI1IiwiYnJhbmQiOiJ2aXNhIiwiY2hlY2tzIjp7ImFkZHJlc3NfbGluZTFfY2hlY2siOiJwYXNzIiwiYWRkcmVzc19wb3N0YWxfY29kZV9jaGVjayI6InBhc3MiLCJjdmNfY2hlY2siOiJwYXNzIn0sImNvdW50cnkiOiJVUyIsImV4cF9tb250aCI6MywiZXhwX3llYXIiOjIwMzAsImV4dGVuZGVkX2F1dGhvcml6YXRpb24iOnsic3RhdHVzIjoiZGlzYWJsZWQifSwiZmluZ2VycHJpbnQiOiJhRWVkMXJmaGZhNUpOcG96IiwiZnVuZGluZyI6ImNyZWRpdCIsImluY3JlbWVudGFsX2F1dGhvcml6YXRpb24iOnsic3RhdHVzIjoidW5hdmFpbGFibGUifSwiaW5zdGFsbG1lbnRzIjpudWxsLCJsYXN0NCI6IjExMTEiLCJtYW5kYXRlIjpudWxsLCJtb3RvIjpudWxsLCJtdWx0aWNhcHR1cmUiOnsic3RhdHVzIjoidW5hdmFpbGFibGUifSwibmV0d29yayI6InZpc2EiLCJuZXR3b3JrX3Rva2VuIjp7InVzZWQiOmZhbHNlfSwibmV0d29ya190cmFuc2FjdGlvbl9pZCI6Ijk3NjkxMDExMDA0OTExNCIsIm92ZXJjYXB0dXJlIjp7Im1heGltdW1fYW1vdW50X2NhcHR1cmFibGUiOjY1NDAsInN0YXR1cyI6InVuYXZhaWxhYmxlIn0sInJlZ3VsYXRlZF9zdGF0dXMiOiJ1bnJlZ3VsYXRlZCIsInRocmVlX2Rfc2VjdXJlIjpudWxsLCJ3YWxsZXQiOm51bGx9LCJ0eXBlIjoiY2FyZCJ9LCJyYWRhcl9vcHRpb25zIjp7fSwicmVjZWlwdF9lbWFpbCI6bnVsbCwicmVjZWlwdF9udW1iZXIiOm51bGwsInJlY2VpcHRfdXJsIjoiaHR0cHM6Ly9wYXkuc3RyaXBlLmNvbS9yZWNlaXB0cy9wYXltZW50L0NBY2FGd29WVldOamRGOHhUVGRtVkdGRU5WSTNaMFJCUjJabUtOVEtwTW9HTWdiQ0RocWV5Skk2TEJhMkMzbEZaenVQSlI5OGNCcU1tdW9UbnhkalNhc0tsUmhqbkpVR2EyUFN4QWNrX2VSZGdfQXdDZjNOIiwicmVmdW5kZWQiOmZhbHNlLCJyZXZpZXciOm51bGwsInNoaXBwaW5nIjp7ImFkZHJlc3MiOnsiY2l0eSI6IlNhbiBGcmFuc2lzY28iLCJjb3VudHJ5IjoiVVMiLCJsaW5lMSI6IjE0NjciLCJsaW5lMiI6IkhhcnJpc29uIFN0cmVldCIsInBvc3RhbF9jb2RlIjoiOTQxMjIiLCJzdGF0ZSI6IkNhbGlmb3JuaWEifSwiY2FycmllciI6bnVsbCwibmFtZSI6Impvc2VwaCBEb2UiLCJwaG9uZSI6Iis5MTgwNTY1OTQ0MjciLCJ0cmFja2luZ19udW1iZXIiOm51bGx9LCJzb3VyY2UiOm51bGwsInNvdXJjZV90cmFuc2ZlciI6bnVsbCwic3RhdGVtZW50X2Rlc2NyaXB0b3IiOiJqb3NlcGgiLCJzdGF0ZW1lbnRfZGVzY3JpcHRvcl9zdWZmaXgiOiJKUyIsInN0YXR1cyI6InN1Y2NlZWRlZCIsInRyYW5zZmVyX2RhdGEiOm51bGwsInRyYW5zZmVyX2dyb3VwIjpudWxsfSwibGl2ZW1vZGUiOmZhbHNlLCJtZXRhZGF0YSI6eyJsb2dpbl9kYXRlIjoiXCIyMDE5LTA5LTEwVDEwOjExOjEyWlwiIiwibmV3X2N1c3RvbWVyIjoiXCJ0cnVlXCIiLCJvcmRlcl9pZCI6InBheV9pdjFjdXdheWEzWVdDMUpEcWhBcl8xIiwidWRmMSI6IlwidmFsdWUxXCIifSwibmV4dF9hY3Rpb24iOm51bGwsIm9uX2JlaGFsZl9vZiI6bnVsbCwicGF5bWVudF9tZXRob2QiOiJwbV8xU2g2c3lENVI3Z0RBR2ZmcTlmVHVjSE8iLCJwYXltZW50X21ldGhvZF9jb25maWd1cmF0aW9uX2RldGFpbHMiOm51bGwsInBheW1lbnRfbWV0aG9kX29wdGlvbnMiOnsiY2FyZCI6eyJpbnN0YWxsbWVudHMiOm51bGwsIm1hbmRhdGVfb3B0aW9ucyI6bnVsbCwibmV0d29yayI6bnVsbCwicmVxdWVzdF90aHJlZV9kX3NlY3VyZSI6ImF1dG9tYXRpYyJ9fSwicGF5bWVudF9tZXRob2RfdHlwZXMiOlsiY2FyZCJdLCJwcm9jZXNzaW5nIjpudWxsLCJyZWNlaXB0X2VtYWlsIjpudWxsLCJyZXZpZXciOm51bGwsInNldHVwX2Z1dHVyZV91c2FnZSI6Im9mZl9zZXNzaW9uIiwic2hpcHBpbmciOnsiYWRkcmVzcyI6eyJjaXR5IjoiU2FuIEZyYW5zaWNvIiwiY291bnRyeSI6IlVTIiwibGluZTEiOiIxNDY3IiwibGluZTIiOiJIYXJyaXNvbiBTdHJlZXQiLCJwb3N0YWxfY29kZSI6Ijk0MTIyIiwic3RhdGUiOiJDYWxpZm9ybmlhIn0sImNhcnJpZXIiOm51bGwsIm5hbWUiOiJqb3NlcGggRG9lIiwicGhvbmUiOiIrOTE4MDU2NTk0NDI3IiwidHJhY2tpbmdfbnVtYmVyIjpudWxsfSwic291cmNlIjpudWxsLCJzdGF0ZW1lbnRfZGVzY3JpcHRvciI6Impvc2VwaCIsInN0YXRlbWVudF9kZXNjcmlwdG9yX3N1ZmZpeCI6IkpTIiwic3RhdHVzIjoic3VjY2VlZGVkIiwidHJhbnNmZXJfZGF0YSI6bnVsbCwidHJhbnNmZXJfZ3JvdXAiOm51bGx9UMgBWuACChdjb250ZW50LXNlY3VyaXR5LXBvbGljeRLEAmJhc2UtdXJpICdub25lJzsgZGVmYXVsdC1zcmMgJ25vbmUnOyBmb3JtLWFjdGlvbiAnbm9uZSc7IGZyYW1lLWFuY2VzdG9ycyAnbm9uZSc7IGltZy1zcmMgJ3NlbGYnOyBzY3JpcHQtc3JjICdzZWxmJyAncmVwb3J0LXNhbXBsZSc7IHN0eWxlLXNyYyAnc2VsZic7IHdvcmtlci1zcmMgJ25vbmUnOyB1cGdyYWRlLWluc2VjdXJlLXJlcXVlc3RzOyByZXBvcnQtdXJpIGh0dHBzOi8vcS5zdHJpcGUuY29tL2NzcC12aW9sYXRpb24/cT1aZDVyaXNwSGNOOVM5bXRldlUxY2xobFh6M3kxMjNWU0plc3J3V1l3NnJBdmRETFh2MFljQzkyN2dvQUYwYi0ydWEwRjhiQ1ppckNxVllyNVosCgRldGFnEiRXLyIxMGRlLW5ZNHNTZG9tWU53ODVKVFRhY0VoUEp1Kzk4VSJaDwoGc2VydmVyEgVuZ2lueFooCiBhY2Nlc3MtY29udHJvbC1hbGxvdy1jcmVkZW50aWFscxIEdHJ1ZVovCgxjb250ZW50LXR5cGUSH2FwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9dXRmLThaJQoEZGF0ZRIdTW9uLCAyMiBEZWMgMjAyNSAxMTowMjo0NSBHTVRaFwoMeC1wb3dlcmVkLWJ5EgdFeHByZXNzWg4KBHZhcnkSBk9yaWdpblocChNzdHJpcGUtc2hvdWxkLXJldHJ5EgVmYWxzZVoOCgR4LXdjEgZBQkdISUpaGAoKY29ubmVjdGlvbhIKa2VlcC1hbGl2ZVo3Cg9pZGVtcG90ZW5jeS1rZXkSJDM4M2RhMTMyLTVlZDItNDhjMy04ZWIzLWUzZTczZGFjZjg2OFo2CiZ4LXN0cmlwZS1yb3V0aW5nLWNvbnRleHQtcHJpb3JpdHktdGllchIMYXBpLXRlc3Rtb2RlWjQKDHgtcmVxdWVzdC1pZBIkMDE5YjQ1YjktY2Q3MS03NWEwLWFmNWMtMWY0MTVmMDI4YTM5WiYKEG9yaWdpbmFsLXJlcXVlc3QSEnJlcV85ekxnMU4xcU00S0tXWFodChZhY2Nlc3MtY29udHJvbC1tYXgtYWdlEgMzMDBaIwoNY2FjaGUtY29udHJvbBISbm8tY2FjaGUsIG5vLXN0b3JlWhMKB3gtc3RhdGUSCHJlc3BvbnNlWkkKGXN0cmljdC10cmFuc3BvcnQtc2VjdXJpdHkSLG1heC1hZ2U9NjMwNzIwMDA7IGluY2x1ZGVTdWJEb21haW5zOyBwcmVsb2FkWiAKCnJlcXVlc3QtaWQSEnJlcV85ekxnMU4xcU00S0tXWFqeAQodYWNjZXNzLWNvbnRyb2wtZXhwb3NlLWhlYWRlcnMSfVJlcXVlc3QtSWQsIFN0cmlwZS1NYW5hZ2UtVmVyc2lvbiwgU3RyaXBlLVNob3VsZC1SZXRyeSwgWC1TdHJpcGUtRXh0ZXJuYWwtQXV0aC1SZXF1aXJlZCwgWC1TdHJpcGUtUHJpdmlsZWdlZC1TZXNzaW9uLVJlcXVpcmVkWikKIXgtc3RyaXBlLXByaW9yaXR5LXJvdXRpbmctZW5hYmxlZBIEdHJ1ZVogChthY2Nlc3MtY29udHJvbC1hbGxvdy1vcmlnaW4SASpaFgoOY29udGVudC1sZW5ndGgSBDQzMThaHAoOc3RyaXBlLXZlcnNpb24SCjIwMjItMTEtMTVaQwocYWNjZXNzLWNvbnRyb2wtYWxsb3ctbWV0aG9kcxIjR0VULCBIRUFELCBQVVQsIFBBVENILCBQT1NULCBERUxFVEVqFBISY3VzX1RhRVVVWEg0ZzJ2T1M1cssQCsgQeyJib2R5IjoiYW1vdW50PTY1NDAmY3VycmVuY3k9VVNEJnN0YXRlbWVudF9kZXNjcmlwdG9yX3N1ZmZpeD1KUyZzdGF0ZW1lbnRfZGVzY3JpcHRvcj1qb3NlcGgmbWV0YWRhdGElNUJsb2dpbl9kYXRlJTVEPSUyMjIwMTktMDktMTBUMTAlM0ExMSUzQTEyWiUyMiZtZXRhZGF0YSU1Qm9yZGVyX2lkJTVEPXBheV9pdjFjdXdheWEzWVdDMUpEcWhBcl8xJm1ldGFkYXRhJTVCbmV3X2N1c3RvbWVyJTVEPSUyMnRydWUlMjImbWV0YWRhdGElNUJ1ZGYxJTVEPSUyMnZhbHVlMSUyMiZyZXR1cm5fdXJsPWh0dHAlM0ElMkYlMkZsb2NhbGhvc3QlM0E4MDgwJTJGcGF5bWVudHMlMkZwYXlfaXYxY3V3YXlhM1lXQzFKRHFoQXIlMkZtZXJjaGFudF8xNzY1NDM2OTMzJTJGcmVkaXJlY3QlMkZyZXNwb25zZSUyRnN0cmlwZSZjb25maXJtPXRydWUmY3VzdG9tZXI9Y3VzX1RhRVVVWEg0ZzJ2T1M1JmRlc2NyaXB0aW9uPUl0cytteStmaXJzdCtwYXltZW50K3JlcXVlc3Qmc2hpcHBpbmclNUJhZGRyZXNzJTVEJTVCY2l0eSU1RD1TYW4rRnJhbnNpY28mc2hpcHBpbmclNUJhZGRyZXNzJTVEJTVCY291bnRyeSU1RD1VUyZzaGlwcGluZyU1QmFkZHJlc3MlNUQlNUJsaW5lMSU1RD0xNDY3JnNoaXBwaW5nJTVCYWRkcmVzcyU1RCU1QmxpbmUyJTVEPUhhcnJpc29uK1N0cmVldCZzaGlwcGluZyU1QmFkZHJlc3MlNUQlNUJwb3N0YWxfY29kZSU1RD05NDEyMiZzaGlwcGluZyU1QmFkZHJlc3MlNUQlNUJzdGF0ZSU1RD1DYWxpZm9ybmlhJnNoaXBwaW5nJTVCbmFtZSU1RD1qb3NlcGgrRG9lJnNoaXBwaW5nJTVCcGhvbmUlNUQ9JTJCOTE4MDU2NTk0NDI3JnBheW1lbnRfbWV0aG9kX2RhdGElNUJiaWxsaW5nX2RldGFpbHMlNUQlNUJhZGRyZXNzJTVEJTVCY291bnRyeSU1RD1VUyZwYXltZW50X21ldGhvZF9kYXRhJTVCYmlsbGluZ19kZXRhaWxzJTVEJTVCbmFtZSU1RD1DTEJSVytkZmZkZyZwYXltZW50X21ldGhvZF9kYXRhJTVCYmlsbGluZ19kZXRhaWxzJTVEJTVCYWRkcmVzcyU1RCU1QmNpdHklNUQ9U2FuK0ZyYW5zaWNvJnBheW1lbnRfbWV0aG9kX2RhdGElNUJiaWxsaW5nX2RldGFpbHMlNUQlNUJhZGRyZXNzJTVEJTVCbGluZTElNUQ9MTQ2NyZwYXltZW50X21ldGhvZF9kYXRhJTVCYmlsbGluZ19kZXRhaWxzJTVEJTVCYWRkcmVzcyU1RCU1QmxpbmUyJTVEPUhhcnJpc29uK1N0cmVldCZwYXltZW50X21ldGhvZF9kYXRhJTVCYmlsbGluZ19kZXRhaWxzJTVEJTVCYWRkcmVzcyU1RCU1QnBvc3RhbF9jb2RlJTVEPTk0MTIyJnBheW1lbnRfbWV0aG9kX2RhdGElNUJiaWxsaW5nX2RldGFpbHMlNUQlNUJhZGRyZXNzJTVEJTVCc3RhdGUlNUQ9Q2FsaWZvcm5pYSZwYXltZW50X21ldGhvZF9kYXRhJTVCYmlsbGluZ19kZXRhaWxzJTVEJTVCcGhvbmUlNUQ9ODA1NjU5NDQyNyZwYXltZW50X21ldGhvZF9kYXRhJTVCdHlwZSU1RD1jYXJkJnBheW1lbnRfbWV0aG9kX2RhdGElNUJjYXJkJTVEJTVCbnVtYmVyJTVEPTQxMTExMTExMTExMTExMTEmcGF5bWVudF9tZXRob2RfZGF0YSU1QmNhcmQlNUQlNUJleHBfbW9udGglNUQ9MDMmcGF5bWVudF9tZXRob2RfZGF0YSU1QmNhcmQlNUQlNUJleHBfeWVhciU1RD0yMDMwJnBheW1lbnRfbWV0aG9kX2RhdGElNUJjYXJkJTVEJTVCY3ZjJTVEPTczNyZwYXltZW50X21ldGhvZF9vcHRpb25zJTVCY2FyZCU1RCU1QnJlcXVlc3RfdGhyZWVfZF9zZWN1cmUlNUQ9YXV0b21hdGljJmNhcHR1cmVfbWV0aG9kPWF1dG9tYXRpYyZzZXR1cF9mdXR1cmVfdXNhZ2U9b2ZmX3Nlc3Npb24mcGF5bWVudF9tZXRob2RfdHlwZXMlNUIwJTVEPWNhcmQmZXhwYW5kJTVCMCU1RD1sYXRlc3RfY2hhcmdlIiwiaGVhZGVycyI6eyJBdXRob3JpemF0aW9uIjoiQmVhcmVyIHNrX3Rlc3RfNTFNN2ZUYUQ1UjdnREFHZmZiMGhjdW0yVjJIQVNjZFBaOUhPSTNtc2hhT1FXYkJKY1JrSXFVVkNVUU9pQnNpNkJqWnJZaEd0cTNsbGtWd2NFZUNjbnJIM00wMEpxQXRjM2htIiwiQ29udGVudC1UeXBlIjoiYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkIiwic3RyaXBlLXZlcnNpb24iOiIyMDIyLTExLTE1IiwidmlhIjoiSHlwZXJTd2l0Y2gifSwibWV0aG9kIjoiUE9TVCIsInVybCI6Imh0dHBzOi8vYXBpLnN0cmlwZS5jb20vdjEvcGF5bWVudF9pbnRlbnRzIn14jDOAAYwziAGMM5IBOgobcG1fMVNoNnN5RDVSN2dEQUdmZnE5ZlR1Y0hPEhtwbV8xU2g2c3lENVI3Z0RBR2ZmcTlmVHVjSE+aAWAKWApWElR7ImFkZHJlc3NfbGluZTFfY2hlY2siOiJwYXNzIiwiYWRkcmVzc19wb3N0YWxfY29kZV9jaGVjayI6InBhc3MiLCJjdmNfY2hlY2siOiJwYXNzIn0SAggAGAA=",
              "trailers": {
                "grpc-status": ["0"]
              }
            },
            "start_ms": 1766401365208,
            "end_ms": 1766401365498
          }
        ];
        setData(sampleData);
      } finally {
        setLoading(false);
      }
    };

    fetchRecordings();
  }, []);

  if (loading) {
    return (
      <div style={{ 
        padding: 24, 
        fontFamily: "sans-serif",
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        background: '#f9fafb'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ 
            width: 40, 
            height: 40, 
            border: '4px solid #e5e7eb',
            borderTop: '4px solid #3b82f6',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 16px auto'
          }}></div>
          <div style={{ color: '#6b7280', fontSize: 16 }}>
            Loading recordings...
          </div>
        </div>
        <style>{`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ 
        padding: 24, 
        fontFamily: "sans-serif",
        background: '#fef2f2',
        minHeight: '100vh'
      }}>
        <div style={{
          maxWidth: 600,
          margin: '0 auto',
          padding: 24,
          background: 'white',
          borderRadius: 8,
          border: '1px solid #fecaca',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
        }}>
          <h2 style={{ color: '#dc2626', margin: '0 0 16px 0' }}>
            Error Loading Recordings
          </h2>
          <p style={{ color: '#7f1d1d', marginBottom: 16 }}>
            {error}
          </p>
          <p style={{ color: '#6b7280', fontSize: 14 }}>
            Using sample data for demonstration. Please check if the backend server is running on localhost:8000
          </p>
        </div>
      </div>
    );
  }

  return <ReplayResults data={data} />;
}
