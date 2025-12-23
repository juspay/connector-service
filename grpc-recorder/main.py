"""
gRPC Recorder Service - Captures and stores gRPC requests/responses for replay
Using file-based storage for simplicity
"""
from concurrent import futures
import json
import logging
from datetime import datetime
from typing import Optional, List
import os
from pathlib import Path
import glob
from grpc_record_aggregator import RecorderAggregator
from frontend import app

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import threading
import uvicorn
def serve_http():
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("HTTP_PORT", 8087)))

import grpc
import threading
from concurrent import futures
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as ext_proc_grpc
from envoy.service.ext_proc.v3 import external_processor_pb2 as ext_proc_pb

def is_reflection(headers) -> bool:
    try:
        for h in headers.headers:
            if h.key == b":path" or h.key == ":path":
                raw = h.raw_value
                if isinstance(raw, (bytes, bytearray)):
                    raw = raw.decode("utf-8", errors="ignore")
                return raw.startswith("/grpc.reflection.v1.")
    except Exception as e:
        logger.info(f">>> header {e}")
        return False
    return False

aggregator = RecorderAggregator()
  
class RecorderProcessor(ext_proc_grpc.ExternalProcessorServicer):
    def Process(self, request_iterator, context):
        req_id = None
        logger.info(f"iterating requests")
        ignore_stream = False
        for request in request_iterator:
            resp = ext_proc_pb.ProcessingResponse()
            phase = request.WhichOneof("request")
            logger.info(f"HTTP Recorder server listening on {phase}")
            try:    
                if phase == "request_headers":
                    if is_reflection(request.request_headers.headers):
                        ignore_stream = True
                    else:
                        req_id = aggregator.add_request_headers(
                            request.request_headers.headers
                        )
                    resp.request_headers.SetInParent()

                elif phase == "request_body":
                    if request.request_body.body and not ignore_stream:
                        aggregator.add_request_body(
                            req_id,
                            request.request_body.body
                        )
                    resp.request_body.SetInParent()

                elif phase == "response_headers":
                    if request.response_headers.headers and not ignore_stream:
                        aggregator.add_response_headers(
                            req_id,
                            request.response_headers.headers
                        )
                    resp.response_headers.SetInParent()

                elif phase == "response_body":
                    if request.response_body.body and not ignore_stream:
                        logger.info(f"HTTP Recorder server listening on port 50051 ")
                        aggregator.add_response_body(
                            req_id,
                            request.response_body.body
                        )
                    resp.response_body.SetInParent()

                elif phase == "response_trailers":
                    if request.response_trailers.trailers and not ignore_stream:
                        aggregator.finish(
                            req_id,
                            request.response_trailers.trailers
                        )
                    resp.response_trailers.SetInParent()

                yield resp  # ALWAYS

            except Exception:
                # Never break the stream
                yield resp

def serve():
    # Increase workers to handle the high-volume stream connections
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=20))
    ext_proc_grpc.add_ExternalProcessorServicer_to_server(RecorderProcessor(), server)
    server.add_insecure_port('[::]:50051')
    logger.info(f"HTTP Recorder server listening on port 50051 --")
    server.start()
    server.wait_for_termination()


def load_all_protos():
    import services_pb2
    import payment_pb2
    import payment_methods_pb2 
if __name__ == '__main__':
    load_all_protos()
    http_thread = threading.Thread(target=serve_http, daemon=True)
    http_thread.start()
    serve()
