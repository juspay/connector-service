import time, json, base64, threading
import logging
import threading
from collections import defaultdict
from concurrent import futures
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

background_executor = futures.ThreadPoolExecutor(max_workers=5)


file_lock = threading.Lock()


BASE_DIR = Path("/data/recordings/grpc")

def get_log_file():
    now = datetime.now()
    dir_path = BASE_DIR / f"{now:%Y/%m}"
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path / f"{now:%d}.ndjson"

def write_recording_to_file(record: dict):
    try:
        log_file = get_log_file()
        line = json.dumps(record, separators=(",", ":"))

        with file_lock:
            with open(log_file, "a") as f:
                f.write(line + "\n")

    except Exception:
        logger.exception("failed to write grpc recording")

def header_map_to_dict(header_map):
    out = defaultdict(list)
    for h in header_map.headers:
        val = h.value or h.raw_value.decode("utf-8", errors="ignore")
        out[h.key].append(val)
    return dict(out)

class RecorderAggregator:
    def __init__(self):
        self.calls = {}
        self.lock = threading.Lock()

    def _new_call(self, req_id):
        return {
            "request_id": req_id,
            "method": None,
            "authority": None,
            "request": {
                "headers": {},
                "body": bytearray(),
            },
            "response": {
                "headers": {},
                "body": bytearray(),
                "trailers": {}
            },
            "start_ms": int(time.time() * 1000)
        }

    def add_request_headers(self, header_map):
        headers = header_map_to_dict(header_map)
        req_id = headers.get("x-request-id", ["unknown"])[0]

        with self.lock:
            call = self.calls.setdefault(req_id, self._new_call(req_id))
            call["method"] = headers.get(":path", [""])[0]
            call["authority"] = headers.get(":authority", [""])[0]
            call["request"]["headers"] = headers

        return req_id

    def add_request_body(self, req_id, body):
        with self.lock:
            self.calls[req_id]["request"]["body"].extend(body)

    def add_response_headers(self, req_id, header_map):
        headers = header_map_to_dict(header_map)
        with self.lock:
            self.calls[req_id]["response"]["headers"] = headers
    def add_response_body(self, req_id, body):
        with self.lock:
            self.calls[req_id]["response"]["body"].extend(body)

    def finish(self, req_id, trailer_map):
        try:
            logger.info("finish")
            trailers = header_map_to_dict(trailer_map)
            with self.lock:
                call = self.calls.pop(req_id, None)

            if not call:
                return

            record = {
                "request_id": req_id,
                "method": call["method"],
                "authority": call["authority"],
                "request": {
                    "headers": call["request"]["headers"],
                    "body_base64": base64.b64encode(call["request"]["body"]).decode()
                },
                "response": {
                    "headers": call["response"]["headers"],
                    "body_base64": base64.b64encode(call["response"]["body"]).decode(),
                    "trailers": trailers
                },
                "start_ms": call["start_ms"],
                "end_ms": int(time.time() * 1000)
            }

            logger.info(
                "grpc recording finished",
                extra={
                    "request_id": req_id,
                    "method": record["method"],
                    "duration_ms": record["end_ms"] - record["start_ms"],
                },
            )
            background_executor.submit(write_recording_to_file, record)
        except Exception as e:
            logger.error(f"failed to finalize grpc recording {e}")