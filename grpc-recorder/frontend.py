from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
import os, json, base64
import grpc
import logging
import gzip
import io

app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
STATIC_PATH = BASE_DIR / "static"
PROTO_PATH = os.getenv("PROTO_PATH", os.path.join(os.path.dirname(__file__), 'proto'))
STORAGE_PATH = os.getenv("STORAGE_PATH", "/data/recordings/grpc/")
GRPC_TARGET = os.getenv("GRPC_TARGET", "localhost:8085")



import struct

METHOD_TO_RESPONSE = {
    "/ucs.v2.PaymentService/Authorize":
        "ucs.v2.PaymentServiceAuthorizeResponse"
}

import sys
import importlib
from google.protobuf import symbol_database

_sym_db = symbol_database.Default()

from google.protobuf import descriptor_pool, descriptor_pb2

def load_descriptor_pool_from_generated(search_path: str):
    """
    search_path: directory containing *_pb2.py files (e.g. "/app")
    """

    # 🔥 IMPORTANT: start from default pool (has google/protobuf/*.proto)
    pool = descriptor_pool.Default()

    if search_path not in sys.path:
        sys.path.insert(0, search_path)
    try:
        for filename in os.listdir(search_path):
            if not filename.endswith("_pb2.py"):
                continue
            module_name = filename[:-3]
            module = importlib.import_module("proto."+module_name, package="proto")
            # Register file descriptor into the pool
            pool.AddSerializedFile(
                module.DESCRIPTOR.serialized_pb
            )
    except Exception as e:
        logger.error(f"failed to load: {e}")

    return pool

pool = load_descriptor_pool_from_generated(PROTO_PATH)

def resolve_response_type(pool, full_method: str):
    _, service_fqn, method_name = full_method.split("/")

    service_desc = pool.FindServiceByName(service_fqn)

    for method in service_desc.methods:
        if method.name == method_name:
            return method.output_type.full_name

    raise RuntimeError(f"Method not found: {full_method}")

from google.protobuf import message_factory
from google.protobuf.json_format import MessageToDict

def decode_dynamic_response(pool, response_type_fqn, response_bytes):
    descriptor = pool.FindMessageTypeByName(response_type_fqn)

    msg_cls = message_factory.GetMessageClass(descriptor)

    msg = msg_cls()
    msg.ParseFromString(response_bytes)

    # ✅ Version-safe arguments only
    return MessageToDict(
        msg,
        preserving_proto_field_name=True,
        use_integers_for_enums=False,
    )

from deepdiff import DeepDiff
import json

def visualize_diff(expected, actual):
    diff = DeepDiff(
        expected,
        actual,
        ignore_order=True,
        verbose_level=2,
    )

    if not diff:
        return {
            "status": "identical",
            "diff": None,
        }

    return {
        "status": "changed",
        "diff": json.loads(diff.to_json()),
    }

DISALLOWED_PREFIXES = (
    ":",
    "grpc-",
    "content-type",
    "user-agent",
    "te",
    "x-forwarded-",
)

import base64


def safe_compare(
    pool,
    full_method: str,
    expected_bytes: bytes,
    actual_bytes: bytes,
):

    # 2️⃣ Binary mismatch detected
    result = {
        "level": "binary",
        "binary": {
            "expected_b64": base64.b64encode(expected_bytes).decode(),
            "actual_b64": base64.b64encode(actual_bytes).decode(),
        },
    }

    # 3️⃣ Try semantic decode
    try:
        response_type = resolve_response_type(pool, full_method)

        expected = decode_dynamic_response(
            pool, response_type, expected_bytes
        )
        actual = decode_dynamic_response(
            pool, response_type, actual_bytes
        )

        semantic = visualize_diff(expected, actual)

        result["level"] = "semantic"
        result["semantic"] = semantic
        result["actual"] = actual
        result["expected"] = expected

    except Exception as e:
        # Semantic decoding failed — binary result still valid
        logger.error(f"error: {e}")
        result["semantic_error"] = str(e)

    return result

def deframe_grpc_message(data: bytes) -> bytes:
    """
    Removes gRPC message framing if present.
    Handles unary gRPC messages.
    """
    if len(data) < 5:
        return data

    compressed_flag = data[0]
    msg_len = int.from_bytes(data[1:5], byteorder="big")

    # Sanity check
    if msg_len + 5 != len(data):
        return data  # Not framed, return as-is

    # TODO: handle compression if flag == 1
    return data[5:]

def replay_request(record, target = GRPC_TARGET):
    channel = grpc.insecure_channel(target)

    method = record["method"]

    # ---- filter metadata ----
    metadata = []
    for k, v in record["request"]["headers"].items():
        lk = k.lower()
        if lk.startswith(DISALLOWED_PREFIXES):
            continue
        metadata.append((lk, v[0]))

    metadata.append(("is-replay-request", "true"))

    # ---- decode body ----
    raw = base64.b64decode(record["request"]["body_base64"])
    expected_res = deframe_grpc_message(base64.b64decode(record["response"]["body_base64"]))

    # strip gRPC framing
    compressed = raw[0]
    msg_len = int.from_bytes(raw[1:5], "big")
    proto_bytes = raw[5:5 + msg_len]

    if compressed != 0:
        raise RuntimeError("Compressed gRPC payload not supported yet")

    unary = channel.unary_unary(
        method,
        request_serializer=lambda x: x,
        response_deserializer=lambda x: x,
    )
    replay_bytes = unary(proto_bytes, metadata=metadata)
    
    res = safe_compare(pool, method, expected_res, replay_bytes)
    # Compare with recorded response
    # diff = compare_recorded_vs_replay(record, replay_bytes)
    return res

app.mount("/static", StaticFiles(directory=STATIC_PATH), name="static")

@app.get("/")
def ui():
    return FileResponse(STATIC_PATH / "index.html")

@app.get("/recordings")
def list_recordings():
    results = []
    for root, _, files in os.walk(STORAGE_PATH):
        logger.info(f"{root}")
        for file in sorted(files):
            if not file.endswith(".ndjson"):
                continue

            file_path = os.path.join(root, file)
            with open(file_path) as f:
                for line_num, line in enumerate(f, 1):
                    record = json.loads(line)
                    # Add ID based on folder structure, filename, and line number
                    record_id = f"{root.split(STORAGE_PATH )[1]}/{file}:{line_num}"
                    record["id"] = record_id
                    record["line_number"] = line_num
                    results.append(record)
    return results

def build_summary(results):
    summary = {
        "total": len(results),
        "identical": 0,
        "changed": 0,
        "failed": 0,
    }

    for r in results:
        if "semantic_error" in r and r["semantic_error"] is not None:
            summary["semantic_error"] += 1
        elif "status" in r and r["status"] == "identical":
            summary["identical"] += 1
        elif "status" in r and r["status"] == "changed":
            summary["changed"] += 1
        else:
            summary["failed"] += 1

    return {
        "summary": summary,
        "results": results,
    }

@app.get("/replay")
def trigger_replay(file: str, background_tasks: BackgroundTasks):
    file_path = os.path.join(STORAGE_PATH, file)
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    results = []
    with open(file_path) as f:
        for line in f:
            record = json.loads(line)
            results.append(replay_request(record))

    return build_summary(results)

@app.post("/replay")
def replay_single_recording(recording_id: str):
    """
    Replay a single recording by ID (format: folder_name/filename:line_number)
    """
    try:
        # Parse the recording ID
        if ":" not in recording_id:
            return {"error": "Invalid recording ID format. Expected: folder_name/filename:line_number"}
        
        file_part, line_num_str = recording_id.split(":")
        if "/" not in file_part:
            return {"error": "Invalid recording ID format. Expected: folder_name/filename:line_number"}
        
        folder_name, filename = file_part.split("/", 1)
        line_number = int(line_num_str)
        
        # Construct the file path
        if folder_name == "root":
            file_path = os.path.join(STORAGE_PATH, filename)
        else:
            file_path = os.path.join(STORAGE_PATH, folder_name, filename)
        
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        # Read the specific line
        with open(file_path) as f:
            for current_line_num, line in enumerate(f, 1):
                if current_line_num == line_number:
                    record = json.loads(line)
                    result = replay_request(record)
                    return build_summary([result])
        
        return {"error": f"Line {line_number} not found in file {file_path}"}
        
    except ValueError:
        return {"error": "Invalid line number in recording ID"}
    except Exception as e:
        logger.error(f"Error replaying recording {recording_id}: {e}")
        return {"error": f"Internal error: {str(e)}"}
