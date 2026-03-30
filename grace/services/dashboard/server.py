"""aiohttp web server — serves dashboard + SSE stream + API."""

import asyncio
import json
from pathlib import Path

from aiohttp import web

from .event_bus import EventBus, get_event_bus
from ..pr_resolver.config import PRResolverConfig
from ..pr_resolver.service import PRResolverService
from ..pr_resolver.state import StateManager

STATIC_DIR = Path(__file__).parent / "static"


async def index_handler(request: web.Request) -> web.Response:
    """Serve the dashboard HTML."""
    html_path = STATIC_DIR / "index.html"
    return web.FileResponse(html_path)


async def api_state_handler(request: web.Request) -> web.Response:
    """Return current state: backlog, in-progress, completed, failed."""
    bus: EventBus = request.app["event_bus"]
    state_mgr: StateManager = request.app["state_manager"]

    # Build state from recent events + state.json
    backlog = []
    in_progress = []
    completed = []
    failed = []

    # From state.json (history)
    state_mgr.load()  # Refresh
    for tid, entry in state_mgr._state.get("processed_threads", {}).items():
        item = {
            "thread_id": tid,
            "pr_number": entry.get("pr_number"),
            "path": entry.get("path", ""),
            "instruction": entry.get("instruction_preview", ""),
            "processed_at": entry.get("processed_at", ""),
            "status": entry.get("status", ""),
            "commit_sha": entry.get("commit_sha", ""),
            "error": entry.get("error", ""),
        }
        if entry.get("status") == "fixed":
            completed.append(item)
        elif entry.get("status") == "failed":
            failed.append(item)

    # From recent events (live) — build backlog, in_progress, AND steps
    steps_by_pr = {}
    active_pr = None
    seen_prs = set()
    for event in bus.get_recent(200):
        if event.type == "comment_found":
            backlog.append(event.data)
        elif event.type == "pr_start":
            active_pr = event.data.get("pr_number")
            if active_pr and active_pr not in seen_prs:
                in_progress.append(event.data)
                seen_prs.add(active_pr)
            steps_by_pr[active_pr] = []
        elif event.type == "gate" and active_pr:
            icon = "pass" if event.data.get("passed") else "fail"
            steps_by_pr.setdefault(active_pr, []).append({
                "icon": icon, "text": event.data.get("name", ""), "detail": event.data.get("detail", "")
            })
        elif event.type == "agent_tool" and active_pr:
            steps_by_pr.setdefault(active_pr, []).append({
                "icon": "tool", "text": event.data.get("tool", ""), "detail": event.data.get("input_summary", "")
            })
        elif event.type == "agent_text" and active_pr:
            steps_by_pr.setdefault(active_pr, []).append({
                "icon": "text", "text": event.data.get("text", "")[:100], "detail": ""
            })

    # Sort completed by timestamp descending
    completed.sort(key=lambda x: x.get("processed_at", ""), reverse=True)
    failed.sort(key=lambda x: x.get("processed_at", ""), reverse=True)

    return web.json_response({
        "backlog": backlog,
        "in_progress": in_progress,
        "completed": completed[:50],
        "failed": failed[:20],
        "steps_by_pr": steps_by_pr,
        "last_poll": state_mgr._state.get("last_poll"),
        "subscribers": bus.subscriber_count,
    })


async def api_history_handler(request: web.Request) -> web.Response:
    """Return recent processing history from state.json."""
    state_mgr: StateManager = request.app["state_manager"]
    state_mgr.load()
    return web.json_response(state_mgr._state)


async def sse_handler(request: web.Request) -> web.StreamResponse:
    """Server-Sent Events endpoint for real-time updates."""
    response = web.StreamResponse(
        status=200,
        reason="OK",
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        },
    )
    await response.prepare(request)

    bus: EventBus = request.app["event_bus"]
    queue = bus.subscribe()

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
                await response.write(event.to_sse().encode("utf-8"))
            except asyncio.TimeoutError:
                # Send keepalive comment
                await response.write(b": keepalive\n\n")
            except ConnectionResetError:
                break
    finally:
        bus.unsubscribe(queue)

    return response


async def start_resolver_background(app: web.Application) -> None:
    """Start the PR resolver service as a background task."""
    config: PRResolverConfig = app["resolver_config"]
    bus: EventBus = app["event_bus"]

    service = PRResolverService(config, event_callback=bus.emit)
    app["resolver_service"] = service
    app["resolver_task"] = asyncio.create_task(service.run_forever())


async def stop_resolver_background(app: web.Application) -> None:
    """Stop the background resolver."""
    task = app.get("resolver_task")
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


def create_app(config: PRResolverConfig) -> web.Application:
    """Create the aiohttp web application."""
    app = web.Application()

    # Store shared state
    app["resolver_config"] = config
    app["event_bus"] = get_event_bus()
    app["state_manager"] = StateManager(config.state_file)

    # Routes
    app.router.add_get("/", index_handler)
    app.router.add_get("/api/state", api_state_handler)
    app.router.add_get("/api/history", api_history_handler)
    app.router.add_get("/api/events", sse_handler)

    # Background tasks
    app.on_startup.append(start_resolver_background)
    app.on_cleanup.append(stop_resolver_background)

    return app
