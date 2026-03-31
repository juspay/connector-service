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
            "resolution_summary": entry.get("resolution_summary", ""),
            "processed_at": entry.get("processed_at", ""),
            "status": entry.get("status", ""),
            "commit_sha": entry.get("commit_sha", ""),
            "error": entry.get("error", ""),
        }
        if entry.get("status") == "fixed":
            completed.append(item)
        elif entry.get("status") in ("failed", "build_blocked"):
            failed.append(item)

    # From recent events (live)
    steps_by_pr = {}  # {pr_number: {connector: [steps]}}
    queued = []
    seen_prs = set()
    active_pr = None  # Track which PR is currently being processed

    for event in bus.get_recent(500):
        t = event.type
        d = event.data

        if t == "comment_found":
            # Deduplicate by thread_id
            tid = d.get("thread_id", f"{d.get('pr')}_{d.get('path')}_{d.get('line')}")
            if not any(b.get("thread_id", f"{b.get('pr')}_{b.get('path')}_{b.get('line')}") == tid for b in backlog):
                backlog.append({**d, "thread_id": tid})
        elif t == "pr_start":
            active_pr = d.get("pr_number")
            if active_pr and active_pr not in seen_prs:
                in_progress.append(d)
                seen_prs.add(active_pr)
            steps_by_pr.setdefault(active_pr, {})
        elif t == "pr_queued":
            queued.append(d)
        elif t == "gate":
            pr = d.get("pr") or active_pr
            if pr:
                steps_by_pr.setdefault(pr, {}).setdefault("_pr", []).append({
                    "icon": "pass" if d.get("passed") else "fail",
                    "text": d.get("name", ""),
                    "detail": d.get("detail", ""),
                    "output": d.get("output", ""),
                })
        elif t.startswith("subtask_"):
            pr = d.get("pr") or active_pr
            connector = d.get("connector", "_pr")
            steps_by_pr.setdefault(pr, {}).setdefault(connector, [])

            if t == "subtask_start":
                steps_by_pr[pr][connector].append({"icon": "start", "text": f"Started ({d.get('comment_count', 0)} comments)", "detail": ""})
            elif t == "subtask_gate":
                steps_by_pr[pr][connector].append({
                    "icon": "pass" if d.get("passed") else "fail",
                    "text": d.get("gate", ""),
                    "detail": d.get("detail", ""),
                })
            elif t == "subtask_agent_tool":
                steps_by_pr[pr][connector].append({"icon": "tool", "text": d.get("tool", ""), "detail": d.get("input_summary", "")})
            elif t == "subtask_agent_text":
                steps_by_pr[pr][connector].append({"icon": "text", "text": d.get("text", "")[:100], "detail": ""})
            elif t == "subtask_committed":
                steps_by_pr[pr][connector].append({"icon": "pass", "text": f"Committed {d.get('sha', '')[:8]}", "detail": ""})
            elif t == "subtask_fixed":
                steps_by_pr[pr][connector].append({"icon": "pass", "text": "Fixed", "detail": ""})
            elif t == "subtask_failed":
                steps_by_pr[pr][connector].append({"icon": "fail", "text": "Failed", "detail": d.get("error", "")[:100]})

    # Sort completed by timestamp descending
    completed.sort(key=lambda x: x.get("processed_at", ""), reverse=True)
    failed.sort(key=lambda x: x.get("processed_at", ""), reverse=True)

    # Remove items from backlog that are in in_progress, completed, or failed
    done_tids = {e.get("thread_id") for e in completed + failed if e.get("thread_id")}
    done_prs = {e.get("pr_number") for e in completed + failed if e.get("pr_number")}
    active_prs = {p.get("pr_number") for p in in_progress}
    backlog = [b for b in backlog
               if b.get("thread_id") not in done_tids
               and b.get("pr") not in active_prs
               and b.get("pr") not in done_prs]
    # Remove in_progress PRs that are fully done
    in_progress = [p for p in in_progress if p.get("pr_number") not in done_prs]

    # Get pool status if available
    service = request.app.get("resolver_service")
    pool_status = service.pool.status if service else []

    return web.json_response({
        "backlog": backlog,
        "in_progress": in_progress,
        "completed": completed[:50],
        "failed": failed[:20],
        "queued": queued,
        "steps_by_pr": steps_by_pr,
        "pool": pool_status,
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


async def api_retry_handler(request: web.Request) -> web.Response:
    """Retry a specific failed thread — removes it from processed state."""
    thread_id = request.match_info["thread_id"]
    state_mgr: StateManager = request.app["state_manager"]
    state_mgr.load()
    ok = state_mgr.retry(thread_id)
    return web.json_response({"ok": ok, "thread_id": thread_id})


async def api_retry_all_handler(request: web.Request) -> web.Response:
    """Retry all failed threads — removes them from processed state."""
    state_mgr: StateManager = request.app["state_manager"]
    state_mgr.load()
    count = state_mgr.retry_all_failed()
    return web.json_response({"ok": True, "retried": count})


async def api_poll_now_handler(request: web.Request) -> web.Response:
    """Trigger an immediate poll cycle without waiting for the interval."""
    service = request.app.get("resolver_service")
    if not service:
        return web.json_response({"ok": False, "error": "Service not running"})
    asyncio.create_task(service.run_once())
    return web.json_response({"ok": True, "message": "Poll triggered"})


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
    app.router.add_post("/api/retry/{thread_id}", api_retry_handler)
    app.router.add_post("/api/retry-all-failed", api_retry_all_handler)
    app.router.add_post("/api/poll-now", api_poll_now_handler)

    # Background tasks
    app.on_startup.append(start_resolver_background)
    app.on_cleanup.append(stop_resolver_background)

    return app
