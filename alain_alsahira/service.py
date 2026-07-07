"""Alain Alsahira runtime-guard as a local HTTP service.

``POST /api/scan`` accepts ``{"events": [...]}`` (RuntimeEvent dicts) and
returns the Arabic assessment: detections, risk score and OK/INVESTIGATE/ISOLATE.
Sensors keep running locally; this endpoint lets agents and collectors on the
machine submit events without shelling out to the CLI.
"""

from __future__ import annotations

from http.server import ThreadingHTTPServer
from typing import Any

from .engine import analyze_events
from .http_base import BaseServiceHandler, build_server
from .models import RuntimeEvent


def _scan_route(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    events = data.get("events")
    if not isinstance(events, list) or not events:
        return 400, {"ok": False, "error": "missing non-empty 'events' list"}
    if len(events) > 10_000:
        return 400, {"ok": False, "error": "too many events in one request (max 10000)"}
    assessment = analyze_events([RuntimeEvent.from_dict(item) for item in events])
    return 200, {"ok": True, **assessment.to_dict()}


class Handler(BaseServiceHandler):
    post_routes = {"/api/scan": staticmethod(_scan_route)}


def create_server(host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    return build_server(Handler, host=host, port=port)


def run_server(host: str | None = None, port: int | None = None) -> None:
    from .version import __version__

    server = create_server(host=host, port=port)
    print(f"alain service v{__version__}: http://{server.server_address[0]}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
