"""xwa-sdk ``Event`` streaming envelope for Yari WebSocket analyses.

When ``xwa-sdk`` is installed (see ``docs/development.md`` and ``yari.sh``) the
canonical dataclasses are used; otherwise an identical local fallback keeps the
backend fully operational. Both paths serialize to the same JSON envelope::

    {"seq": 1, "type": "analysis_started", "tool": "yari",
     "analysis_id": "12", "ts": "2026-09-12T00:00:00.000Z", "payload": {...}}

Event types follow the canonical contract:
``analysis_started`` → ``analysis_progress`` → ``item_found``* →
``analysis_completed`` | ``analysis_error``.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from typing import Any

TOOL = "yari"

try:  # pragma: no cover - depends on install mode
    from xwa_sdk import Event as Event  # type: ignore[assignment]
    from xwa_sdk import to_dict as _to_dict

    XWA_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - local fallback, same contract
    XWA_SDK_AVAILABLE = False

    @dataclass
    class Event:  # type: ignore[no-redef]
        seq: int
        type: str
        tool: str
        analysis_id: str
        ts: str
        payload: Any = None

    def _to_dict(obj: Any) -> dict:
        data = asdict(obj) if is_dataclass(obj) else dict(obj)
        return {k: v for k, v in data.items() if v is not None}


def utc_now_iso() -> str:
    """UTC timestamp in the RFC 3339 form used by xwa-sdk schemas."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class EventStream:
    """Monotonic ``Event`` emitter scoped to a single analysis / WebSocket."""

    def __init__(self, websocket: Any, analysis_id: str, tool: str = TOOL) -> None:
        self._websocket = websocket
        self._analysis_id = str(analysis_id)
        self._tool = tool
        self._seq = 0

    @property
    def analysis_id(self) -> str:
        return self._analysis_id

    @property
    def seq(self) -> int:
        return self._seq

    async def emit(self, event_type: str, payload: Any = None) -> dict:
        """Send one event envelope and return the serialized dict."""
        self._seq += 1
        event = Event(
            seq=self._seq,
            type=event_type,
            tool=self._tool,
            analysis_id=self._analysis_id,
            ts=utc_now_iso(),
            payload=payload,
        )
        data = _to_dict(event)
        await self._websocket.send_text(json.dumps(data, ensure_ascii=False))
        return data

    async def log(self, message: str) -> dict:
        """Convenience wrapper for human-readable pipeline messages."""
        return await self.emit("log", {"message": message})
