from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from bbai.filesystem import secure_private_directory

ExecutionStatus = Literal["dry_run", "denied", "failed", "succeeded"]


def append_tool_audit_event(
    log_path: Path,
    *,
    tool_name: str,
    status: ExecutionStatus,
    approved: bool,
    duration_ms: int,
) -> None:
    secure_private_directory(log_path.parent)
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": "tool_execution",
        "tool": tool_name,
        "status": status,
        "approved": approved,
        "duration_ms": duration_ms,
    }
    payload = (json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written == 0:
                raise OSError("audit log write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
