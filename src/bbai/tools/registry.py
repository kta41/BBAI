from __future__ import annotations

import shutil
from collections.abc import Mapping
from typing import Any

from bbai.auth.models import AuthContext
from bbai.tools.base import (
    FfufTool,
    GauTool,
    HttpHeadersTool,
    HttpInspectTool,
    KatanaTool,
    NucleiTool,
    SubfinderTool,
    Tool,
)

TOOL_NAMES = (
    "http_inspect",
    "http_headers",
    "subfinder",
    "ffuf",
    "gau",
    "katana",
    "nuclei",
)


def build_tools(
    *, scope: str, timeout_seconds: int, auth: AuthContext | None = None
) -> dict[str, Tool]:
    return {
        "http_inspect": HttpInspectTool(
            scope=scope, timeout_seconds=min(timeout_seconds, 15), auth=auth
        ),
        "http_headers": HttpHeadersTool(
            scope=scope, timeout_seconds=min(timeout_seconds, 15), auth=auth
        ),
        "subfinder": SubfinderTool(scope=scope, timeout_seconds=timeout_seconds),
        "ffuf": FfufTool(scope=scope, timeout_seconds=timeout_seconds, auth=auth),
        "gau": GauTool(scope=scope, timeout_seconds=timeout_seconds, auth=auth),
        "katana": KatanaTool(scope=scope, timeout_seconds=timeout_seconds, auth=auth),
        "nuclei": NucleiTool(scope=scope, timeout_seconds=timeout_seconds, auth=auth),
    }


def tool_definitions(tools: Mapping[str, Tool]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
            },
        }
        for tool in tools.values()
    ]


def tool_availability() -> dict[str, str]:
    return {
        "http_inspect": "built-in",
        "http_headers": "built-in",
        "subfinder": "available" if shutil.which("subfinder") else "missing",
        "ffuf": "available" if shutil.which("ffuf") else "missing",
        "gau": "available" if shutil.which("gau") else "missing",
        "katana": "available" if shutil.which("katana") else "missing",
        "nuclei": "available" if shutil.which("nuclei") else "missing",
    }
