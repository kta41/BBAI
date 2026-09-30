from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScopePolicy:
    allowed_tools: frozenset[str]
    approval_required: bool = True
    tool_approval_required: Mapping[str, bool] = field(default_factory=dict)

    def validate_tool(self, tool_name: str) -> None:
        if tool_name not in self.allowed_tools:
            raise ValueError(f"Tool '{tool_name}' is not allowed by the active policy")

    def requires_approval(self, tool_name: str) -> bool:
        self.validate_tool(tool_name)
        return self.approval_required or self.tool_approval_required.get(tool_name, True)
