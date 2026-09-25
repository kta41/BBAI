from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScopePolicy:
    allowed_tools: frozenset[str]
    approval_required: bool = True

    def validate_tool(self, tool_name: str) -> None:
        if tool_name not in self.allowed_tools:
            raise ValueError(f"Tool '{tool_name}' is not allowed by the active policy")

    def requires_approval(self, tool_name: str) -> bool:
        self.validate_tool(tool_name)
        return self.approval_required
