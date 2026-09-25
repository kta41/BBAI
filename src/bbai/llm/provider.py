from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx


class LLMProvider(Protocol):
    async def generate(
        self,
        prompt: str,
        *,
        model: str | None = None,
        system: str | None = None,
    ) -> str: ...


@dataclass(frozen=True)
class ToolCall:
    identifier: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ToolTurn:
    text: str
    tool_calls: list[ToolCall]
    message: dict[str, Any]


class OllamaProvider:
    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434",
        default_model: str = "llama3.1",
        timeout_seconds: int = 60,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.timeout_seconds = timeout_seconds

    async def generate(
        self,
        prompt: str,
        *,
        model: str | None = None,
        system: str | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(f"{self.base_url}/api/generate", json=payload)
            response.raise_for_status()
            data: Mapping[str, Any] = response.json()

        return str(data.get("response", ""))

    async def chat_with_tools(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Sequence[dict[str, Any]],
        model: str | None = None,
        system: str | None = None,
    ) -> ToolTurn:
        request_messages = list(messages)
        if system:
            request_messages.insert(0, {"role": "system", "content": system})
        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "messages": request_messages,
            "tools": list(tools),
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            data: Mapping[str, Any] = response.json()
        message = data.get("message", {})
        if not isinstance(message, dict):
            raise TypeError("Ollama returned an invalid chat message")
        raw_calls = message.get("tool_calls", [])
        calls: list[ToolCall] = []
        if isinstance(raw_calls, list):
            for index, raw_call in enumerate(raw_calls):
                if not isinstance(raw_call, dict):
                    continue
                function = raw_call.get("function", {})
                if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                    continue
                arguments = function.get("arguments", {})
                calls.append(
                    ToolCall(
                        identifier=str(raw_call.get("id", f"call-{index}")),
                        name=function["name"],
                        arguments=arguments if isinstance(arguments, dict) else {},
                    )
                )
        return ToolTurn(text=str(message.get("content", "")), tool_calls=calls, message=message)
