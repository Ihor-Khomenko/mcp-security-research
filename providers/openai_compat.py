"""OpenAI-compatible multi-provider client layer.

Mirrors ``llm_tester.providers.LLMProvider`` for later code sharing.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from openai import APIStatusError, OpenAI, RateLimitError

from providers.config import RateLimitParams, RunParams, load_rate_limit_params, resolve_provider_config


class MaxRequestsExceeded(RuntimeError):
    """Raised when ``RateLimitParams.max_requests`` is exhausted."""


@dataclass
class ChatResult:
    content: str
    latency_s: float
    raw: Optional[Dict[str, Any]] = None
    attempts: int = 1
    tool_calls: Optional[List[Dict[str, Any]]] = None
    message: Optional[Dict[str, Any]] = None


class LLMProvider:
    """Thin wrapper around the OpenAI SDK pointed at a configurable base_url."""

    def __init__(
        self,
        provider: str,
        model: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        params: Optional[RunParams] = None,
        max_retries: int = 5,
        backoff_base: float = 1.0,
        backoff_max: float = 60.0,
        rate_limits: Optional[RateLimitParams] = None,
        session: Optional[Any] = None,
    ) -> None:
        cfg = resolve_provider_config(provider, base_url=base_url, api_key=api_key)
        self.provider = cfg["name"]
        self.base_url = cfg["base_url"]
        self.model = model or cfg["default_model"]
        if not self.model:
            raise ValueError(f"Model is required for provider '{self.provider}'.")
        self.params = params or RunParams()
        rl = rate_limits or load_rate_limit_params(max_retries=max_retries)
        self.max_retries = rl.max_retries if rate_limits is not None else max_retries
        self.backoff_base = rl.backoff_base if rate_limits is not None else backoff_base
        self.backoff_max = rl.backoff_max if rate_limits is not None else backoff_max
        self.rate_limits = rl
        self._session = session  # optional RateLimitedSession
        # Disable the SDK's own retries so we control 429 backoff centrally.
        self._client = OpenAI(
            api_key=cfg["api_key"],
            base_url=self.base_url,
            max_retries=0,
        )

    def chat(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        messages: Optional[List[Dict[str, str]]] = None,
    ) -> ChatResult:
        """Simple chat completion (llm_tester-compatible signature)."""
        built: List[Dict[str, Any]] = []
        if messages is None:
            if system:
                built.append({"role": "system", "content": system})
            built.append({"role": "user", "content": prompt})
        else:
            built = list(messages)
            if system:
                built.insert(0, {"role": "system", "content": system})
            if prompt:
                built.append({"role": "user", "content": prompt})
        return self.complete(built)

    def complete(
        self,
        messages: List[Dict[str, Any]],
        *,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ChatResult:
        """Chat completion with optional OpenAI-style tools (MCP agent loops)."""
        self._before_request()

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.params.temperature,
        }
        if self.params.seed is not None:
            kwargs["seed"] = self.params.seed
        if self.params.max_tokens is not None:
            kwargs["max_tokens"] = self.params.max_tokens
        if tools:
            kwargs["tools"] = tools

        attempt = 0
        start = time.perf_counter()
        while True:
            attempt += 1
            try:
                response = self._client.chat.completions.create(**kwargs)
                latency = time.perf_counter() - start
                content = ""
                tool_calls = None
                message_dict: Dict[str, Any] = {"role": "assistant", "content": ""}
                if response.choices:
                    msg = response.choices[0].message
                    content = msg.content or ""
                    message_dict["content"] = content
                    if getattr(msg, "tool_calls", None):
                        tool_calls = []
                        for tc in msg.tool_calls:
                            args = tc.function.arguments
                            # Keep string args for OpenAI round-trip; parsers may JSON-decode.
                            tool_calls.append(
                                {
                                    "id": tc.id,
                                    "type": "function",
                                    "function": {
                                        "name": tc.function.name,
                                        "arguments": args,
                                    },
                                }
                            )
                        message_dict["tool_calls"] = tool_calls
                result = ChatResult(
                    content=content,
                    latency_s=latency,
                    raw=response.model_dump(),
                    attempts=attempt,
                    tool_calls=tool_calls,
                    message=message_dict,
                )
                self._after_request()
                return result
            except (RateLimitError, APIStatusError) as exc:
                status = getattr(exc, "status_code", None)
                if status is None and hasattr(exc, "response"):
                    status = getattr(exc.response, "status_code", None)
                is_rate_limited = isinstance(exc, RateLimitError) or status == 429
                if not is_rate_limited or attempt > self.max_retries:
                    raise
                delay = self._backoff_seconds(attempt, exc)
                time.sleep(delay)

    def _before_request(self) -> None:
        if self._session is not None:
            self._session.before_request()
            return
        # Inline budget when no shared session is attached.
        if self.rate_limits.max_requests is not None:
            used = getattr(self, "_requests_made", 0)
            if used >= self.rate_limits.max_requests:
                raise MaxRequestsExceeded(
                    f"Reached max_requests={self.rate_limits.max_requests}. "
                    "Raise LLM_MAX_REQUESTS or wait for the next quota window."
                )
        delay = self.rate_limits.delay
        if delay > 0 and getattr(self, "_requests_made", 0) > 0:
            time.sleep(delay)

    def _after_request(self) -> None:
        if self._session is not None:
            self._session.after_request()
            return
        self._requests_made = getattr(self, "_requests_made", 0) + 1

    def _backoff_seconds(self, attempt: int, exc: BaseException) -> float:
        """Exponential backoff with jitter; honour Retry-After when present."""
        retry_after = None
        response = getattr(exc, "response", None)
        if response is not None:
            headers = getattr(response, "headers", None) or {}
            raw = headers.get("retry-after") or headers.get("Retry-After")
            if raw is not None:
                try:
                    retry_after = float(raw)
                except (TypeError, ValueError):
                    retry_after = None
        if retry_after is not None:
            return min(self.backoff_max, max(0.0, retry_after))
        expo = self.backoff_base * (2 ** (attempt - 1))
        jitter = random.uniform(0, self.backoff_base)
        return min(self.backoff_max, expo + jitter)

    def info(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "params": self.params.as_dict(),
            "rate_limits": {
                "max_requests": self.rate_limits.max_requests,
                "delay": self.rate_limits.delay,
                "max_retries": self.max_retries,
            },
        }


def parse_tool_arguments(args: Union[str, Dict[str, Any], None]) -> Dict[str, Any]:
    """Normalize tool-call arguments to a dict."""
    if args is None:
        return {}
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        try:
            parsed = json.loads(args)
            return parsed if isinstance(parsed, dict) else {"_raw": args}
        except json.JSONDecodeError:
            return {"_raw": args}
    return {"_raw": str(args)}
