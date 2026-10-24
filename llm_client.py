"""Unified LLM client for MCP attack/defense simulations.

OpenAI-compatible providers (ollama, openai, openrouter, xai, groq) go through
``providers.LLMProvider`` — the same shape as LLM-tester-tool's provider layer.
Claude API and CLI agents remain as thin adapters for the research UI.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from typing import Any, Dict, List, Optional

import requests

from providers import (
    LLMProvider,
    MaxRequestsExceeded,
    RateLimitedSession,
    RunParams,
    load_rate_limit_params,
    normalize_provider_name,
)
from providers.config import api_key_env_for, is_openai_compatible


class UnifiedLLMClient:
    def __init__(
        self,
        provider,
        model_or_cmd,
        api_key=None,
        base_url=None,
        *,
        rate_limits=None,
        session=None,
        params=None,
    ):
        self.provider = provider
        self.model_or_cmd = model_or_cmd
        self.api_key = api_key
        self.base_url = base_url
        self.params = params or RunParams(temperature=0.0, seed=None)
        self.rate_limits = rate_limits or load_rate_limit_params()
        self.session = session or RateLimitedSession(self.rate_limits)
        self._openai_provider: Optional[LLMProvider] = None

    def is_cli(self):
        return self.provider in ["Claude Code CLI", "Copilot CLI", "Agy CLI", "Codex CLI"]

    def _ensure_openai_provider(self) -> LLMProvider:
        if self._openai_provider is not None:
            return self._openai_provider
        name = normalize_provider_name(self.provider)
        # Unsloth / custom OpenAI-compatible endpoints still resolve as "openai"
        # but honour an explicit base_url from the UI.
        self._openai_provider = LLMProvider(
            name,
            self.model_or_cmd,
            base_url=self.base_url or None,
            api_key=self.api_key or None,
            params=self.params,
            rate_limits=self.rate_limits,
            session=self.session,
        )
        return self._openai_provider

    def chat_completion(self, messages, tools=None):
        """
        For API-based models, performs a (optionally tool-enabled) chat completion.
        Returns an Ollama-compatible dict: ``{"message": {...}}``.
        """
        if self.is_cli():
            raise ValueError("CLI providers do not support chat_completion; use run_cli_agent.")

        if is_openai_compatible(self.provider) or self.provider in (
            "Unsloth Studio",
            "ChatGPT",
            "Codex API",
            "Ollama",
        ):
            return self._chat_openai_compatible(messages, tools=tools)

        if self.provider == "Claude API":
            return self._chat_claude(messages, tools=tools)

        # Legacy: raw Ollama SDK path if somehow labelled differently
        if self.provider == "Ollama":
            return self._chat_openai_compatible(messages, tools=tools)

        raise ValueError(f"Unknown API provider: {self.provider}")

    def _chat_openai_compatible(self, messages, tools=None):
        # Prefer shared OpenAI-compatible layer; fall back to legacy Ollama SDK
        # only when the openai package path fails for local tool calling quirks.
        try:
            provider = self._ensure_openai_provider()
            # Normalize tool_call arguments for round-trip: keep strings as returned.
            normalized = []
            for msg in messages:
                m = dict(msg)
                if m.get("tool_calls"):
                    tcs = []
                    for tc in m["tool_calls"]:
                        fn = dict(tc.get("function") or {})
                        args = fn.get("arguments")
                        if isinstance(args, dict):
                            fn["arguments"] = json.dumps(args)
                        tcs.append({**tc, "function": fn})
                    m["tool_calls"] = tcs
                normalized.append(m)
            result = provider.complete(normalized, tools=tools)
            message = result.message or {
                "role": "assistant",
                "content": result.content or "",
            }
            # Parse arguments to dict for simulation code that uses .get()
            if message.get("tool_calls"):
                parsed_calls = []
                for tc in message["tool_calls"]:
                    fn = dict(tc.get("function") or {})
                    args = fn.get("arguments")
                    if isinstance(args, str):
                        try:
                            fn["arguments"] = json.loads(args)
                        except json.JSONDecodeError:
                            pass
                    parsed_calls.append({**tc, "function": fn})
                message = {**message, "tool_calls": parsed_calls}
            return {"message": message}
        except MaxRequestsExceeded:
            raise
        except Exception:
            if normalize_provider_name(self.provider) == "ollama" and not self.base_url:
                return self._chat_ollama_sdk(messages, tools=tools)
            raise

    def _chat_ollama_sdk(self, messages, tools=None):
        import ollama

        return ollama.chat(model=self.model_or_cmd, messages=messages, tools=tools)

    def _chat_claude(self, messages, tools=None):
        url = self.base_url or "https://api.anthropic.com/v1"
        headers = {
            "x-api-key": self.api_key or os.environ.get("ANTHROPIC_API_KEY") or "",
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        system_prompt = ""
        anthropic_messages = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")
            if role == "system":
                system_prompt = content
            elif role == "tool":
                tool_use_id = msg.get("tool_call_id") or "tool_id"
                anthropic_messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_use_id,
                                "content": content,
                            }
                        ],
                    }
                )
            elif role == "assistant" and msg.get("tool_calls"):
                content_blocks = []
                if content:
                    content_blocks.append({"type": "text", "text": content})
                for tc in msg["tool_calls"]:
                    args = tc["function"]["arguments"]
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {"_raw": args}
                    content_blocks.append(
                        {
                            "type": "tool_use",
                            "id": tc.get("id") or "tool_id",
                            "name": tc["function"]["name"],
                            "input": args,
                        }
                    )
                anthropic_messages.append({"role": "assistant", "content": content_blocks})
            else:
                anthropic_messages.append({"role": role, "content": content})

        payload = {
            "model": self.model_or_cmd,
            "messages": anthropic_messages,
            "max_tokens": 4096,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            anth_tools = []
            for t in tools:
                anth_tools.append(
                    {
                        "name": t["function"]["name"],
                        "description": t["function"]["description"],
                        "input_schema": t["function"]["parameters"],
                    }
                )
            payload["tools"] = anth_tools

        self.session.before_request()
        resp = requests.post(f"{url}/messages", json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        self.session.after_request()
        res = resp.json()

        content_text = ""
        tool_calls = []
        for block in res.get("content", []):
            if block["type"] == "text":
                content_text += block["text"]
            elif block["type"] == "tool_use":
                tool_calls.append(
                    {
                        "id": block["id"],
                        "type": "function",
                        "function": {
                            "name": block["name"],
                            "arguments": block["input"],
                        },
                    }
                )

        return {
            "message": {
                "role": "assistant",
                "content": content_text,
                "tool_calls": tool_calls if tool_calls else None,
            }
        }

    def run_cli_agent(self, workspace_dir, prompt):
        """
        Executes a CLI agent (like Claude Code, Copilot, Agy, Codex) in a subprocess.
        """
        print(f"🎬 [CLI AGENT]: Spawning '{self.provider}' ({self.model_or_cmd}) in {workspace_dir}...")

        cmd_args = shlex.split(self.model_or_cmd)

        try:
            process = subprocess.Popen(
                cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=workspace_dir,
                text=True,
            )

            stdout, _ = process.communicate(input=prompt + "\nexit\n", timeout=120)
            return stdout
        except Exception as e:
            return f"Error executing CLI agent: {e}"

    def info(self) -> Dict[str, Any]:
        if is_openai_compatible(self.provider) or self.provider in (
            "Unsloth Studio",
            "ChatGPT",
            "Codex API",
            "Ollama",
        ):
            try:
                return self._ensure_openai_provider().info()
            except Exception as exc:
                return {"provider": self.provider, "model": self.model_or_cmd, "error": str(exc)}
        return {
            "provider": self.provider,
            "model": self.model_or_cmd,
            "base_url": self.base_url,
        }


def resolve_api_key_for_ui(provider: str, keys: Dict[str, str]) -> str:
    """Map vault/UI key fields onto the selected provider."""
    name = normalize_provider_name(provider)
    if provider == "Claude API":
        return keys.get("anthropic") or keys.get("Claude API") or os.environ.get("ANTHROPIC_API_KEY") or ""
    if name == "openai" or provider in ("ChatGPT", "Codex API", "Unsloth Studio"):
        if provider == "Unsloth Studio":
            return keys.get("unsloth") or keys.get("Unsloth Studio") or keys.get("openai") or ""
        return keys.get("openai") or keys.get("ChatGPT") or os.environ.get("OPENAI_API_KEY") or ""
    env_name = api_key_env_for(provider)
    if env_name:
        return keys.get(name) or keys.get(provider) or os.environ.get(env_name) or ""
    return keys.get(provider) or ""
