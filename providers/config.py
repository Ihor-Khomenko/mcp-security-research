"""Provider defaults and environment loading.

Compatible with ``llm_tester.config`` (LLM-tester-tool) so both projects can
share provider resolution later.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from dotenv import load_dotenv

    # Load .env from CWD (and parents) if present; never override existing env.
    load_dotenv(override=False)
except ImportError:  # pragma: no cover - optional at import time
    pass

PROVIDERS: Dict[str, Dict[str, Any]] = {
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "api_key_env": "OLLAMA_API_KEY",
        "base_url_env": "OLLAMA_BASE_URL",
        "default_api_key": "ollama",
        "default_model": "llama3",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "base_url_env": "OPENAI_BASE_URL",
        "default_model": "gpt-4o-mini",
    },
    "xai": {
        "base_url": "https://api.x.ai/v1",
        "api_key_env": "XAI_API_KEY",
        "base_url_env": "XAI_BASE_URL",
        "default_model": "grok-2-latest",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "base_url_env": "OPENROUTER_BASE_URL",
        # Prefer a free-tier model id; override with --model as needed.
        "default_model": "meta-llama/llama-3.2-3b-instruct:free",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "base_url_env": "GROQ_BASE_URL",
        "default_model": "llama-3.1-8b-instant",
    },
}

# UI / legacy labels → canonical provider ids (OpenAI-compatible only).
PROVIDER_ALIASES: Dict[str, str] = {
    "ollama": "ollama",
    "Ollama": "ollama",
    "openai": "openai",
    "OpenAI": "openai",
    "ChatGPT": "openai",
    "Codex API": "openai",
    "Unsloth Studio": "openai",
    "xai": "xai",
    "xAI": "xai",
    "XAI": "xai",
    "openrouter": "openrouter",
    "OpenRouter": "openrouter",
    "groq": "groq",
    "Groq": "groq",
}

DEFAULT_TEMPERATURE = 0.0
DEFAULT_SEED = 42

# Canonical OpenAI-compatible choices for Gradio / CLI dropdowns.
UI_PROVIDER_CHOICES = [
    "ollama",
    "openai",
    "openrouter",
    "xai",
    "groq",
    "Unsloth Studio",
    "Claude API",
    "Claude Code CLI",
    "Copilot CLI",
    "Agy CLI",
    "Codex CLI",
]


@dataclass(frozen=True)
class RunParams:
    """Deterministic generation settings logged with every response."""

    temperature: float = DEFAULT_TEMPERATURE
    seed: Optional[int] = DEFAULT_SEED
    max_tokens: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"temperature": self.temperature}
        if self.seed is not None:
            d["seed"] = self.seed
        if self.max_tokens is not None:
            d["max_tokens"] = self.max_tokens
        return d


@dataclass(frozen=True)
class RateLimitParams:
    """Quota-friendly request pacing (OpenRouter free tier ~50 req/day)."""

    max_requests: Optional[int] = None
    delay: float = 0.0
    max_retries: int = 5
    backoff_base: float = 1.0
    backoff_max: float = 60.0


def load_rate_limit_params(
    *,
    max_requests: Optional[int] = None,
    delay: Optional[float] = None,
    max_retries: Optional[int] = None,
) -> RateLimitParams:
    """Resolve rate-limit settings from args or environment."""
    env_max = os.environ.get("LLM_MAX_REQUESTS") or os.environ.get("MCP_LLM_MAX_REQUESTS")
    env_delay = os.environ.get("LLM_REQUEST_DELAY") or os.environ.get("MCP_LLM_REQUEST_DELAY")
    env_retries = os.environ.get("LLM_MAX_RETRIES") or os.environ.get("MCP_LLM_MAX_RETRIES")

    resolved_max = max_requests
    if resolved_max is None and env_max not in (None, ""):
        resolved_max = int(env_max)
    # Treat 0 / negative as "unlimited" so CI can set LLM_MAX_REQUESTS=0
    # without blocking mocked unit tests that still exercise the client path.
    if resolved_max is not None and resolved_max <= 0:
        resolved_max = None

    resolved_delay = delay
    if resolved_delay is None:
        resolved_delay = float(env_delay) if env_delay not in (None, "") else 0.0

    resolved_retries = max_retries
    if resolved_retries is None:
        resolved_retries = int(env_retries) if env_retries not in (None, "") else 5

    return RateLimitParams(
        max_requests=resolved_max,
        delay=float(resolved_delay or 0.0),
        max_retries=int(resolved_retries),
    )


def normalize_provider_name(provider: str) -> str:
    """Map UI / alias labels to a canonical PROVIDERS key when possible."""
    raw = (provider or "").strip()
    if raw in PROVIDER_ALIASES:
        return PROVIDER_ALIASES[raw]
    lower = raw.lower()
    if lower in PROVIDERS:
        return lower
    return raw


def is_openai_compatible(provider: str) -> bool:
    """Return True when the provider can use the shared OpenAI-compatible client."""
    name = normalize_provider_name(provider)
    return name in PROVIDERS


def resolve_provider_config(
    provider: str,
    *,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve base_url and api_key for a named provider."""
    name = normalize_provider_name(provider)
    if name not in PROVIDERS:
        raise ValueError(
            f"Unknown provider '{provider}'. Choose from: {', '.join(sorted(PROVIDERS))}"
        )
    meta = PROVIDERS[name]
    resolved_base = (
        base_url
        or os.environ.get(meta["base_url_env"])
        or meta["base_url"]
    )
    resolved_key = (
        api_key
        or os.environ.get(meta["api_key_env"])
        or meta.get("default_api_key")
    )
    if not resolved_key:
        raise ValueError(
            f"Missing API key for provider '{name}'. "
            f"Set {meta['api_key_env']} in the environment or .env "
            f"(see .env.example)."
        )
    return {
        "name": name,
        "base_url": resolved_base.rstrip("/"),
        "api_key": resolved_key,
        "default_model": meta.get("default_model"),
    }


def api_key_env_for(provider: str) -> Optional[str]:
    """Return the env var name that holds the API key for a provider."""
    name = normalize_provider_name(provider)
    meta = PROVIDERS.get(name)
    return meta["api_key_env"] if meta else None
