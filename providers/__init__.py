"""OpenAI-compatible multi-provider client layer.

API surface mirrors ``llm_tester.providers`` / ``llm_tester.config`` in
https://github.com/Ihor-Khomenko/LLM-tester-tool (branch cursor/llm-tester-package-ee1e)
so the two repos can later share this package.
"""

from providers.config import (
    PROVIDERS,
    PROVIDER_ALIASES,
    RunParams,
    RateLimitParams,
    is_openai_compatible,
    load_rate_limit_params,
    normalize_provider_name,
    resolve_provider_config,
)
from providers.openai_compat import ChatResult, LLMProvider, MaxRequestsExceeded
from providers.rate_limit import RateLimitedSession

__all__ = [
    "PROVIDERS",
    "PROVIDER_ALIASES",
    "RunParams",
    "RateLimitParams",
    "ChatResult",
    "LLMProvider",
    "MaxRequestsExceeded",
    "RateLimitedSession",
    "is_openai_compatible",
    "load_rate_limit_params",
    "normalize_provider_name",
    "resolve_provider_config",
]
